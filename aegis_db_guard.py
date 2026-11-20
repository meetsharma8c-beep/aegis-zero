#!/usr/bin/env python3
"""AEGIS-ZERO transactional SQLite guard: per-statement savepoints, blast-radius cap, honey rows.

Every agent SQL statement is evaluated by the AegisController. Writes run inside
`SAVEPOINT aegis_sp_<n>`; if the cumulative modified-row count exceeds `max_rows`
(or the controller does not ALLOW) the savepoint is rolled back and the agent
process tree is frozen. Any statement or result set touching `_aegis_canary_row`
is a CANARY_TRIP: full rollback + freeze, never approvable.

  python3 -B aegis_db_guard.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, re, sqlite3, tempfile
from pathlib import Path

import aegis_controller as ac
from aegis_controller import (Action, AegisController, Decision, Priv, ProcessTreeFreezer, Verdict,
                              default_canary_dir, ensure_operator_keypair, load_operator_pubkey,
                              process_state, reap, register_cleanup, spawn_agent)

CANARY = "_aegis_canary_row"
READ_KW = {"SELECT", "WITH", "PRAGMA", "EXPLAIN"}
WRITE_KW = {"INSERT", "UPDATE", "REPLACE", "CREATE"}
DELETE_KW = {"DELETE", "DROP", "ALTER", "TRUNCATE"}
TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+[\"`\[]?(\w+)", re.I)
IDENT_RE = re.compile(r"^\w+$")


class AegisDBGuard:
    def __init__(self, conn: sqlite3.Connection, controller: AegisController, max_rows: int = 5):
        self.conn, self.ctl, self.max_rows = conn, controller, max_rows
        self.conn.isolation_level = None  # we own transaction boundaries explicitly
        self.rows_modified = 0
        self.sp_counter = 0
        self.last_rows: list[tuple] = []

    # ---- setup
    def install_canary(self, table: str, col: str = "id") -> None:
        if not (IDENT_RE.match(table) and IDENT_RE.match(col)):
            raise ValueError("table/column must be plain identifiers")
        self.conn.execute(f"INSERT INTO {table} ({col}) VALUES (?)", (CANARY,))

    # ---- helpers
    @staticmethod
    def classify(sql: str) -> tuple[str, Priv]:
        kw = (sql.strip().split(None, 1) or [""])[0].upper()
        if kw in READ_KW:
            return "sql_query", Priv.READ
        if kw in DELETE_KW:
            return "sql_exec", Priv.DELETE
        if kw in WRITE_KW:
            return "sql_exec", Priv.WRITE
        return "sql_exec", Priv.EXEC  # unknown statement class = maximum privilege

    @staticmethod
    def target(sql: str) -> str:
        m = TABLE_RE.search(sql)
        return f"db:{m.group(1)}" if m else "db:*"

    def _begin(self) -> None:
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")

    def _trip(self, pid: int) -> Decision:
        if self.conn.in_transaction:
            self.conn.rollback()
        self.rows_modified = 0
        ac.log("DB-GUARD", f"honey row {CANARY} touched by pid {pid}: session rolled back")
        return self.ctl.evaluate(Action(pid, "sql_query", Priv.READ, CANARY))

    # ---- main entry
    def execute(self, pid: int, sql: str, params: tuple = ()) -> Decision:
        self.last_rows = []
        if CANARY in sql or any(isinstance(p, str) and CANARY in p for p in params):
            return self._trip(pid)
        tool, priv = self.classify(sql)
        a = Action(pid, tool, priv, self.target(sql), {"sql": sql})
        dec = self.ctl.evaluate(a)
        if dec.verdict != Verdict.ALLOW:
            ac.log("DB-GUARD", f"{tool} blocked before execution: {dec.verdict} ({dec.reason})")
            return dec
        if priv == Priv.READ:
            rows = self.conn.execute(sql, params).fetchall()
            if any(CANARY in str(v) for r in rows for v in r):
                return self._trip(pid)
            self.last_rows = rows
            return dec
        self._begin()
        self.sp_counter += 1
        sp = f"aegis_sp_{self.sp_counter}"
        self.conn.execute(f"SAVEPOINT {sp}")
        try:
            cur = self.conn.execute(sql, params)
            n = max(cur.rowcount, 0)
        except sqlite3.Error as e:
            self.conn.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            self.conn.execute(f"RELEASE SAVEPOINT {sp}")
            return self.ctl._block(a, Verdict.DENY, f"sql error: {e}", dec.risk, True)
        if self.rows_modified + n > self.max_rows:
            self.conn.execute(f"ROLLBACK TO SAVEPOINT {sp}")
            self.conn.execute(f"RELEASE SAVEPOINT {sp}")
            ac.log("DB-GUARD", f"ROLLBACK TO SAVEPOINT {sp}: {n} row(s) would bring total to "
                               f"{self.rows_modified + n} > max_rows={self.max_rows}")
            return self.ctl._block(a, Verdict.ESCALATE,
                                   f"blast radius: {self.rows_modified + n} rows > max_rows={self.max_rows}",
                                   dict(dec.risk, rows=n), True)
        self.conn.execute(f"RELEASE SAVEPOINT {sp}")
        self.rows_modified += n
        ac.log("DB-GUARD", f"{sp} released: {n} row(s), session total {self.rows_modified}/{self.max_rows}")
        return dec

    def commit(self) -> None:
        if self.conn.in_transaction:
            self.conn.execute("COMMIT")
        self.rows_modified = 0

    def rollback_all(self) -> None:
        if self.conn.in_transaction:
            self.conn.execute("ROLLBACK")
        self.rows_modified = 0
        ac.log("DB-GUARD", "session rolled back to start")


# --------------------------------------------------------------------------- self-test
def run_self_test() -> int:
    canary_dir = default_canary_dir(); register_cleanup(canary_dir)
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dbguard_", dir="/tmp")); register_cleanup(tmp)
    keydir = Path(tempfile.mkdtemp(prefix="aegis_keys_", dir="/tmp")); register_cleanup(keydir)
    ensure_operator_keypair(keydir)
    fz = ProcessTreeFreezer()
    ctl = AegisController("query the orders table and update the status of one order", canary_dir,
                          load_operator_pubkey(keydir), None, fz)
    conn = sqlite3.connect(str(tmp / "shop.db"))
    conn.execute("CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT, amount INTEGER)")
    conn.executemany("INSERT INTO orders VALUES (?, 'open', ?)", [(f"o{i}", i * 10) for i in range(1, 8)])
    conn.commit()
    g = AegisDBGuard(conn, ctl, max_rows=5)
    g.install_canary("orders")
    snap = lambda: conn.execute("SELECT id, status, amount FROM orders ORDER BY id").fetchall()
    results, agents = [], []

    print("\n=== DB1 aligned SELECT + 1-row UPDATE ===")
    ag = spawn_agent(); fz.register(ag.pid); agents.append(ag)
    d_sel = g.execute(ag.pid, "SELECT status FROM orders WHERE id = ?", ("o1",))
    sel_rows = list(g.last_rows)
    d_upd = g.execute(ag.pid, "UPDATE orders SET status = 'shipped' WHERE id = ?", ("o1",))
    g.commit()
    st1 = conn.execute("SELECT status FROM orders WHERE id='o1'").fetchone()[0]
    results.append(("DB1 aligned SELECT + 1-row UPDATE", d_sel.verdict == Verdict.ALLOW and d_upd.verdict == Verdict.ALLOW
                    and sel_rows == [("open",)] and st1 == "shipped", f"{d_sel.verdict}/{d_upd.verdict} status={st1}"))

    print("\n=== DB2 mass UPDATE exceeds max_rows ===")
    ag = spawn_agent(); fz.register(ag.pid); agents.append(ag)
    before = snap()
    d_mass = g.execute(ag.pid, "UPDATE orders SET status = 'cancelled'")
    after = snap()
    frozen = bool(d_mass.frozen_pids) and all(process_state(p).startswith("T") for p in d_mass.frozen_pids)
    g.rollback_all()
    results.append(("DB2 mass UPDATE -> savepoint rollback + freeze", d_mass.verdict == Verdict.ESCALATE and frozen
                    and before == after, f"{d_mass.verdict} frozen={d_mass.frozen_pids} rows_changed={sum(a != b for a, b in zip(before, after))}"))

    print("\n=== DB3 SELECT touches honey row ===")
    ag = spawn_agent(); fz.register(ag.pid); agents.append(ag)
    d_can = g.execute(ag.pid, "SELECT * FROM orders")
    frozen3 = bool(d_can.frozen_pids) and all(process_state(p).startswith("T") for p in d_can.frozen_pids)
    d_lit = g.execute(ag.pid, f"SELECT * FROM orders WHERE id = '{CANARY}'")
    results.append(("DB3 honey-row SELECT -> CANARY_TRIP + freeze", d_can.verdict == Verdict.TRIP and frozen3
                    and not d_can.approvable and g.last_rows == [] and d_lit.verdict == Verdict.TRIP,
                    f"{d_can.verdict} frozen={d_can.frozen_pids}"))

    conn.close()
    for a in agents:
        reap(a, fz)
    print("\n=== DB GUARD SUMMARY ===")
    for n, ok, info in results:
        print(f"  {n:<48} {'PASS' if ok else 'FAIL'}  {info}")
    return 0 if all(ok for _, ok, _ in results) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ns = ap.parse_args(argv)
    if ns.self_test:
        return run_self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
