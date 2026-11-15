#!/usr/bin/env python3
"""AEGIS-ZERO OOB operator console (the human enclave side).

Connects to the proxy's Unix socket, streams telemetry and pending frozen
actions, and signs decisions with the operator's Ed25519 private key
(~/.aegis/operator_ed25519.key, 0600). The proxy only holds the public key
(~/.aegis/operator_ed25519.pub), so a compromised proxy cannot forge approvals.

  python3 aegis_cli.py --init-key            # create keypair, print public key
  python3 aegis_cli.py [--socket /tmp/aegis_oob.sock] [--key-dir ~/.aegis]
  commands:  list | status | show <id> | approve <id> | deny <id> [--kill] | rollback | quiet | verbose | quit
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, json, queue, socket, threading, time
from pathlib import Path

from aegis_controller import Ed25519, ensure_operator_keypair, operator_sign, operator_sign_command

DEFAULT_SOCK = "/tmp/aegis_oob.sock"


class OOBClient:
    """Programmatic client used by both the interactive console and the demo."""

    def __init__(self, path: str = DEFAULT_SOCK, seed: bytes | None = None, on_message=None):
        self.seed = seed if seed is not None else ensure_operator_keypair()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.file = self.sock.makefile("rwb", buffering=0)
        self.pending: dict[str, dict] = {}
        self.telemetry: dict = {}
        self.replies: queue.Queue = queue.Queue()
        self.events: queue.Queue = queue.Queue()
        self.on_message = on_message
        self.closed = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        try:
            for raw in self.file:
                msg = json.loads(raw)
                kind = msg.get("type")
                if kind == "telemetry":
                    self.telemetry = msg["data"]
                    self.pending = {p["id"]: p for p in msg["data"].get("pending", [])}
                elif kind == "pending":
                    self.pending[msg["data"]["id"]] = msg["data"]
                    self.events.put(msg)
                elif kind == "resolved":
                    self.pending.pop(msg["data"]["id"], None)
                    self.events.put(msg)
                elif kind == "reply":
                    self.replies.put(msg)
                if self.on_message:
                    self.on_message(msg)
        except (OSError, ValueError):
            pass
        finally:
            self.closed.set()

    def _send(self, obj: dict, timeout: float = 10.0) -> dict:
        self.file.write((json.dumps(obj) + "\n").encode())
        return self.replies.get(timeout=timeout)

    def decide(self, rid: str, decision: str, kill: bool = False, sig_key: bytes | None = None) -> dict:
        p = self.pending.get(rid)
        if p is None:
            return {"type": "reply", "ok": False, "error": f"unknown request {rid}"}
        sig = operator_sign(sig_key if sig_key is not None else self.seed, p["payload"], decision)
        return self._send({"cmd": decision, "id": rid, "sig": sig, "kill": kill})

    def rollback(self) -> dict:
        ts = time.time_ns()
        sig = operator_sign_command(self.seed, "rollback", ts)
        rep = self._send({"cmd": "rollback", "ts": ts, "sig": sig})
        rep["_ts"], rep["_sig"] = ts, sig
        return rep

    def wait_pending(self, timeout: float = 10.0) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            try:
                m = self.events.get(timeout=max(0.01, end - time.time()))
            except queue.Empty:
                break
            if m["type"] == "pending":
                return m["data"]
        raise TimeoutError("no pending request arrived")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def render(p: dict) -> str:
    pl, r = p["payload"], p["payload"]["risk"]
    lines = [
        "+" + "-" * 78,
        f"| PENDING {p['id']}   verdict={p['verdict']}   approvable={pl['approvable']}   frozen={p['frozen_pids']}",
        f"| U0 (root intent) : {pl['user_root_intent']}",
        f"| A_t (AST)        : {json.dumps(pl['proposed_action_ast'])}",
        f"| reason           : {pl['reason']}",
        f"| risk             : " + "  ".join(f"{k}={v}" for k, v in r.items()),
        f"| blast radius     : {pl['blast_radius']['priv']} {pl['blast_radius']['target']}",
        f"| object sha256    : {pl['blast_radius']['object_id_sha256']}",
        f"| taint lineage    : {' -> '.join(pl['taint_lineage']) or '(none)'}",
        f"| challenge nonce  : {pl['challenge']}",
        "+" + "-" * 78,
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket", default=DEFAULT_SOCK)
    ap.add_argument("--key-dir", type=Path, default=None)
    ap.add_argument("--init-key", action="store_true", help="create the operator keypair and exit")
    ns = ap.parse_args()
    seed = ensure_operator_keypair(ns.key_dir)
    if ns.init_key:
        print(f"operator public key ({Ed25519.backend}): {Ed25519.public_from_seed(seed).hex()}")
        return 0
    state = {"verbose": False}

    def on_msg(m: dict) -> None:
        if m["type"] == "pending":
            print("\n" + render(m["data"]) + "\naegis> ", end="", flush=True)
        elif m["type"] == "rollback":
            print(f"\n[rollback] restored {len(m['data']['restored'])} object(s); merkle_root="
                  f"{m['data']['merkle_root'][:16]}\naegis> ", end="", flush=True)
        elif m["type"] == "resolved":
            print(f"\n[resolved] {m['data']['id']} -> {m['data']['outcome']}\naegis> ", end="", flush=True)
        elif m["type"] == "telemetry" and state["verbose"]:
            t = m["data"]
            print(f"\n[telemetry] taint={t['taint']} H={t['H_graph']} ewma={t['ewma']} R={t['last_risk'].get('R')} "
                  f"tokens={t['active_tokens']} wal={t.get('wal_entries')} root={str(t.get('merkle_root'))[:12]} "
                  f"pending={len(t['pending'])}\naegis> ", end="", flush=True)

    try:
        cli = OOBClient(ns.socket, seed, on_msg)
    except OSError as e:
        print(f"cannot connect to {ns.socket}: {e}", file=sys.stderr)
        return 2
    print(f"connected to {ns.socket}. type 'help'.")
    while not cli.closed.is_set():
        try:
            line = input("aegis> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd in ("quit", "exit"):
            break
        if cmd == "help":
            print(__doc__)
        elif cmd == "verbose":
            state["verbose"] = True
        elif cmd == "quiet":
            state["verbose"] = False
        elif cmd == "status":
            t = cli.telemetry
            print(json.dumps({k: v for k, v in t.items() if k != "pending"}, indent=2))
        elif cmd == "list":
            if not cli.pending:
                print("(no pending actions)")
            for p in cli.pending.values():
                print(f"  {p['id']}  {p['verdict']:<12} {p['payload']['proposed_action_ast']['tool']} "
                      f"{p['payload']['proposed_action_ast']['target']}  ({p['payload']['reason']})")
        elif cmd == "show" and len(parts) == 2 and parts[1] in cli.pending:
            print(render(cli.pending[parts[1]]))
        elif cmd == "rollback":
            try:
                rep = cli.rollback()
            except queue.Empty:
                rep = {"ok": False, "error": "timeout waiting for proxy"}
            print(f"restored {len(rep.get('restored', []))} object(s)" if rep.get("ok") else f"REJECTED: {rep.get('error')}")
        elif cmd in ("approve", "deny") and len(parts) >= 2:
            try:
                rep = cli.decide(parts[1], cmd, kill="--kill" in parts[2:])
            except queue.Empty:
                rep = {"ok": False, "error": "timeout waiting for proxy"}
            print("OK" if rep.get("ok") else f"REJECTED: {rep.get('error')}")
        else:
            print("unknown command; type 'help'")
    cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
