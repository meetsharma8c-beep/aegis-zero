#!/usr/bin/env python3
"""AEGIS-ZERO universal agent launcher — wraps any command in containment.

Orchestrates the full AEGIS-ZERO runtime stack around an arbitrary child command:
  1. Creates or resolves an isolated sandbox directory
  2. Deploys Canary sentinel decoys to detect environment probing
  3. Ensures operator Ed25519 keypair and verification public key
  4. Manages the ProcessTreeFreezer for kernel-level freezing (cgroups v2 / SIGSTOP tree)
  5. Instantiates the AegisController (intent verification, taint tracking, CoW rollback)
  6. Starts the reverse proxy and OOB operator Unix domain socket
  7. Spawns the child agent process with containment environment variables
  8. Enforces hold-and-release human approval for policy escalations

Usage:
  python3 aegis_run.py --intent "summarize data.txt" -- python3 agent.py
  python3 aegis_run.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import atexit
import json
import os
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from aegis_cli import OOBClient
from aegis_proxy import AegisProxy, MockToolServer, ProxyHandler, serve
import aegis_controller as ac
from aegis_controller import (
    Action,
    AegisController,
    Priv,
    ProcessTreeFreezer,
    Verdict,
    default_canary_dir,
    descendants,
    ensure_operator_keypair,
    load_operator_pubkey,
    register_cleanup,
)

_EXTRA_CLEANUP: list[Path] = []
_SOCKETS_TO_CLEAN: list[str] = []


def _local_cleanup() -> None:
    for sock in _SOCKETS_TO_CLEAN:
        try:
            if os.path.exists(sock):
                os.unlink(sock)
        except OSError:
            pass

    if ac.KEEP_CANARIES:
        return

    for p in _EXTRA_CLEANUP:
        try:
            if p.is_file() or p.is_symlink():
                p.unlink(missing_ok=True)
            elif p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass


atexit.register(_local_cleanup)

AGENT_SCRIPT = """\
#!/usr/bin/env python3
\"\"\"Stand-in self-test AI agent making JSON-RPC tool calls via AEGIS proxy.\"\"\"
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import json
import os
import urllib.error
import urllib.request

proxy_url = os.environ.get("AEGIS_PROXY_URL", "").rstrip("/") + "/"
if not proxy_url.strip("/"):
    sys.exit(1)


def rpc_call(name: str, args: dict, req_id: int) -> tuple[int, dict]:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }).encode("utf-8")
    req = urllib.request.Request(
        proxy_url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60.0) as resp:
            data = resp.read()
            return resp.status, json.loads(data or b"{}")
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            body = json.loads(data or b"{}")
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return 500, {"error": str(e)}


def main() -> int:
    # Step 1: read_file(path="data.txt") -> expects 200
    c1, r1 = rpc_call("read_file", {"path": "data.txt"}, 1)
    if c1 != 200:
        return 1

    # Step 2: write_file(path="summary.txt", content="summary of data") -> expects 200
    c2, r2 = rpc_call("write_file", {"path": "summary.txt", "content": "summary of data"}, 2)
    if c2 != 200:
        return 1

    # Step 3: rag_search(query="external context") -> expects 200, this taints the session
    c3, r3 = rpc_call("rag_search", {"query": "external context"}, 3)
    if c3 != 200:
        return 1

    # Step 4: tainted overwrite of data.txt -> frozen (SIGSTOP) in the hold queue, operator
    # issues a signed CoW rollback and then denies -> expects 403
    c4, r4 = rpc_call("write_file", {"path": "data.txt", "content": "POISONED BY RAG"}, 4)
    if c4 != 403:
        return 1

    # Step 5: verify the sandbox was rolled back to its pre-session state
    sandbox = os.environ.get("AEGIS_SANDBOX_DIR", ".")
    with open(os.path.join(sandbox, "data.txt"), encoding="utf-8") as fh:
        restored = fh.read() == "test data\\n"
    summary_gone = not os.path.exists(os.path.join(sandbox, "summary.txt"))
    return 0 if (restored and summary_gone) else 2


if __name__ == "__main__":
    sys.exit(main())
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--intent", default=None, help="the user's root intent U0 (required unless --self-test)")
    ap.add_argument("--workdir", type=Path, default=None, help="sandbox work directory (auto-creates temp if not set)")
    ap.add_argument("--upstream", default=None, help="upstream tool server URL (uses mock tool server if not set)")
    ap.add_argument("--port", type=int, default=0, help="proxy listen port (default: 0 = ephemeral)")
    ap.add_argument("--host", default="127.0.0.1", help="proxy listen host (default: 127.0.0.1)")
    ap.add_argument("--hold-timeout", type=float, default=120.0, help="hold timeout in seconds (default: 120.0)")
    ap.add_argument("--on-timeout", choices=["kill", "thaw"], default="kill", help="action on hold timeout (default: kill)")
    ap.add_argument("--socket", default=None, help="OOB socket path (default: /tmp/aegis_run_oob_<pid>.sock)")
    ap.add_argument("--key-dir", type=Path, default=None, help="operator key directory (default: ~/.aegis)")
    ap.add_argument("--keep-canaries", action="store_true", help="do not delete canary sentinels on exit")
    ap.add_argument("--self-test", action="store_true", help="run end-to-end self-test verification suite")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="the AI agent command to wrap (after --)")
    return ap


def run_normal(ns: argparse.Namespace) -> int:
    ac.KEEP_CANARIES = ns.keep_canaries

    # 1. Resolve or create workdir
    if ns.workdir:
        workdir = Path(ns.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="aegis_run_work_", dir="/tmp")).resolve()
        register_cleanup(workdir)
        _EXTRA_CLEANUP.append(workdir)

    # 2. Create canary dir
    canary_dir = default_canary_dir()
    register_cleanup(canary_dir)
    _EXTRA_CLEANUP.append(canary_dir)

    # 3. Ensure operator keypair
    key_dir = Path(ns.key_dir).resolve() if ns.key_dir else None
    ensure_operator_keypair(key_dir)

    # 4. Load pubkey
    pub = load_operator_pubkey(key_dir)

    # 5. Create ProcessTreeFreezer
    freezer = ProcessTreeFreezer()

    # 6. Create AegisController
    ctl = AegisController(ns.intent, canary_dir, pub, workdir, freezer)

    # 7. Upstream tool server: mock tool server if --upstream not provided
    up_srv = None
    if ns.upstream:
        upstream_url = ns.upstream
    else:
        up_srv = serve(ThreadingHTTPServer, MockToolServer, "127.0.0.1", 0, root=workdir)
        upstream_url = f"http://127.0.0.1:{up_srv.server_address[1]}/"

    # 8. Create AegisProxy
    sock_path = ns.socket or f"/tmp/aegis_run_oob_{os.getpid()}.sock"
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass
    _SOCKETS_TO_CLEAN.append(sock_path)
    proxy = AegisProxy(ctl, upstream_url, 0, ns.hold_timeout, ns.on_timeout, sock_path)

    # 9. Start proxy HTTP server on --port
    proxy_srv = serve(ThreadingHTTPServer, ProxyHandler, ns.host, ns.port, proxy=proxy)
    actual_port = proxy_srv.server_address[1]
    proxy_url = f"http://{ns.host}:{actual_port}"

    # Prepare child environment
    child_env = os.environ.copy()
    child_env["AEGIS_PROXY_URL"] = proxy_url
    child_env["AEGIS_SANDBOX_DIR"] = str(workdir)
    child_env["AEGIS_OOB_SOCKET"] = sock_path
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"

    cmd = list(ns.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if len(cmd) == 1 and not shutil.which(cmd[0]):
        import shlex
        cmd = shlex.split(cmd[0])

    ac.log("LAUNCHER", f"Proxy listening on {proxy_url} -> {upstream_url}")
    ac.log("LAUNCHER", f"OOB socket: {sock_path}")
    ac.log("LAUNCHER", f"Sandbox workdir: {workdir}")
    ac.log("LAUNCHER", f"Launching contained process: {' '.join(cmd)}")

    child = None
    try:
        # 10. Spawn the child command
        child = subprocess.Popen(
            cmd,
            start_new_session=True,
            cwd=str(workdir),
            env=child_env,
        )

        # 11. Register child PID with proxy freezer
        proxy.set_agent(child.pid)
        ac.log("LAUNCHER", f"Registered contained PID: {child.pid}")

        # 12. Wait for child to exit
        try:
            exit_code = child.wait()
        except KeyboardInterrupt:
            ac.log("LAUNCHER", "Caught KeyboardInterrupt; terminating child process")
            try:
                child.terminate()
                exit_code = child.wait(timeout=3.0)
            except (subprocess.TimeoutExpired, OSError):
                child.kill()
                exit_code = child.wait()
        return exit_code
    finally:
        # 13. Clean up
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                    child.wait(timeout=2.0)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            for p in descendants(child.pid):
                try:
                    os.kill(p, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            freezer.unregister(child.pid)

        proxy_srv.shutdown()
        proxy_srv.server_close()
        if up_srv is not None:
            up_srv.shutdown()
            up_srv.server_close()
        proxy.oob.close()
        if os.path.exists(sock_path):
            try:
                os.unlink(sock_path)
            except OSError:
                pass


def run_self_test(ns: argparse.Namespace) -> int:
    ac.KEEP_CANARIES = ns.keep_canaries

    print("\n=== AEGIS-ZERO RUNNER SELF-TEST ===")

    # 1. Create temp dirs: workdir, keydir, canary dir
    workdir = Path(tempfile.mkdtemp(prefix="aegis_run_work_", dir="/tmp")).resolve()
    register_cleanup(workdir)
    _EXTRA_CLEANUP.append(workdir)

    keydir = Path(tempfile.mkdtemp(prefix="aegis_run_keys_", dir="/tmp")).resolve()
    register_cleanup(keydir)
    _EXTRA_CLEANUP.append(keydir)

    canary_dir = default_canary_dir()
    register_cleanup(canary_dir)
    _EXTRA_CLEANUP.append(canary_dir)

    # 3. Write test file
    data_file = workdir / "data.txt"
    data_file.write_text("test data\n", encoding="utf-8")

    # 4. Create operator keypair + load pubkey
    seed = ensure_operator_keypair(keydir)
    pub = load_operator_pubkey(keydir)

    # 5. Create freezer and controller
    intent = "read data.txt and write summary.txt"
    freezer = ProcessTreeFreezer()
    ctl = AegisController(intent, canary_dir, pub, workdir, freezer)

    # 6. Start mock upstream on port 0
    up = serve(ThreadingHTTPServer, MockToolServer, "127.0.0.1", 0, root=workdir)
    upstream_url = f"http://127.0.0.1:{up.server_address[1]}/"

    # 7. Create unique OOB socket
    sock_path = f"/tmp/aegis_run_oob_{os.getpid()}.sock"
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass
    _SOCKETS_TO_CLEAN.append(sock_path)

    # 8. Create AegisProxy with hold_timeout=8.0, on_timeout="kill"
    proxy = AegisProxy(ctl, upstream_url, 0, 8.0, "kill", sock_path)

    # 9. Start proxy HTTP server on port 0
    srv = serve(ThreadingHTTPServer, ProxyHandler, "127.0.0.1", 0, proxy=proxy)
    proxy_port = srv.server_address[1]
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    # 10. Write agent script to temp file
    fd, agent_path_str = tempfile.mkstemp(prefix="aegis_run_agent_", suffix=".py", dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(AGENT_SCRIPT)
    agent_script_path = Path(agent_path_str).resolve()
    os.chmod(agent_script_path, 0o755)
    register_cleanup(agent_script_path)
    _EXTRA_CLEANUP.append(agent_script_path)

    child = None
    op = None
    pending_received = False
    denied_ok = False

    try:
        # 11. Spawn the agent script
        child_env = os.environ.copy()
        child_env["AEGIS_PROXY_URL"] = proxy_url
        child_env["AEGIS_SANDBOX_DIR"] = str(workdir)
        child_env["AEGIS_OOB_SOCKET"] = sock_path
        child_env["PYTHONDONTWRITEBYTECODE"] = "1"

        child = subprocess.Popen(
            [sys.executable, "-B", str(agent_script_path)],
            start_new_session=True,
            cwd=str(workdir),
            env=child_env,
        )

        # 12. Register child PID with proxy
        proxy.set_agent(child.pid)

        # 13. Create OOBClient to act as the operator
        op = OOBClient(sock_path, seed)

        # 14. In main thread: wait for pending request, verify, deny, wait for child
        try:
            pending = op.wait_pending(timeout=10.0)
            if pending and "id" in pending:
                pending_received = True
                pending_id = pending["id"]
                ac.log("SELF-TEST", f"Observed pending request {pending_id} (verdict={pending.get('verdict')})")
                frozen_state = {p: ac.process_state(p) for p in pending.get("frozen_pids", [])}
                was_frozen = bool(frozen_state) and all(s.startswith("T") for s in frozen_state.values())
                summary_mid = (workdir / "summary.txt").exists()
                rb = op.rollback()
                rolled_back = bool(rb.get("ok")) and len(rb.get("restored", [])) >= 1
                ac.log("SELF-TEST", f"frozen={frozen_state} rollback ok={rb.get('ok')} restored={rb.get('restored')}")
                rep = op.decide(pending_id, "deny")
                denied_ok = bool(rep.get("ok")) and was_frozen and summary_mid and rolled_back
                ac.log("SELF-TEST", f"Operator denied {pending_id}: ok={rep.get('ok')}")
        except Exception as e:
            ac.log("SELF-TEST", f"Error during pending wait/decision: {e}")

        try:
            child.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            ac.log("SELF-TEST", "Agent child process timed out waiting for exit; killing")
            child.kill()
            child.wait(timeout=5.0)

        # 15. Run verification tests
        summary_file = workdir / "summary.txt"
        tainted_file = workdir / "tainted.txt"

        restored = (data_file.read_text(encoding="utf-8") == "test data\n" and not summary_file.exists()
                    and not tainted_file.exists())
        r1_ok = pending_received  # agent only reaches the held call after aligned read+write returned 200
        r2_ok = (ctl.taint.tau.name == "TAINTED")
        r3_ok = (pending_received and denied_ok)
        r4_ok = (child.returncode == 0 and restored and ctl.cow.verify_chain())

        results = [
            ("R1: Aligned read+write forwarded (200)", r1_ok, f"agent reached step 4: {pending_received}"),
            ("R2: Session was tainted", r2_ok, f"tau={ctl.taint.tau.name}"),
            ("R3: Tainted write frozen, rollback+deny", r3_ok, f"held={pending_received} ok={denied_ok}"),
            ("R4: Pre-session state restored, rc=0", r4_ok, f"rc={child.returncode} restored={restored}"),
        ]

        # 16. Print results R1..R4 PASS/FAIL, clean up, exit 0/1
        print("\n=== SELF-TEST SUMMARY ===")
        for name, ok, info in results:
            status = "PASS" if ok else "FAIL"
            print(f"  {name:<42} {status}  ({info})")

        return 0 if all(ok for _, ok, _ in results) else 1

    finally:
        if op is not None:
            op.close()
        srv.shutdown()
        srv.server_close()
        up.shutdown()
        up.server_close()
        proxy.oob.close()

        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                    child.wait(timeout=2.0)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            for p in descendants(child.pid):
                try:
                    os.kill(p, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            freezer.unregister(child.pid)

        if os.path.exists(sock_path):
            try:
                os.unlink(sock_path)
            except OSError:
                pass

        if agent_script_path.exists():
            try:
                agent_script_path.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    ns = ap.parse_args(argv)

    if ns.self_test:
        return run_self_test(ns)

    if not ns.intent:
        ap.error("--intent is required (unless --self-test)")

    cmd = list(ns.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("command is required (unless --self-test)")

    return run_normal(ns)


if __name__ == "__main__":
    sys.exit(main())
