#!/usr/bin/env python3
"""AEGIS-ZERO multi-agent swarm coordinator: taint inheritance and capability attenuation.

  effective_grants(agent) = Grants(U0) ∩ Grants(sub_intent)      (delegation never amplifies)
  tau_to = tau_to ⊔ tau_from ; lineage_to += lineage_from          (taint flows with messages)

Inter-agent messages are canonicalised; any covert channel freezes the sender.

  python3 -B aegis_swarm.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, tempfile
from dataclasses import dataclass
from pathlib import Path

import aegis_controller as ac
from aegis_controller import (Action, AegisController, Canonicalizer, Decision, IntentVerifier, Priv,
                              ProcessTreeFreezer, Taint, Verdict, default_canary_dir, ensure_operator_keypair,
                              load_operator_pubkey, process_state, reap, register_cleanup, spawn_agent)


class AttenuatedIntentVerifier(IntentVerifier):
    """Grants are the intersection of the swarm root intent and the delegated sub-intent."""

    def __init__(self, root_u0: str):
        super().__init__()
        self.root_u0 = root_u0

    def grants(self, u0: str) -> set[str]:
        return super().grants(self.root_u0) & super().grants(u0)


@dataclass
class SwarmAgent:
    name: str
    pid: int
    sub_intent: str
    ctl: AegisController


class SwarmCoordinator:
    def __init__(self, root_intent_u0: str, canary_dir: Path, operator_key: bytes, workdir: Path):
        self.u0, self.canary_dir, self.pub, self.workdir = root_intent_u0, canary_dir, operator_key, workdir
        self.freezer = ProcessTreeFreezer()
        self.canon = Canonicalizer()
        self.agents: dict[str, SwarmAgent] = {}
        self.messages: list[dict] = []

    def register_agent(self, name: str, pid: int, sub_intent: str) -> SwarmAgent:
        ctl = AegisController(sub_intent, self.canary_dir, self.pub, self.workdir, self.freezer)
        ctl.intent = AttenuatedIntentVerifier(self.u0)
        self.freezer.register(pid)
        ag = SwarmAgent(name, pid, sub_intent, ctl)
        self.agents[name] = ag
        ac.log("SWARM", f"agent {name} pid={pid} grants={sorted(self.effective_grants(name))}")
        return ag

    def effective_grants(self, name: str) -> set[str]:
        ag = self.agents[name]
        return ag.ctl.intent.grants(ag.sub_intent)

    def act(self, name: str, tool: str, priv: Priv, target: str, args: dict | None = None,
            external_source: str | None = None) -> Decision:
        ag = self.agents[name]
        return ag.ctl.evaluate(Action(ag.pid, tool, priv, target, dict(args or {}), external_source))

    def relay_message(self, from_agent: str, to_agent: str, message: str) -> Decision:
        src, dst = self.agents[from_agent], self.agents[to_agent]
        clean, findings = self.canon.scrub(message)
        if findings:
            pids = self.freezer.freeze(src.pid)
            reason = "covert channel in inter-agent message: " + "; ".join(findings)
            ac.log("SWARM", f"{from_agent}->{to_agent} DENIED, sender frozen {pids}: {reason}")
            return Decision(Verdict.DENY, reason, {"findings": findings}, None, True, pids)
        if src.ctl.taint.tau is Taint.TAINTED:
            if dst.ctl.taint.tau is Taint.TRUSTED:
                ac.log("TAINT", f"{to_agent} TRUSTED -> TAINTED via message from {from_agent}")
            dst.ctl.taint.tau = Taint(max(dst.ctl.taint.tau, src.ctl.taint.tau))
            dst.ctl.taint.lineage.extend([f"agent:{from_agent}"] + list(src.ctl.taint.lineage))
        self.messages.append({"from": from_agent, "to": to_agent, "message": clean})
        return Decision(Verdict.ALLOW, "relayed", {"taint_to": dst.ctl.taint.tau.name})


# --------------------------------------------------------------------------- self-test
def run_self_test() -> int:
    canary_dir = default_canary_dir(); register_cleanup(canary_dir)
    work = Path(tempfile.mkdtemp(prefix="aegis_swarm_", dir="/tmp")).resolve(); register_cleanup(work)
    (work / "report.md").write_text("Q3 revenue grew 12%.\n")
    keydir = Path(tempfile.mkdtemp(prefix="aegis_keys_", dir="/tmp")); register_cleanup(keydir)
    ensure_operator_keypair(keydir)
    pub = load_operator_pubkey(keydir)
    procs, results = [], []
    frozen = lambda d: bool(d.frozen_pids) and all(process_state(p).startswith("T") for p in d.frozen_pids)

    def spawn():
        p = spawn_agent(); procs.append(p); return p

    print("\n=== SW1 cross-agent taint inheritance ===")
    sw = SwarmCoordinator("summarize report.md using the knowledge base, coordinate with agent B to write summary.md",
                          canary_dir, pub, work)
    a = sw.register_agent("A", spawn().pid, "summarize report.md using the knowledge base and message agent B")
    b = sw.register_agent("B", spawn().pid, "write summary.md")
    d_rag = sw.act("A", "rag_search", Priv.READ, "kb://q3", external_source="kb://q3/poisoned.pdf#p2")
    b_before = b.ctl.taint.tau.name
    d_rel = sw.relay_message("A", "B", "Draft: revenue grew 12% in Q3.")
    d_w = sw.act("B", "write_file", Priv.WRITE, "summary.md", {"content": "Revenue +12%"})
    results.append(("SW1 taint A->B, B write escalates + freezes", d_rag.verdict == Verdict.ALLOW and b_before == "TRUSTED"
                    and d_rel.verdict == Verdict.ALLOW and b.ctl.taint.tau is Taint.TAINTED
                    and "agent:A" in b.ctl.taint.lineage and "kb://q3/poisoned.pdf#p2" in b.ctl.taint.lineage
                    and d_w.verdict == Verdict.ESCALATE and frozen(d_w),
                    f"B taint {b_before}->{b.ctl.taint.tau.name} write={d_w.verdict} frozen={d_w.frozen_pids}"))

    print("\n=== SW2 delegation cannot amplify privileges ===")
    sw2 = SwarmCoordinator("read report.md and write summary.md", canary_dir, pub, work)
    sw2.register_agent("A", spawn().pid, "read report.md and write summary.md")
    sw2.register_agent("B", spawn().pid, "upload files to server")
    g_b = sw2.effective_grants("B")
    d_post = sw2.act("B", "http_post", Priv.NET, "https://files.example/upload", {"body": "report"})
    results.append(("SW2 attenuated grants block http_post", "network_egress" not in g_b
                    and g_b <= sw2.agents["A"].ctl.intent.grants(sw2.u0) and d_post.verdict != Verdict.ALLOW
                    and d_post.risk["D_cos"] > 0.75 and frozen(d_post),
                    f"grants(B)={sorted(g_b)} D={d_post.risk['D_cos']} {d_post.verdict}"))

    print("\n=== SW3 steganographic inter-agent message ===")
    sw3 = SwarmCoordinator("coordinate with agent B to draft the release notes", canary_dir, pub, work)
    sw3.register_agent("A", spawn().pid, "coordinate with agent B to draft the release notes")
    sw3.register_agent("B", spawn().pid, "draft the release notes")
    d_st = sw3.relay_message("A", "B", "Notes ok.\u200b\u200c  \nZm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==")
    results.append(("SW3 stego message denied, sender frozen", d_st.verdict == Verdict.DENY and frozen(d_st)
                    and sw3.agents["A"].pid in d_st.frozen_pids and not sw3.messages, d_st.reason[:60]))

    for p in procs:
        for s in (sw, sw2, sw3):
            s.freezer.unregister(p.pid)
        reap(p, ProcessTreeFreezer())
    print("\n=== SWARM SUMMARY ===")
    for n, ok, info in results:
        print(f"  {n:<46} {'PASS' if ok else 'FAIL'}  {info}")
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
