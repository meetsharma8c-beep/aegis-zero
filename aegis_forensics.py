#!/usr/bin/env python3
"""AEGIS-ZERO signed incident bundle exporter and Merkle WAL chain verifier.

A bundle is canonical JSON (sorted keys, no whitespace) holding the session state,
the blocking decision, the full CoW WAL hash chain, compliance tags and an
Ed25519 operator signature over the canonical payload. Verification checks the
signature, recomputes every WAL link from genesis "0"*64, and recomputes the
RFC 6962 Merkle root.

  python3 -B aegis_forensics.py --self-test
  python3 -B aegis_forensics.py --verify bundle.json [--key-dir ~/.aegis]
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, json, tempfile, time
from pathlib import Path

import aegis_controller as ac
from aegis_controller import (Action, AegisController, CoWShadowStore, Decision, Ed25519, Priv, ProcessTreeFreezer,
                              Taint, Verdict, canonical, default_canary_dir, ensure_operator_keypair,
                              load_operator_pubkey, reap, register_cleanup, spawn_agent)

GENESIS = "0" * 64
SCHEMA = "aegis.incident.v1"
TAG_LLM01 = "OWASP-LLM01:2025 Prompt Injection"
TAG_LLM06 = "OWASP-LLM06:2025 Excessive Agency"
TAG_NIST = "NIST-AI-RMF-MANAGE-2.4"


def signed_message(payload: dict) -> bytes:
    return b"aegis.incident.v1|" + canonical(payload)


class ForensicExporter:
    @staticmethod
    def compliance_tags(ctl: AegisController, decision: Decision) -> list[str]:
        tags = []
        if ctl.taint.tau is Taint.TAINTED or ctl.taint.lineage:
            tags.append(TAG_LLM01)
        if decision.verdict != Verdict.ALLOW:
            tags.append(TAG_LLM06)
        tags.append(TAG_NIST)
        return tags

    def export_bundle(self, controller: AegisController, decision: Decision, out_path: Path,
                      operator_priv_key: bytes) -> dict:
        wal = [dict(e) for e in controller.cow.wal] if controller.cow is not None else []
        root = controller.cow.merkle_root() if controller.cow is not None else CoWShadowStore._mth([]).hex()
        payload = {
            "schema": SCHEMA,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "timestamp_ns": time.time_ns(),
            "u0": controller.u0,
            "taint": controller.taint.tau.name,
            "taint_lineage": list(controller.taint.lineage),
            "ewma": round(controller.graph.ewma, 6),
            "decision": {"verdict": decision.verdict, "reason": decision.reason,
                         "risk": decision.risk, "frozen_pids": list(decision.frozen_pids)},
            "merkle_root": root,
            "wal_chain": wal,
            "compliance_tags": self.compliance_tags(controller, decision),
            "signer_pub": Ed25519.public_from_seed(operator_priv_key).hex(),
            "sig_alg": "Ed25519",
        }
        payload = json.loads(canonical(payload))  # normalise exactly as it will be verified
        bundle = dict(payload, signature=Ed25519.sign(operator_priv_key, signed_message(payload)).hex())
        out_path.write_bytes(canonical(bundle))
        ac.log("FORENSICS", f"bundle {out_path.name}: verdict={decision.verdict} wal={len(wal)} "
                            f"root={root[:16]} tags={len(payload['compliance_tags'])}")
        return bundle

    @staticmethod
    def verify_bundle(bundle_path: Path, operator_pub_key: bytes) -> tuple[bool, str]:
        try:
            bundle = json.loads(Path(bundle_path).read_bytes())
            payload = {k: v for k, v in bundle.items() if k != "signature"}
            sig = bytes.fromhex(bundle["signature"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            return False, f"unparseable bundle: {e}"
        if payload.get("schema") != SCHEMA:
            return False, "wrong schema"
        if not Ed25519.verify(operator_pub_key, signed_message(payload), sig):
            return False, "signature invalid"
        prev = GENESIS
        try:
            for i, e in enumerate(payload["wal_chain"]):
                if e["index"] != i or e["prev"] != prev:
                    return False, f"WAL link {i} broken"
                h = CoWShadowStore.leaf(prev, i, e["tool"], e["path"], e["before"], e["after"], e["taint"], e["ts_ns"])
                if h != e["H"]:
                    return False, f"WAL leaf {i} hash mismatch"
                prev = h
            root = CoWShadowStore._mth([bytes.fromhex(e["H"]) for e in payload["wal_chain"]]).hex()
        except (KeyError, TypeError, ValueError) as e:
            return False, f"malformed WAL: {e}"
        if root != payload["merkle_root"]:
            return False, "merkle_root mismatch"
        return True, f"signature ok, {len(payload['wal_chain'])} WAL links ok, root {root[:16]}"


# --------------------------------------------------------------------------- self-test
def run_self_test() -> int:
    canary_dir = default_canary_dir(); register_cleanup(canary_dir)
    tmp = Path(tempfile.mkdtemp(prefix="aegis_forensics_", dir="/tmp")).resolve(); register_cleanup(tmp)
    work = tmp / "work"; work.mkdir()
    (work / "report.md").write_text("Q3 revenue grew 12%.\n")
    keydir = Path(tempfile.mkdtemp(prefix="aegis_keys_", dir="/tmp")); register_cleanup(keydir)
    seed = ensure_operator_keypair(keydir)
    pub = load_operator_pubkey(keydir)
    fz = ProcessTreeFreezer()
    ctl = AegisController("summarize report.md using the knowledge base and write summary.md",
                          canary_dir, pub, work, fz)
    ag = spawn_agent(); fz.register(ag.pid)
    results = []

    d_w = ctl.evaluate(Action(ag.pid, "write_file", Priv.WRITE, "summary.md", {"content": "x"}))
    (work / "summary.md").write_text("Revenue +12%.\n")
    leaf = ctl.commit(d_w.stage)
    ctl.evaluate(Action(ag.pid, "rag_search", Priv.READ, "kb://q3", external_source="kb://q3/poisoned.pdf#p7"))
    d_trip = ctl.evaluate(Action(ag.pid, "stat", Priv.READ, str(canary_dir / ".env")))
    ctl.rollback()  # zero-tolerance response appends a ROLLBACK leaf to the chain
    results.append(("F1 write + canary trip recorded", d_w.verdict == Verdict.ALLOW and leaf is not None
                    and d_trip.verdict == Verdict.TRIP and bool(d_trip.frozen_pids) and len(ctl.cow.wal) == 2,
                    f"write={d_w.verdict} trip={d_trip.verdict} wal={len(ctl.cow.wal)}"))

    fx = ForensicExporter()
    path = tmp / "incident.json"
    bundle = fx.export_bundle(ctl, d_trip, path, seed)
    ok, why = fx.verify_bundle(path, pub)
    tags_ok = {TAG_LLM01, TAG_LLM06, TAG_NIST} <= set(bundle["compliance_tags"])
    results.append(("F2 signed bundle verifies", ok and tags_ok, why))

    raw = path.read_text()
    i = raw.index('"reason":"') + len('"reason":"')
    path.write_text(raw[:i] + ("X" if raw[i] != "X" else "Y") + raw[i + 1:])
    ok_m, why_m = fx.verify_bundle(path, pub)
    path.write_text(raw)
    forged = json.loads(raw)
    forged["wal_chain"][0]["after"] = "f" * 64
    forged["signature"] = Ed25519.sign(seed, signed_message({k: v for k, v in forged.items() if k != "signature"})).hex()
    path.write_bytes(canonical(forged))
    ok_c, why_c = fx.verify_bundle(path, pub)
    path.write_text(raw)
    ok_k, why_k = fx.verify_bundle(path, Ed25519.public_from_seed(b"\x01" * 32))
    results.append(("F3 1-char tamper rejected", not ok_m, why_m))
    results.append(("F4 re-signed WAL forgery rejected", not ok_c and "WAL" in why_c, why_c))
    results.append(("F5 wrong operator key rejected", not ok_k, why_k))

    reap(ag, fz)
    print("\n=== FORENSICS SUMMARY ===")
    for n, ok_, info in results:
        print(f"  {n:<40} {'PASS' if ok_ else 'FAIL'}  {info}")
    return 0 if all(ok_ for _, ok_, _ in results) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verify", type=Path, help="verify an incident bundle")
    ap.add_argument("--key-dir", type=Path, default=None)
    ns = ap.parse_args(argv)
    if ns.self_test:
        return run_self_test()
    if ns.verify:
        ok, why = ForensicExporter.verify_bundle(ns.verify, load_operator_pubkey(ns.key_dir))
        print(("VALID: " if ok else "INVALID: ") + why)
        return 0 if ok else 1
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
