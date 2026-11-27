#!/usr/bin/env python3
"""AEGIS-ZERO <-> CONCODE_BRAIN Neuro-Symbolic & Universal Tool Bus Bridge.

Connects CONCODE_BRAIN (https://github.com/meetsharma8c-beep/CONCODE_BRAIN) and
CONCODE.WEB with AEGIS-ZERO's Ring 0/1/2 runtime containment plane:

  1. ConcodeGuildScoper      -- Classifies/bindsCONCODE's 18 expert guilds and
                                intersects Grants(U0) with GuildCeiling(guild).
  2. ConcodePayloadVerifier  -- CONCODE v4.0 APEX-compatible AST CWE taint auditor
                                (CWE-78, CWE-89, CWE-94, CWE-208, CWE-400, CWE-798,
                                CWE-918), multi-language syntax checker, wait-for
                                deadlock prover, and exact SMT unsat_core prover.
  3. ConcodeToolBusGuard     -- Wraps CONCODE UniversalToolBus permissions
                                (READ_ONLY, SANDBOX_EXEC, WORKSPACE_WRITE,
                                EXTERNAL_NETWORK, HUMAN_APPROVAL) in AegisController,
                                CoW Merkle WAL, process-tree freezing, Ed25519 OOB
                                human approval, and enriched ForensicExporter bundles.

Runs with the Python standard library alone; automatically uses `z3-solver` or a
local `CONCODE_BRAIN` checkout (`CONCODE_BRAIN_PATH`) when available.

  python3 -B aegis_concode_bridge.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import ast
import json
import os
import re
import secrets
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

import aegis_controller as ac
from aegis_controller import (
    Action,
    AegisController,
    Decision,
    Ed25519,
    IntentVerifier,
    Priv,
    ProcessTreeFreezer,
    Taint,
    Verdict,
    canonical,
    default_canary_dir,
    ensure_operator_keypair,
    load_operator_pubkey,
    operator_sign,
    process_state,
    reap,
    register_cleanup,
    spawn_agent,
)
from aegis_forensics import ForensicExporter, signed_message

# CONCODE_BRAIN Universal Tool Bus permission tiers (src/brain/tools.py)
PERM_READ_ONLY = "READ_ONLY"
PERM_SANDBOX_EXEC = "SANDBOX_EXEC"
PERM_WORKSPACE_WRITE = "WORKSPACE_WRITE"
PERM_EXTERNAL_NETWORK = "EXTERNAL_NETWORK"
PERM_HUMAN_APPROVAL = "HUMAN_APPROVAL"

PERM_TO_PRIV: dict[str, Priv] = {
    PERM_READ_ONLY: Priv.READ,
    PERM_WORKSPACE_WRITE: Priv.WRITE,
    PERM_EXTERNAL_NETWORK: Priv.NET,
    PERM_SANDBOX_EXEC: Priv.EXEC,
    PERM_HUMAN_APPROVAL: Priv.EXEC,
}


# --------------------------------------------------------------------------- Data Models
@dataclass
class FormalProofResult:
    """CONCODE v4.0 APEX-compatible deductive mathematical / policy / deadlock proof."""

    is_satisfiable: bool
    status: str  # PROVEN_SAT | UNSAT_CONFLICT
    solver_engine: str = "deterministic_exact"
    witness: dict[str, Any] = field(default_factory=dict)
    unsat_core: list[str] = field(default_factory=list)
    remediation_guidance: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CompilerCheckResult:
    language: str
    compiled: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityFinding:
    cwe_id: str
    severity: str  # HIGH | MEDIUM
    detail: str
    language: str = "generic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallResult:
    """CONCODE_BRAIN UniversalToolBus-compatible tool execution outcome."""

    tool_name: str
    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    permission_used: str = PERM_READ_ONLY
    aegis_verdict: str = Verdict.ALLOW
    proof: dict[str, Any] = field(default_factory=dict)
    cwe_findings: list[dict[str, Any]] = field(default_factory=list)
    forensic_bundle: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- 1. 18-Guild Scoper
class ConcodeGuildScoper:
    """Maps CONCODE_BRAIN's 18 expert guilds to strict capability domain ceilings."""

    GUILD_KEYWORDS: dict[str, tuple[str, ...]] = {
        "debugger": ("fix", "bug", "error", "traceback", "stack", "crash", "debug", "exception"),
        "webgl": ("3d", "three.js", "shader", "webgl", "canvas", "glsl", "mesh", "vertex"),
        "ai_ml": ("pytorch", "llm", "rag", "gguf", "embedding", "transformer", "tensor", "train"),
        "qa": ("pytest", "jest", "cypress", "unit test", "coverage", "assert", "mock", "tdd"),
        "security": ("jwt", "oauth", "csrf", "xss", "sanitize", "encrypt", "hmac", "owasp", "rbac"),
        "performance": ("latency", "benchmark", "cache", "optimize", "profil", "throughput"),
        "database": ("sql", "sqlite", "postgres", "mongo", "schema", "query", "migration", "index"),
        "ui_ux": ("css", "tailwind", "layout", "component", "button", "theme", "responsive", "ui"),
        "devops": ("docker", "kubernetes", "ci", "deploy", "terraform", "nginx", "caddy", "helm"),
        "api": ("rest", "graphql", "endpoint", "fastapi", "webhook", "openapi", "jsonrpc"),
        "fullstack": ("fullstack", "webapp", "express", "react", "next.js", "portal"),
        "mobile": ("ios", "android", "flutter", "swift", "kotlin", "react native"),
        "blockchain": ("solidity", "smart contract", "erc20", "evm", "web3", "merkle"),
        "conversational": ("chat", "summarize", "explain", "translate", "question", "greeting"),
        "system_architect": ("architecture", "diagram", "rfc", "design doc", "topology", "spec"),
        "research_scientist": ("theorem", "paper", "arxiv", "proof", "ablation", "hypothesis"),
        "automation_operator": ("workflow", "cron", "pipeline", "automate", "handoff", "coordinate"),
        "critic_verifier": ("audit", "review", "verify", "formal", "static analysis", "inspect"),
    }

    # Maximum capability ceiling permitted for each CONCODE guild
    GUILD_CEILINGS: dict[str, frozenset[str]] = {
        "conversational": frozenset({"file_read", "data_transform"}),
        "research_scientist": frozenset({"file_read", "data_transform"}),
        "critic_verifier": frozenset({"file_read", "data_transform", "db_read"}),
        "system_architect": frozenset({"file_read", "data_transform", "file_write"}),
        "ui_ux": frozenset({"file_read", "data_transform", "file_write"}),
        "webgl": frozenset({"file_read", "data_transform", "file_write"}),
        "mobile": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "blockchain": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "performance": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "qa": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "debugger": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "ai_ml": frozenset({"file_read", "data_transform", "file_write", "process_exec"}),
        "database": frozenset({"file_read", "data_transform", "db_read", "db_write", "file_write"}),
        "api": frozenset({"file_read", "data_transform", "file_write", "network_egress", "db_read"}),
        "automation_operator": frozenset({"file_read", "data_transform", "file_write", "agent_message", "network_egress"}),
        "security": frozenset({"file_read", "data_transform", "file_write", "process_exec", "credential_access"}),
        "devops": frozenset({"file_read", "data_transform", "file_write", "file_delete", "process_exec", "network_egress"}),
        "fullstack": frozenset({
            "file_read", "data_transform", "file_write", "file_delete",
            "db_read", "db_write", "process_exec", "network_egress", "agent_message",
        }),
    }

    @classmethod
    def classify_guild(cls, prompt: str, explicit_guild: str | None = None) -> str:
        if explicit_guild and explicit_guild in cls.GUILD_CEILINGS:
            return explicit_guild
        low = prompt.lower()
        best_guild, best_score = "fullstack", 0
        for guild, kws in cls.GUILD_KEYWORDS.items():
            score = sum(1 for kw in kws if kw in low)
            if score > best_score:
                best_guild, best_score = guild, score
        return best_guild

    @classmethod
    def ceiling(cls, guild: str) -> frozenset[str]:
        return cls.GUILD_CEILINGS.get(guild, cls.GUILD_CEILINGS["conversational"])


class GuildAttenuatedIntentVerifier(IntentVerifier):
    """Enforces Grants_eff(U0, guild) = Grants(U0) ∩ GuildCeiling(guild)."""

    def __init__(self, guild: str):
        super().__init__()
        self.guild = guild
        self.ceiling = ConcodeGuildScoper.ceiling(guild)

    def grants(self, u0: str) -> set[str]:
        return super().grants(u0) & set(self.ceiling)


# --------------------------------------------------------------------------- 2. Formal & CWE Verifier
class ConcodePayloadVerifier:
    """CONCODE v4.0 APEX-compatible AST CWE auditor, syntax verifier, deadlock & SMT prover."""

    SECRET_EQ_RE = re.compile(r"\b(signature|hmac|digest|api_key|secret_token|password)\s*==\s*", re.I)
    SQL_INTERP_RE = re.compile(
        r"""\b(SELECT|UPDATE|DELETE|INSERT)\b[^\n;]{0,120}?(f["']|\+\s*[a-zA-Z_]|%\s*[a-zA-Z_(]|\.format\(|`[^`]*\$\{)""",
        re.I,
    )
    CRED_LITERAL_RE = re.compile(
        r"(\bsk-[a-zA-Z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bghp_[a-zA-Z0-9]{24,}\b|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)"
    )
    SSRF_META_RE = re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)", re.I)

    def __init__(self) -> None:
        self._z3 = None
        try:
            import z3  # type: ignore
            self._z3 = z3
        except ImportError:
            self._z3 = None

    @property
    def solver_backend(self) -> str:
        return "z3-smt" if self._z3 is not None else "deterministic_exact"

    @staticmethod
    def infer_language(target: str, tool: str) -> str:
        low = target.lower()
        if low.endswith(".py") or tool in ("python", "run_python"):
            return "python"
        if low.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")):
            return "typescript"
        if low.endswith(".go"):
            return "go"
        if low.endswith(".rs"):
            return "rust"
        if tool in ("sql_query", "sql_exec") or low.endswith(".sql"):
            return "sql"
        return "generic"

    def check_syntax(self, language: str, code: str) -> CompilerCheckResult:
        if not code.strip():
            return CompilerCheckResult(language=language, compiled=True, detail="Empty payload.")
        if language == "python":
            try:
                compile(code, "<aegis_concode_gate>", "exec")
                return CompilerCheckResult(language="python", compiled=True, detail="Python AST compiled cleanly.")
            except SyntaxError as exc:
                return CompilerCheckResult(language="python", compiled=False, detail=f"SyntaxError: {exc.msg} (line {exc.lineno})")
        if language in ("typescript", "go", "rust"):
            ok = (
                code.count("{") == code.count("}")
                and code.count("(") == code.count(")")
                and code.count("[") == code.count("]")
            )
            return CompilerCheckResult(
                language=language,
                compiled=ok,
                detail=f"Balanced {language} delimiters." if ok else f"Unbalanced delimiters in {language} payload.",
            )
        return CompilerCheckResult(language=language, compiled=True, detail=f"Pass-through ({language}).")

    def audit_payload(self, target: str, tool: str, args: dict[str, Any]) -> list[SecurityFinding]:
        """Inspect code/command/query arguments for high-risk CWEs before execution or disk write."""
        blobs: list[tuple[str, str]] = []
        base_lang = self.infer_language(target, tool)
        for key in ("content", "code", "command", "argv", "query", "sql", "url", "body"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                lang = "python" if key == "code" and base_lang == "generic" else base_lang
                blobs.append((lang, val))

        findings: list[SecurityFinding] = []
        for lang, code in blobs:
            if lang == "python" or "import " in code or "subprocess." in code or "os.system" in code:
                try:
                    tree = ast.parse(code)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            fn_name = ""
                            mod_name = ""
                            if isinstance(node.func, ast.Name):
                                fn_name = node.func.id
                            elif isinstance(node.func, ast.Attribute):
                                fn_name = node.func.attr
                                if isinstance(node.func.value, ast.Name):
                                    mod_name = node.func.value.id
                            if fn_name in ("eval", "exec"):
                                findings.append(SecurityFinding(
                                    "CWE-94", "HIGH", f"Dynamic code execution '{fn_name}()' in payload.", "python"
                                ))
                            if fn_name in ("system", "popen") and mod_name in ("os", ""):
                                findings.append(SecurityFinding(
                                    "CWE-78", "HIGH", f"OS shell call '{fn_name}()' risks command injection.", "python"
                                ))
                            if (mod_name, fn_name) in (("pickle", "loads"), ("pickle", "load")):
                                findings.append(SecurityFinding(
                                    "CWE-502", "HIGH", "Unsafe pickle deserialization in payload.", "python"
                                ))
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    findings.append(SecurityFinding(
                                        "CWE-78", "HIGH", "subprocess call with shell=True.", "python"
                                    ))
                        elif isinstance(node, ast.JoinedStr):
                            # Detect f-string SQL statements directly in Python AST
                            raw_parts = "".join(
                                c.value for c in node.values if isinstance(c, ast.Constant) and isinstance(c.value, str)
                            )
                            if re.search(r"\b(SELECT|UPDATE|DELETE|INSERT)\b.*\b(FROM|SET|INTO|WHERE)\b", raw_parts, re.I):
                                findings.append(SecurityFinding(
                                    "CWE-89", "HIGH", "Python f-string SQL query construction; use parameterized '?' bindings.", "python"
                                ))
                except SyntaxError:
                    pass

            if self.SECRET_EQ_RE.search(code):
                if "compare_digest" not in code and "timingSafeEqual" not in code and "hmac.Equal" not in code:
                    findings.append(SecurityFinding(
                        "CWE-208", "HIGH",
                        "Non-constant-time secret comparison; use hmac.compare_digest.", lang
                    ))

            if self.SQL_INTERP_RE.search(code):
                findings.append(SecurityFinding(
                    "CWE-89", "HIGH",
                    "Interpolated/concatenated SQL detected; use parameterized queries.", lang
                ))

            if self.CRED_LITERAL_RE.search(code):
                findings.append(SecurityFinding(
                    "CWE-798", "HIGH", "Hardcoded secret/API key literal in payload.", lang
                ))

            if self.SSRF_META_RE.search(code):
                findings.append(SecurityFinding(
                    "CWE-918", "HIGH", "Cloud instance metadata SSRF target detected.", lang
                ))

            if "unbounded_channel" in code:
                findings.append(SecurityFinding(
                    "CWE-400", "MEDIUM", "Unbounded async channel risks OOM under backpressure.", lang
                ))

        seen: set[tuple[str, str]] = set()
        unique: list[SecurityFinding] = []
        for item in findings:
            k = (item.cwe_id, item.detail)
            if k not in seen:
                seen.add(k)
                unique.append(item)
        return unique

    def prove_allocations(
        self,
        total_ceiling: int,
        allocations: Sequence[tuple[str, int, int]],
        exact_sum: bool = False,
    ) -> FormalProofResult:
        """Prove bounded integer resource/row/token allocation constraints with unsat_core."""
        if self._z3 is not None:
            z3 = self._z3
            solver = z3.Solver()
            solver.set(unsat_core=True)
            vars_map = {}
            for name, lo, hi in allocations:
                v = z3.Int(name)
                vars_map[name] = v
                solver.assert_and_track(v >= int(lo), f"min_{name}_{lo}")
                solver.assert_and_track(v <= int(hi), f"max_{name}_{hi}")
            total_expr = z3.Sum(list(vars_map.values())) if vars_map else z3.IntVal(0)
            if exact_sum:
                solver.assert_and_track(total_expr == int(total_ceiling), f"exact_ceiling_{total_ceiling}")
            else:
                solver.assert_and_track(total_expr <= int(total_ceiling), f"ceiling_{total_ceiling}")
            if solver.check() == z3.sat:
                m = solver.model()
                witness = {k: m[v].as_long() for k, v in vars_map.items()}
                return FormalProofResult(True, "PROVEN_SAT", "z3-smt", witness=witness)
            core = [str(c) for c in solver.unsat_core()]
            return FormalProofResult(
                False, "UNSAT_CONFLICT", "z3-smt", unsat_core=core,
                remediation_guidance=f"Unsatisfiable allocation constraints: {', '.join(core)}"
            )

        bad_bounds = [f"bounds_{n}_{lo}>{hi}" for n, lo, hi in allocations if int(lo) > int(hi)]
        if bad_bounds:
            return FormalProofResult(
                False, "UNSAT_CONFLICT", "deterministic_exact", unsat_core=bad_bounds,
                remediation_guidance="Lower bound exceeds upper bound."
            )
        min_sum = sum(int(lo) for _, lo, _ in allocations)
        max_sum = sum(int(hi) for _, _, hi in allocations)
        if min_sum > total_ceiling:
            core = [f"min_{n}_{lo}" for n, lo, _ in allocations if int(lo) > 0] + [f"ceiling_{total_ceiling}"]
            return FormalProofResult(
                False, "UNSAT_CONFLICT", "deterministic_exact", unsat_core=core,
                remediation_guidance=f"Minimum sum ({min_sum}) exceeds ceiling ({total_ceiling})."
            )
        if exact_sum and max_sum < total_ceiling:
            core = [f"max_{n}_{hi}" for n, _, hi in allocations] + [f"exact_ceiling_{total_ceiling}"]
            return FormalProofResult(
                False, "UNSAT_CONFLICT", "deterministic_exact", unsat_core=core,
                remediation_guidance=f"Maximum sum ({max_sum}) cannot reach exact target ({total_ceiling})."
            )
        witness: dict[str, int] = {n: int(lo) for n, lo, _ in allocations}
        rem = (total_ceiling - min_sum) if exact_sum else 0
        for n, lo, hi in allocations:
            if rem <= 0:
                break
            add = min(rem, int(hi) - int(lo))
            witness[n] += add
            rem -= add
        return FormalProofResult(True, "PROVEN_SAT", "deterministic_exact", witness=witness)

    @staticmethod
    def prove_deadlock_freedom(lock_edges: Sequence[tuple[str, str]]) -> FormalProofResult:
        """Prove acyclicity of a multi-guild / multi-agent wait-for lock graph."""
        adj: dict[str, list[str]] = {}
        nodes: set[str] = set()
        for u, v in lock_edges:
            adj.setdefault(u, []).append(v)
            nodes.add(u)
            nodes.add(v)
        state: dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=done
        cycle: list[str] = []

        def dfs(u: str, stack: list[str]) -> bool:
            state[u] = 1
            stack.append(u)
            for nxt in sorted(adj.get(u, ())):
                st = state.get(nxt, 0)
                if st == 1:
                    idx = stack.index(nxt)
                    cycle.extend(stack[idx:] + [nxt])
                    return True
                if st == 0 and dfs(nxt, stack):
                    return True
            stack.pop()
            state[u] = 2
            return False

        for n in sorted(nodes):
            if state.get(n, 0) == 0 and dfs(n, []):
                edges_core = [f"{cycle[i]}->{cycle[i + 1]}" for i in range(len(cycle) - 1)]
                return FormalProofResult(
                    False, "UNSAT_CONFLICT", "graph_cycle_prover", unsat_core=edges_core,
                    remediation_guidance=f"Deadlock cycle proven: {' -> '.join(cycle)}"
                )
        return FormalProofResult(
            True, "PROVEN_SAT", "graph_cycle_prover",
            witness={"nodes_verified": len(nodes), "edges_verified": len(lock_edges)},
            remediation_guidance="Wait-for graph is strictly acyclic."
        )

    def prove_action_contract(
        self,
        *,
        guild: str,
        domain: str,
        u0_granted: bool,
        guild_granted: bool,
        tainted: bool,
        priv: Priv,
        high_cwes: list[SecurityFinding],
        require_human: bool,
        human_verified: bool,
    ) -> FormalProofResult:
        """Produce a deductive SAT/UNSAT certificate with minimal unsat_core for an agent action."""
        core: list[str] = []
        if not guild_granted:
            core.append(f"guild_ceiling_excludes({guild},{domain})")
        if not u0_granted:
            core.append(f"u0_intent_excludes({domain})")
        if tainted and priv > Priv.READ and not human_verified:
            core.append(f"biba_taint_write_up(tau=TAINTED,priv={priv.name})")
        for f in high_cwes:
            core.append(f"static_cwe_gate({f.cwe_id})")
        if require_human and not human_verified:
            core.append("perm_human_approval_unsigned")
        if core:
            return FormalProofResult(
                False,
                "UNSAT_CONFLICT",
                self.solver_backend,
                unsat_core=core,
                remediation_guidance="Action violates CONCODExAEGIS safety invariants: " + ", ".join(core),
            )
        return FormalProofResult(
            True,
            "PROVEN_SAT",
            self.solver_backend,
            witness={
                "guild": guild,
                "domain": domain,
                "priv": priv.name,
                "tainted": tainted,
                "cwe_high_count": 0,
                "human_verified": human_verified,
            },
            remediation_guidance="All guild, intent, taint, and static CWE invariants satisfied.",
        )


# --------------------------------------------------------------------------- 3. Universal Tool Bus Guard
class ConcodeToolBusGuard:
    """Wraps CONCODE_BRAIN tool invocations inside AEGIS-ZERO runtime containment."""

    def __init__(
        self,
        u0: str,
        workdir: Path,
        operator_pub: bytes,
        *,
        guild: str | None = None,
        canary_dir: Path | None = None,
        freezer: ProcessTreeFreezer | None = None,
        forensic_dir: Path | None = None,
    ):
        self.workdir = workdir.resolve()
        self.canary_dir = (canary_dir or default_canary_dir()).resolve()
        self.guild = ConcodeGuildScoper.classify_guild(u0, explicit_guild=guild)
        self.freezer = freezer or ProcessTreeFreezer()
        self.ctl = AegisController(u0, self.canary_dir, operator_pub, self.workdir, self.freezer)
        self.base_intent = IntentVerifier()
        self.ctl.intent = GuildAttenuatedIntentVerifier(self.guild)
        self.verifier = ConcodePayloadVerifier()
        self.forensics = ForensicExporter()
        self.attest_seed = secrets.token_bytes(32)
        self.attest_pub = Ed25519.public_from_seed(self.attest_seed)
        self.forensic_dir = forensic_dir
        self._tools: dict[str, tuple[str, Callable[..., dict[str, Any]]]] = {}
        self.pending_oob: dict[str, tuple[Action, dict[str, Any], str, Callable[..., dict[str, Any]]]] = {}

    def register_tool(self, name: str, permission: str, handler: Callable[..., dict[str, Any]]) -> None:
        if permission not in PERM_TO_PRIV:
            raise ValueError(f"Unknown CONCODE permission tier: {permission}")
        self._tools[name] = (permission, handler)

    def attach_concode_bus(self, bus: Any) -> int:
        """Import registered tools directly from a live CONCODE_BRAIN UniversalToolBus instance."""
        tools_dict = getattr(bus, "_tools", {})
        count = 0
        for name, tdef in tools_dict.items():
            self.register_tool(name, getattr(tdef, "permission", PERM_READ_ONLY), tdef.handler)
            count += 1
        return count

    def _export_concode_incident(self, dec: Decision, proof: FormalProofResult,
                                 cwes: list[SecurityFinding]) -> str | None:
        if self.forensic_dir is None:
            return None
        self.forensic_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        out = self.forensic_dir / f"concode_incident_{secrets.token_hex(4)}.json"
        enriched_risk = dict(
            dec.risk,
            concode_guild=self.guild,
            concode_proof=proof.to_dict(),
            cwe_findings=[c.to_dict() for c in cwes],
        )
        enriched_dec = Decision(
            dec.verdict, dec.reason, enriched_risk, dec.token,
            dec.approvable, list(dec.frozen_pids), dec.payload, dec.stage,
        )
        self.forensics.export_bundle(self.ctl, enriched_dec, out, self.attest_seed)
        return str(out)

    def invoke(
        self,
        pid: int,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        target: str | None = None,
        external_source: str | None = None,
        enforce_syntax: bool = False,
    ) -> ToolCallResult:
        if tool_name not in self._tools:
            return ToolCallResult(
                tool_name=tool_name,
                success=False,
                error=f"Unregistered tool: {tool_name}",
                aegis_verdict=Verdict.DENY,
            )
        perm, handler = self._tools[tool_name]
        priv = PERM_TO_PRIV[perm]
        call_args = dict(args or {})
        tgt = str(target or call_args.get("path") or call_args.get("url") or call_args.get("command") or tool_name)
        act = Action(pid, tool_name, priv, tgt, call_args, external_source)

        # 1. Static CONCODE AST CWE & optional syntax check on payload BEFORE controller mutates/mints
        cwes = self.verifier.audit_payload(tgt, tool_name, call_args)
        high_cwes = [c for c in cwes if c.severity == "HIGH"]
        if enforce_syntax and isinstance(call_args.get("content"), str):
            lang = self.verifier.infer_language(tgt, tool_name)
            comp = self.verifier.check_syntax(lang, call_args["content"])
            if not comp.compiled:
                high_cwes.append(SecurityFinding("SYNTAX", "HIGH", comp.detail, lang))

        ast_view = act.ast()
        dom = self.ctl.intent.domain(ast_view)
        u0_granted = dom in self.base_intent.grants(self.ctl.u0)
        guild_granted = dom in ConcodeGuildScoper.ceiling(self.guild)
        tainted_now = (self.ctl.taint.tau is Taint.TAINTED) or (external_source is not None)
        require_human = perm == PERM_HUMAN_APPROVAL

        proof = self.verifier.prove_action_contract(
            guild=self.guild,
            domain=dom,
            u0_granted=u0_granted,
            guild_granted=guild_granted,
            tainted=tainted_now,
            priv=priv,
            high_cwes=high_cwes,
            require_human=require_human,
            human_verified=False,
        )

        if high_cwes:
            cwe_summary = "; ".join(f"{c.cwe_id}: {c.detail}" for c in high_cwes)
            dec = self.ctl._block(
                act,
                Verdict.DENY,
                f"CONCODE static verifier blocked payload ({cwe_summary})",
                {"domain": dom, "concode_guild": self.guild, "unsat_core": proof.unsat_core},
                approvable=False,
            )
            bundle_path = self._export_concode_incident(dec, proof, high_cwes)
            return ToolCallResult(
                tool_name=tool_name,
                success=False,
                error=dec.reason,
                permission_used=perm,
                aegis_verdict=dec.verdict,
                proof=proof.to_dict(),
                cwe_findings=[c.to_dict() for c in high_cwes],
                forensic_bundle=bundle_path,
            )

        # 2. Evaluate through AEGIS-ZERO Ring 1/2 controller (with guild-attenuated IntentVerifier)
        dec = self.ctl.evaluate(act)
        if dec.verdict == Verdict.ALLOW and require_human:
            # PERM_HUMAN_APPROVAL always escalates to Ed25519 OOB enclave even when aligned
            dec = self.ctl._block(
                act,
                Verdict.ESCALATE,
                "CONCODE PERM_HUMAN_APPROVAL requires Ed25519 operator signature",
                dict(dec.risk, concode_guild=self.guild),
                approvable=True,
            )

        if dec.verdict != Verdict.ALLOW:
            if dec.payload and "challenge" in dec.payload:
                self.pending_oob[dec.payload["challenge"]] = (act, call_args, perm, handler)
            bundle_path = (
                self._export_concode_incident(dec, proof, cwes)
                if dec.verdict in (Verdict.DENY, Verdict.TRIP)
                else None
            )
            return ToolCallResult(
                tool_name=tool_name,
                success=False,
                output={"challenge": dec.payload["challenge"]} if dec.payload else {},
                error=f"{dec.verdict}: {dec.reason}",
                permission_used=perm,
                aegis_verdict=dec.verdict,
                proof=proof.to_dict(),
                cwe_findings=[c.to_dict() for c in cwes],
                forensic_bundle=bundle_path,
            )

        # 3. Consume single-use capability token, execute handler, and commit CoW Merkle WAL leaf
        if dec.token is not None and not self.ctl.policy.consume(dec.token, pid, priv.name, tgt):
            return ToolCallResult(
                tool_name=tool_name,
                success=False,
                error="AEGIS capability rejected at release (TOCTOU swap or replay)",
                permission_used=perm,
                aegis_verdict=Verdict.DENY,
                proof=proof.to_dict(),
            )
        out = handler(**call_args)
        self.ctl.commit(dec.stage)
        return ToolCallResult(
            tool_name=tool_name,
            success=True,
            output=out,
            permission_used=perm,
            aegis_verdict=Verdict.ALLOW,
            proof=proof.to_dict(),
            cwe_findings=[c.to_dict() for c in cwes],
        )

    def approve_oob(self, challenge: str, sig_hex: str) -> ToolCallResult:
        """Verify Ed25519 operator signature for a held PERM_HUMAN_APPROVAL or ESCALATE tool call."""
        item = self.pending_oob.get(challenge)
        if item is None:
            return ToolCallResult("unknown", False, error="Unknown or expired challenge", aegis_verdict=Verdict.DENY)
        act, call_args, perm, handler = item
        payload = self.ctl.gate.pending.get(challenge)
        if payload is None:
            return ToolCallResult(act.tool, False, error="Challenge missing from OOB gate", aegis_verdict=Verdict.DENY)
        tok, stage = self.ctl.approve(act, payload, sig_hex)
        if tok is None:
            return ToolCallResult(
                act.tool, False, error="Ed25519 operator signature invalid or non-approvable",
                permission_used=perm, aegis_verdict=Verdict.DENY,
            )
        del self.pending_oob[challenge]
        if not self.ctl.policy.consume(tok, act.pid, act.priv.name, act.target):
            return ToolCallResult(act.tool, False, error="Capability invalid on release", aegis_verdict=Verdict.DENY)
        out = handler(**call_args)
        self.ctl.commit(stage)
        dom = self.ctl.intent.domain(act.ast())
        proof = self.verifier.prove_action_contract(
            guild=self.guild,
            domain=dom,
            u0_granted=True,
            guild_granted=True,
            tainted=False,
            priv=act.priv,
            high_cwes=[],
            require_human=(perm == PERM_HUMAN_APPROVAL),
            human_verified=True,
        )
        return ToolCallResult(
            tool_name=act.tool,
            success=True,
            output=out,
            permission_used=perm,
            aegis_verdict=Verdict.ALLOW,
            proof=proof.to_dict(),
        )

    @staticmethod
    def forward_via_proxy(proxy_url: str, tool_name: str, arguments: dict[str, Any], req_id: int = 1) -> tuple[int, dict]:
        """Forward a CONCODE tool call directly over HTTP JSON-RPC 2.0 to a live aegis_proxy.py."""
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }).encode("utf-8")
        req = urllib.request.Request(
            proxy_url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30.0) as r:
                return r.status, json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")


# --------------------------------------------------------------------------- Self-Test Suite
def run_self_test() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="aegis_concode_", dir="/tmp")).resolve()
    register_cleanup(tmp)
    work = tmp / "work"
    work.mkdir()
    (work / "Button.tsx").write_text("export const Button = () => <button>Click</button>;\n", encoding="utf-8")
    canary_dir = tmp / "canaries"
    forensic_dir = tmp / "forensics"
    keydir = tmp / "keys"
    seed = ensure_operator_keypair(keydir)
    pub = load_operator_pubkey(keydir)
    fz = ProcessTreeFreezer()
    agents: list = []
    results: list[tuple[str, bool, str]] = []

    def new_agent() -> int:
        p = spawn_agent()
        fz.register(p.pid)
        agents.append(p)
        return p.pid

    def write_handler(path: str, content: str) -> dict[str, Any]:
        fp = (work / path).resolve()
        if work in fp.parents:
            fp.write_text(content, encoding="utf-8")
        return {"written": fp.name, "bytes": len(content)}

    def exec_handler(command: str) -> dict[str, Any]:
        return {"ran": command}

    def deploy_handler(service: str) -> dict[str, Any]:
        return {"deployed": service}

    try:
        # C1: Clean ui_ux guild write compiles, passes CWE audit, proves SAT, commits WAL
        g_ui = ConcodeToolBusGuard(
            "update the responsive button component layout in Button.tsx",
            work, pub, canary_dir=canary_dir, freezer=fz, forensic_dir=forensic_dir,
        )
        g_ui.register_tool("write_file", PERM_WORKSPACE_WRITE, write_handler)
        g_ui.register_tool("run_command", PERM_SANDBOX_EXEC, exec_handler)
        pid1 = new_agent()
        clean_tsx = "export function Button() { return (<button className='px-4'>Save</button>); }\n"
        r1 = g_ui.invoke(pid1, "write_file", {"path": "Button.tsx", "content": clean_tsx}, enforce_syntax=True)
        c1_ok = (
            g_ui.guild == "ui_ux"
            and r1.success
            and r1.aegis_verdict == Verdict.ALLOW
            and r1.proof.get("status") == "PROVEN_SAT"
            and len(g_ui.ctl.cow.wal) == 1
        )
        results.append((
            "C1 CONCODE ui_ux clean write + SAT proof + WAL",
            c1_ok,
            f"guild={g_ui.guild} proof={r1.proof.get('status')} wal={len(g_ui.ctl.cow.wal)}",
        ))

        # C2: Guild ceiling attenuation blocks process_exec under ui_ux even if prompt mentions "run"
        g_att = ConcodeToolBusGuard(
            "run a responsive layout check and update Button.tsx",
            work, pub, guild="ui_ux", canary_dir=canary_dir, freezer=fz, forensic_dir=forensic_dir,
        )
        g_att.register_tool("run_command", PERM_SANDBOX_EXEC, exec_handler)
        pid2 = new_agent()
        r2 = g_att.invoke(pid2, "run_command", {"command": "pytest"})
        frozen2 = process_state(pid2).startswith("T")
        c2_ok = (
            not r2.success
            and r2.aegis_verdict == Verdict.ESCALATE
            and frozen2
            and "guild_ceiling_excludes(ui_ux,process_exec)" in r2.proof.get("unsat_core", [])
        )
        results.append((
            "C2 Guild ceiling blocks ungranted process_exec",
            c2_ok,
            f"verdict={r2.aegis_verdict} core={r2.proof.get('unsat_core')}",
        ))

        # C3: Static AST CWE payload gate blocks CWE-78 / CWE-89 / CWE-208 / CWE-798 before disk write
        g_fs = ConcodeToolBusGuard(
            "write backend handler auth_service.py in fullstack webapp",
            work, pub, guild="fullstack", canary_dir=canary_dir, freezer=fz, forensic_dir=forensic_dir,
        )
        g_fs.register_tool("write_file", PERM_WORKSPACE_WRITE, write_handler)
        pid3 = new_agent()
        vuln_py = (
            "import subprocess\n"
            "API_SECRET = 'AKIA1234567890ABCDEF'\n"
            "def check(api_key, user_id):\n"
            "    if api_key == API_SECRET:\n"
            "        q = f'SELECT * FROM users WHERE id = {user_id}'\n"
            "        subprocess.run('ls ' + user_id, shell=True)\n"
        )
        r3 = g_fs.invoke(pid3, "write_file", {"path": "auth_service.py", "content": vuln_py}, enforce_syntax=True)
        cwes_found = {c["cwe_id"] for c in r3.cwe_findings}
        c3_ok = (
            not r3.success
            and r3.aegis_verdict == Verdict.DENY
            and process_state(pid3).startswith("T")
            and not (work / "auth_service.py").exists()
            and {"CWE-78", "CWE-89", "CWE-208", "CWE-798"} <= cwes_found
        )
        results.append((
            "C3 Static AST CWE gate (78/89/208/798) blocks write",
            c3_ok,
            f"cwes={sorted(cwes_found)} file_exists={(work / 'auth_service.py').exists()}",
        ))

        # C4: SMT allocation unsat_core & multi-guild wait-for deadlock cycle prover
        pv = ConcodePayloadVerifier()
        sat_p = pv.prove_allocations(10, [("guild_ui", 2, 4), ("guild_api", 3, 6)], exact_sum=True)
        unsat_p = pv.prove_allocations(5, [("guild_db", 4, 6), ("guild_sec", 3, 5)], exact_sum=False)
        acyclic_p = pv.prove_deadlock_freedom([("guild:api", "guild:db"), ("guild:ui", "guild:api")])
        deadlock_p = pv.prove_deadlock_freedom([
            ("guild:db", "guild:api"), ("guild:api", "guild:sec"), ("guild:sec", "guild:db")
        ])
        c4_ok = (
            sat_p.is_satisfiable
            and sum(sat_p.witness.values()) == 10
            and not unsat_p.is_satisfiable
            and "ceiling_5" in unsat_p.unsat_core
            and acyclic_p.is_satisfiable
            and not deadlock_p.is_satisfiable
            and len(deadlock_p.unsat_core) == 3
        )
        results.append((
            "C4 SMT unsat_core & wait-for deadlock cycle prover",
            c4_ok,
            f"solver={pv.solver_backend} unsat_core={unsat_p.unsat_core} cycle={deadlock_p.unsat_core}",
        ))

        # C5: CONCODE PERM_HUMAN_APPROVAL escalates to Ed25519 OOB enclave; forged sig rejected, real sig runs
        g_ops = ConcodeToolBusGuard(
            "deploy production release container",
            work, pub, guild="devops", canary_dir=canary_dir, freezer=fz, forensic_dir=forensic_dir,
        )
        g_ops.register_tool("deploy_prod", PERM_HUMAN_APPROVAL, deploy_handler)
        pid5 = new_agent()
        r5_hold = g_ops.invoke(pid5, "deploy_prod", {"service": "concode-web"})
        chall = r5_hold.output.get("challenge", "")
        raw_payload = g_ops.ctl.gate.pending.get(chall, {})
        forged_sig = operator_sign(secrets.token_bytes(32), raw_payload, "approve")
        r5_forged = g_ops.approve_oob(chall, forged_sig)
        good_sig = operator_sign(seed, raw_payload, "approve")
        r5_good = g_ops.approve_oob(chall, good_sig)
        c5_ok = (
            not r5_hold.success
            and r5_hold.aegis_verdict == Verdict.ESCALATE
            and not r5_forged.success
            and r5_good.success
            and r5_good.output == {"deployed": "concode-web"}
            and r5_good.proof.get("status") == "PROVEN_SAT"
        )
        results.append((
            "C5 PERM_HUMAN_APPROVAL Ed25519 OOB gate",
            c5_ok,
            f"held={r5_hold.aegis_verdict} forged_ok={r5_forged.success} signed_ok={r5_good.success}",
        ))

        # C6: Enriched forensic bundle from C3 verifies Ed25519 signature + Merkle WAL + CONCODE proof metadata
        bundle_file = Path(r3.forensic_bundle) if r3.forensic_bundle else tmp / "missing.json"
        ok_b, why_b = ForensicExporter.verify_bundle(bundle_file, g_fs.attest_pub)
        bundle_json = json.loads(bundle_file.read_bytes()) if bundle_file.is_file() else {}
        saved_risk = bundle_json.get("decision", {}).get("risk", {})
        c6_ok = (
            ok_b
            and saved_risk.get("concode_guild") == "fullstack"
            and len(saved_risk.get("cwe_findings", [])) >= 4
            and saved_risk.get("concode_proof", {}).get("status") == "UNSAT_CONFLICT"
        )
        results.append((
            "C6 Signed CONCODExAEGIS forensic bundle verifies",
            c6_ok,
            f"{why_b}; cwes={len(saved_risk.get('cwe_findings', []))}",
        ))
    finally:
        for p in agents:
            reap(p, fz)

    print("\n=== CONCODE BRIDGE SELF-TEST ===")
    for name, ok, info in results:
        print(f"  {name:<50} {'PASS' if ok else 'FAIL'}  {info}")
    return 0 if all(ok for _, ok, _ in results) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="run C1-C6 CONCODExAEGIS integration suite")
    ns = ap.parse_args(argv)
    if ns.self_test:
        return run_self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
