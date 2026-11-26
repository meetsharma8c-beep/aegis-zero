#!/usr/bin/env python3
"""AEGIS-ZERO Phase 7: Non-Euclidean & Topological Security Engine.

Implements four stdlib-only (`math`, `cmath`, `hashlib`) geometric and
cohomological containment primitives fused into Ring 1 / Ring 2 telemetry:

  1. PoincarePrivilegeManifold  -- Open Poincare ball B^n_c with Mobius addition
                                   and hyperbolic geodesic privilege scaling.
  2. CellularSheafObserver      -- Cellular sheaf over interaction graphs with
                                   Sheaf Laplacian Dirichlet energy E_sheaf(s).
  3. TropicalGeodesicEngine     -- Min-plus tropical semiring W^(x)k horizon
                                   preemptive exploit-path detector.
  4. PAdicUltrametricGuard      -- Non-Archimedean p-adic ultrametric d_p(x, y)
                                   clopen ball isolation over namespace tries.

Usage:
  python3 -B aegis_hypermath.py --self-test
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import cmath
import hashlib
import math


# --------------------------------------------------------------------------- 1. Poincare Ball
class PoincarePrivilegeManifold:
    """Open Poincare ball B^n_c = {x in R^n : c * ||x||^2 < 1}.

    Privilege tiers scale radial placement r in [0.05, 0.98] monotonically as a
    fraction of the ideal boundary radius 1/sqrt(c): low-privilege READ actions
    sit near the origin while WRITE / EXEC / CREDENTIAL actions approach the
    hyperbolic boundary where geodesic distances diverge exponentially.
    """

    TIER_RADIUS: dict[str, float] = {
        "ORIGIN": 0.05,
        "ROOT_INTENT": 0.05,
        "READ": 0.12,
        "file_read": 0.12,
        "db_read": 0.14,
        "TRANSFORM": 0.28,
        "data_transform": 0.28,
        "AGENT_MSG": 0.45,
        "agent_message": 0.45,
        "WRITE": 0.68,
        "file_write": 0.68,
        "db_write": 0.72,
        "DELETE": 0.80,
        "file_delete": 0.80,
        "NET": 0.88,
        "network_egress": 0.88,
        "EXEC": 0.93,
        "process_exec": 0.93,
        "CREDENTIAL": 0.98,
        "credential_access": 0.98,
        "CANARY": 0.98,
    }

    def __init__(self, curvature: float = 1.0, dim: int = 16):
        if curvature <= 0.0:
            raise ValueError("Poincare curvature c must be > 0")
        if dim < 2:
            raise ValueError("Poincare manifold dimension must be >= 2")
        self.c = float(curvature)
        self.dim = int(dim)
        self._boundary = 1.0 / math.sqrt(self.c)

    @staticmethod
    def _tokenize(features: str | dict | list | tuple) -> list[str]:
        if isinstance(features, dict):
            raw = " ".join(f"{k} {v}" for k, v in sorted(features.items()))
        elif isinstance(features, (list, tuple)):
            raw = " ".join(str(x) for x in features)
        else:
            raw = str(features)
        buf, cur = [], []
        for ch in raw.lower():
            if ch.isalnum():
                cur.append(ch)
            elif cur:
                buf.append("".join(cur))
                cur = []
        if cur:
            buf.append("".join(cur))
        grams = list(buf)
        for tok in buf:
            if len(tok) >= 4:
                grams.extend(tok[i:i + 3] for i in range(len(tok) - 2))
        return grams or ["_empty_"]

    def tier_radius(self, tier: str) -> float:
        r = self.TIER_RADIUS.get(tier, 0.85)
        return max(0.05, min(0.98, r))

    def _project_inside(self, x: list[float]) -> list[float]:
        norm_sq = sum(v * v for v in x)
        max_norm = (1.0 - 1e-12) * self._boundary
        if self.c * norm_sq >= (1.0 - 1e-12) ** 2:
            scale = max_norm / max(math.sqrt(norm_sq), 1e-30)
            return [v * scale for v in x]
        return x

    def embed(self, features: str | dict | list | tuple, tier: str = "READ") -> list[float]:
        """Project hashed text/AST features onto S^(dim-1) via complex phase rotors and scale to radius r/sqrt(c)."""
        tokens = self._tokenize(features)
        acc = [0.0] * self.dim
        pairs = self.dim // 2
        for tok in tokens:
            digest = hashlib.sha256(tok.encode("utf-8")).digest()
            for p in range(pairs):
                off = (2 * p) % (len(digest) - 1)
                word = (digest[off] << 8) | digest[off + 1]
                angle = (2.0 * math.pi * word) / 65536.0
                rotor = cmath.rect(1.0, angle)
                acc[2 * p] += rotor.real
                acc[2 * p + 1] += rotor.imag
            if self.dim % 2 == 1:
                acc[-1] += 1.0 if (digest[-1] & 1) == 0 else -1.0
        norm = math.sqrt(sum(v * v for v in acc))
        if norm < 1e-12:
            unit = [1.0] + [0.0] * (self.dim - 1)
        else:
            unit = [v / norm for v in acc]
        r = self.tier_radius(tier)
        radial = r * self._boundary
        return self._project_inside([u * radial for u in unit])

    def mobius_add(self, u: list[float], v: list[float]) -> list[float]:
        """Exact Mobius addition u (+)_c v on the open Poincare ball B^n_c."""
        if len(u) != self.dim or len(v) != self.dim:
            raise ValueError(f"vectors must have dimension {self.dim}")
        c = self.c
        uv = sum(a * b for a, b in zip(u, v))
        uu = sum(a * a for a in u)
        vv = sum(b * b for b in v)
        denom = 1.0 + 2.0 * c * uv + (c * c) * uu * vv
        if abs(denom) < 1e-15:
            denom = 1e-15
        coef_u = (1.0 + 2.0 * c * uv + c * vv) / denom
        coef_v = (1.0 - c * uu) / denom
        return self._project_inside([coef_u * a + coef_v * b for a, b in zip(u, v)])

    def geodesic_distance(self, u: list[float], v: list[float]) -> float:
        """Exact hyperbolic geodesic distance d_B(u, v) = (2/sqrt(c)) * arctanh(sqrt(c) * ||(-u) (+)_c v||)."""
        neg_u = [-a for a in u]
        diff = self.mobius_add(neg_u, v)
        norm_diff = math.sqrt(sum(x * x for x in diff))
        arg = min(1.0 - 1e-15, max(0.0, math.sqrt(self.c) * norm_diff))
        return (2.0 / math.sqrt(self.c)) * math.atanh(arg)

    def normalized_distance(self, u: list[float], v: list[float]) -> float:
        """Squashes d_B(u, v) via tanh(d_B / 4) into [0, 1)."""
        return math.tanh(self.geodesic_distance(u, v) / 4.0)


# --------------------------------------------------------------------------- 2. Cellular Sheaf
class CellularSheafObserver:
    """Cellular sheaf (G, F) over execution steps or multi-agent interaction edges.

    Each vertex u carries a stalk vector s_u in R^(d_u); each directed edge
    e = (u, v) carries linear restriction maps F_{u <= e} in R^(d_e x d_u) and
    F_{v <= e} in R^(d_e x d_v). Discrepancy along e is the coboundary component
    (delta s)_e = F_{u <= e}(s_u) - F_{v <= e}(s_v), and the Sheaf Laplacian
    Dirichlet energy is:

        E_sheaf(s) = ||delta s||_2^2 = s^T L_F s = sum_e ||F_{u<=e}(s_u) - F_{v<=e}(s_v)||_2^2

    Non-vanishing energy over a pinned boundary or cycle witnesses a semantic or
    provenance contradiction (H^1(G, F) != 0).
    """

    STALK_DIM = 6
    PROVENANCE_MAP: list[list[float]] = [
        [1.0, 0.0, 0.0, 0.0, 0.0, 0.0],  # taint indicator
        [0.0, 1.0, 0.0, 0.0, 0.0, 0.0],  # sensitive-data touch indicator
        [0.0, 0.0, 1.0, 0.0, 0.0, 0.0],  # state-mutation indicator
        [0.0, 0.0, 0.0, 1.0, 0.0, 0.0],  # external-egress indicator
    ]
    IDENTITY_MAP: list[list[float]] = [
        [1.0 if i == j else 0.0 for j in range(6)] for i in range(6)
    ]

    def __init__(self, max_edges: int = 32):
        self.max_edges = int(max_edges)
        self.stalks: dict[str, list[float]] = {}
        self.edges: list[tuple[str, str, list[list[float]], list[list[float]]]] = []
        self._step = 0

    def reset(self) -> None:
        self.stalks.clear()
        self.edges.clear()
        self._step = 0

    @staticmethod
    def topic_rotor(topic: str) -> complex:
        if not topic:
            return complex(1.0, 0.0)
        digest = hashlib.sha256(topic.strip().lower().encode("utf-8")).digest()
        word = int.from_bytes(digest[:4], "big")
        angle = (2.0 * math.pi * word) / float(1 << 32)
        return cmath.exp(1j * angle)

    @classmethod
    def make_stalk(cls, *, tainted: float = 0.0, sensitive: float = 0.0, mutating: float = 0.0,
                   egress: float = 0.0, topic: str = "") -> list[float]:
        z = cls.topic_rotor(topic)
        return [float(tainted), float(sensitive), float(mutating), float(egress), z.real, z.imag]

    @staticmethod
    def project(matrix: list[list[float]], vec: list[float]) -> list[float]:
        return [sum(row[j] * vec[j] for j in range(len(vec))) for row in matrix]

    def set_stalk(self, node: str, vec: list[float]) -> None:
        self.stalks[node] = [float(x) for x in vec]

    def add_edge(self, u: str, v: str, f_u: list[list[float]], f_v: list[list[float]]) -> None:
        if len(f_u) != len(f_v):
            raise ValueError("restriction maps on an edge must share target edge-stalk dimension")
        self.edges.append((u, v, f_u, f_v))
        if len(self.edges) > self.max_edges:
            self.edges.pop(0)

    def edge_discrepancy(self, u: str, v: str, f_u: list[list[float]], f_v: list[list[float]]) -> list[float]:
        su = self.stalks[u]
        sv = self.stalks[v]
        pu = self.project(f_u, su)
        pv = self.project(f_v, sv)
        return [a - b for a, b in zip(pu, pv)]

    def dirichlet_energy(self) -> float:
        """Compute exact Sheaf Laplacian Dirichlet energy sum_e ||F_{u<=e}(s_u) - F_{v<=e}(s_v)||_2^2."""
        total = 0.0
        for u, v, f_u, f_v in self.edges:
            if u in self.stalks and v in self.stalks:
                diff = self.edge_discrepancy(u, v, f_u, f_v)
                total += sum(d * d for d in diff)
        return total

    def laplacian_quadratic_form(self) -> float:
        """Assemble explicit Sheaf Laplacian L_F = delta^T delta and evaluate s^T L_F s."""
        active_nodes = []
        seen = set()
        for u, v, _, _ in self.edges:
            if u in self.stalks and v in self.stalks:
                if u not in seen:
                    seen.add(u)
                    active_nodes.append(u)
                if v not in seen:
                    seen.add(v)
                    active_nodes.append(v)
        if not active_nodes:
            return 0.0
        offsets: dict[str, int] = {}
        flat_s: list[float] = []
        for node in active_nodes:
            offsets[node] = len(flat_s)
            flat_s.extend(self.stalks[node])
        n_total = len(flat_s)
        lap = [[0.0] * n_total for _ in range(n_total)]
        for u, v, f_u, f_v in self.edges:
            if u not in offsets or v not in offsets:
                continue
            ou, ov = offsets[u], offsets[v]
            du, dv, de = len(self.stalks[u]), len(self.stalks[v]), len(f_u)
            for k in range(de):
                for i in range(du):
                    for j in range(du):
                        lap[ou + i][ou + j] += f_u[k][i] * f_u[k][j]
                    for j in range(dv):
                        val = f_u[k][i] * f_v[k][j]
                        lap[ou + i][ov + j] -= val
                        lap[ov + j][ou + i] -= val
                for i in range(dv):
                    for j in range(dv):
                        lap[ov + i][ov + j] += f_v[k][i] * f_v[k][j]
        return sum(flat_s[i] * sum(lap[i][j] * flat_s[j] for j in range(n_total)) for i in range(n_total))

    def has_cohomological_obstruction(self, tol: float = 1e-6) -> bool:
        return self.dirichlet_energy() > tol

    def observe_step(self, *, granted: bool, taint_violation: bool, sensitive: bool,
                     egress: bool, stego: bool) -> float:
        """Update rolling intent-vs-execution sheaf for single-controller action evaluation."""
        if "intent_anchor" not in self.stalks:
            self.set_stalk("intent_anchor", [0.0, 0.0, 0.0, 0.0, 1.0, 0.0])
        self._step += 1
        node = f"step_{self._step}"
        # Stalk captures contract-violating components so aligned operations sit in ker(delta)
        unauth_cap = 0.0 if granted else 1.0
        taint_leak = 1.0 if taint_violation else 0.0
        sens_egress = 1.0 if (sensitive and egress) else 0.0
        covert = 1.0 if stego else 0.0
        phase = cmath.exp(1j * (0.0 if granted and not stego else math.pi / 2.0))
        self.set_stalk(node, [taint_leak, sens_egress, unauth_cap, covert, phase.real, phase.imag])
        # Keep rolling window compact (anchor -> latest 4 steps)
        self.edges = [e for e in self.edges if e[1] in self.stalks][-3:]
        self.add_edge("intent_anchor", node, self.PROVENANCE_MAP, self.PROVENANCE_MAP)
        return self.dirichlet_energy()


# --------------------------------------------------------------------------- 3. Tropical Semiring
class TropicalGeodesicEngine:
    """Tropical min-plus semiring (R u {+inf}, min, +) over the Causal Execution Graph.

    Computes W^(x)k via (A (x) B)_{ij} = min_m (A_{im} + B_{mj}). Because W_{ii} = 0,
    (W^(x)k)_{ij} equals the exact minimum tropical path weight from state i to
    state j in at most k transitions, enabling preemptive detection of staged
    attack chains (e.g. READ_SENSITIVE -> TRANSFORM) before NET_OUT executes.
    """

    STATES: tuple[str, ...] = (
        "START",
        "READ",
        "WRITE",
        "DELETE",
        "EXEC",
        "READ_SENSITIVE",
        "TRANSFORM",
        "WRITE_TMP",
        "NET_OUT",
        "CANARY_SINK",
    )
    INDEX: dict[str, int] = {name: idx for idx, name in enumerate(STATES)}
    SINKS: tuple[str, ...] = ("NET_OUT", "CANARY_SINK")

    def __init__(self, k_horizon: int = 3, alert_threshold: float = 0.80):
        if k_horizon < 1:
            raise ValueError("k_horizon must be >= 1")
        self.k_horizon = int(k_horizon)
        self.alert_threshold = float(alert_threshold)
        self.sensitive_loaded = False
        self.current_state = "START"

    def reset(self) -> None:
        self.sensitive_loaded = False
        self.current_state = "START"

    def transition_matrix(self) -> list[list[float]]:
        n = len(self.STATES)
        inf = math.inf
        w = [[0.0 if i == j else inf for j in range(n)] for i in range(n)]

        def edge(src: str, dst: str, cost: float) -> None:
            i, j = self.INDEX[src], self.INDEX[dst]
            if cost < w[i][j]:
                w[i][j] = cost

        benign = ("START", "READ", "WRITE", "DELETE", "EXEC")
        for s in benign:
            for d in benign:
                if s != d:
                    edge(s, d, 0.50)
            edge(s, "READ_SENSITIVE", 1.20)
            edge(s, "TRANSFORM", 1.10)
            edge(s, "WRITE_TMP", 1.20)
            edge(s, "NET_OUT", 2.40)
            edge(s, "CANARY_SINK", 2.80)

        # Exfiltration & canary staging spine
        edge("READ_SENSITIVE", "TRANSFORM", 0.35)
        edge("READ_SENSITIVE", "WRITE_TMP", 0.55)
        edge("READ_SENSITIVE", "NET_OUT", 0.95)
        edge("READ_SENSITIVE", "CANARY_SINK", 0.90)
        edge("READ_SENSITIVE", "READ", 0.60)

        if self.sensitive_loaded:
            # Sensitive payload is resident in agent context: staging hops to sink are armed
            edge("TRANSFORM", "WRITE_TMP", 0.20)
            edge("TRANSFORM", "NET_OUT", 0.50)
            edge("WRITE_TMP", "NET_OUT", 0.15)
            edge("TRANSFORM", "CANARY_SINK", 0.70)
        else:
            edge("TRANSFORM", "WRITE_TMP", 0.55)
            edge("TRANSFORM", "NET_OUT", 1.10)
            edge("WRITE_TMP", "NET_OUT", 0.85)
            edge("TRANSFORM", "CANARY_SINK", 1.60)
            edge("TRANSFORM", "READ", 0.50)
            edge("TRANSFORM", "WRITE", 0.55)

        return w

    @staticmethod
    def tropical_matmul(a: list[list[float]], b: list[list[float]]) -> list[list[float]]:
        """Exact min-plus matrix product (A (x) B)_{ij} = min_m (A_{im} + B_{mj})."""
        n = len(a)
        m_dim = len(b)
        p_dim = len(b[0])
        out = [[math.inf] * p_dim for _ in range(n)]
        for i in range(n):
            row_a = a[i]
            out_i = out[i]
            for m in range(m_dim):
                aim = row_a[m]
                if aim == math.inf:
                    continue
                row_b = b[m]
                for j in range(p_dim):
                    cand = aim + row_b[j]
                    if cand < out_i[j]:
                        out_i[j] = cand
        return out

    def tropical_power(self, w: list[list[float]], k: int | None = None) -> list[list[float]]:
        steps = self.k_horizon if k is None else int(k)
        if steps < 1:
            raise ValueError("tropical power k must be >= 1")
        acc = [row[:] for row in w]
        for _ in range(steps - 1):
            acc = self.tropical_matmul(acc, w)
        return acc

    def step(self, category: str) -> tuple[float, float, bool]:
        """Advance state to `category` and return (min_sink_cost, proximity_score, preemptive_alert)."""
        state = category if category in self.INDEX else "EXEC"
        if state == "READ_SENSITIVE":
            self.sensitive_loaded = True
        self.current_state = state
        w = self.transition_matrix()
        wk = self.tropical_power(w, self.k_horizon)
        src_idx = self.INDEX[state]
        min_cost = min(wk[src_idx][self.INDEX[sink]] for sink in self.SINKS)
        proximity = 0.0 if min_cost == math.inf else math.exp(-min_cost)
        alert = min_cost < self.alert_threshold
        return min_cost, proximity, alert


# --------------------------------------------------------------------------- 4. p-Adic Ultrametric
class PAdicUltrametricGuard:
    """Non-Archimedean p-adic ultrametric d_p(x, y) = p^(-v_p(x, y)) over namespace tries.

    Every path/URI is canonicalized into rooted namespace segments. For two distinct
    paths x, y, the valuation v_p(x, y) >= 0 is the exact depth of their lowest
    common ancestor in the trie (and +inf when x == y, giving d_p = 0). Because
    v_p(x, z) >= min(v_p(x, y), v_p(y, z)), d_p satisfies the Strong Triangle
    Inequality d_p(x, z) <= max(d_p(x, y), d_p(y, z)), partitioning workspace,
    canary, and OS root hierarchies into mutually disjoint clopen balls.
    """

    MACOS_PRIVATE_ROOTS = {"tmp", "etc", "var"}

    def __init__(self, prime: int = 7, workdir: object = None,
                 canary_dir: object = None):
        if prime < 2 or not self._is_prime(prime):
            raise ValueError(f"prime must be a prime integer >= 2, got {prime}")
        self.p = int(prime)
        self.workdir_segs = self._fs_segments(str(workdir) if workdir is not None else "/workspace", base=None)
        self.canary_segs = (
            self._fs_segments(str(canary_dir), base=None)
            if canary_dir is not None
            else ("@fs", "tmp", "aegis_canaries")
        )
        self.workspace_radius = float(self.p) ** (-len(self.workdir_segs))
        self.canary_radius = float(self.p) ** (-len(self.canary_segs))

    @staticmethod
    def _is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2
        d = 3
        while d * d <= n:
            if n % d == 0:
                return False
            d += 2
        return True

    @classmethod
    def _fs_segments(cls, raw_path: str, base: tuple[str, ...] | None) -> tuple[str, ...]:
        raw = raw_path.replace("\\", "/").strip()
        if raw.startswith("/"):
            stack: list[str] = []
        elif base is not None:
            stack = list(base[1:])
        else:
            stack = ["workspace"]
        for part in raw.split("/"):
            if not part or part == ".":
                continue
            if part == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(part)
        # Canonicalize macOS /private/{tmp,etc,var} firmlinks to /{tmp,etc,var}
        if len(stack) >= 2 and stack[0] == "private" and stack[1] in cls.MACOS_PRIVATE_ROOTS:
            stack = stack[1:]
        return ("@fs", *stack)

    def canonical_segments(self, target: object) -> tuple[str, ...]:
        s = str(target).strip()
        if "://" in s:
            scheme, rest = s.split("://", 1)
            parts = [p for p in rest.split("/") if p and p != "."]
            return (f"@ns:{scheme.lower()}", *parts)
        if s.startswith("db:"):
            return ("@ns:db", s[3:] or "*")
        return self._fs_segments(s, base=self.workdir_segs)

    def padic_code(self, target: object, digits: int = 8) -> int:
        """Encode canonical trie path as a truncated p-adic integer sum_{k=0}^{digits-1} a_k * p^k."""
        segs = self.canonical_segments(target)
        val = 0
        p_pow = 1
        for k in range(digits):
            if k < len(segs):
                h = hashlib.sha256(f"{k}:{segs[k]}".encode("utf-8")).digest()
                digit = 1 + (int.from_bytes(h[:4], "big") % (self.p - 1)) if self.p > 2 else 1
            else:
                digit = 0
            val += digit * p_pow
            p_pow *= self.p
        return val

    def valuation(self, x: object, y: object) -> int | None:
        """Return v_p(x, y) (LCA trie depth), or None (+infinity) when canonical paths coincide."""
        sx = self.canonical_segments(x)
        sy = self.canonical_segments(y)
        if sx == sy:
            return None
        common = 0
        for a, b in zip(sx, sy):
            if a != b:
                break
            common += 1
        return common

    def distance(self, x: object, y: object) -> float:
        """Compute non-Archimedean p-adic ultrametric d_p(x, y) = p^(-v_p(x, y))."""
        v = self.valuation(x, y)
        return 0.0 if v is None else float(self.p) ** (-v)

    def workspace_distance(self, target: object) -> float:
        sx = self.canonical_segments(target)
        sw = self.workdir_segs
        if sx == sw:
            return 0.0
        common = 0
        for a, b in zip(sx, sw):
            if a != b:
                break
            common += 1
        return float(self.p) ** (-common)

    def in_workspace_ball(self, target: object) -> bool:
        return self.workspace_distance(target) <= self.workspace_radius + 1e-18

    def in_canary_ball(self, target: object) -> bool:
        sx = self.canonical_segments(target)
        sc = self.canary_segs
        common = 0
        for a, b in zip(sx, sc):
            if a != b:
                break
            common += 1
        dist = 0.0 if sx == sc else float(self.p) ** (-common)
        return dist <= self.canary_radius + 1e-18

    def verify_strong_triangle(self, x: object, y: object, z: object) -> bool:
        d_xy = self.distance(x, y)
        d_yz = self.distance(y, z)
        d_xz = self.distance(x, z)
        eps = 1e-15
        return (
            d_xz <= max(d_xy, d_yz) + eps
            and d_xy <= max(d_xz, d_yz) + eps
            and d_yz <= max(d_xy, d_xz) + eps
        )


# --------------------------------------------------------------------------- Unified Fusion Engine
class HyperMathEngine:
    """Fuses all four Phase 7 non-Euclidean & topological telemetry signals for AegisController."""

    def __init__(self, u0: str, workdir: object = None,
                 canary_dir: object = None, curvature: float = 1.0,
                 dim: int = 16, k_horizon: int = 3, prime: int = 7):
        self.u0 = u0
        self.poincare = PoincarePrivilegeManifold(curvature=curvature, dim=dim)
        self.sheaf = CellularSheafObserver()
        self.tropical = TropicalGeodesicEngine(k_horizon=k_horizon)
        self.padic = PAdicUltrametricGuard(prime=prime, workdir=workdir, canary_dir=canary_dir)
        self._u0_origin = self.poincare.embed(u0, tier="ORIGIN")

    def reset_drift(self) -> None:
        self.sheaf.reset()
        self.tropical.reset()

    def observe(self, ast: dict, target: str, *, dom: str, category: str,
                granted: bool, taint_violation: bool, stego: bool = False) -> dict[str, float]:
        # 1. Poincare normalized geodesic distance from U0 anchor to action embedding
        anchor = self.poincare.embed(self.u0, tier=dom) if granted else self._u0_origin
        act_vec = self.poincare.embed(ast, tier=dom)
        d_poincare = self.poincare.normalized_distance(anchor, act_vec)

        # 2. Cellular Sheaf Dirichlet energy over rolling intent-action restriction maps
        sheaf_energy = self.sheaf.observe_step(
            granted=granted,
            taint_violation=taint_violation,
            sensitive=(category == "READ_SENSITIVE" or dom == "credential_access"),
            egress=(category == "NET_OUT" or dom == "network_egress"),
            stego=stego,
        )

        # 3. Tropical min-plus W^(x)k geodesic cost to {NET_OUT, CANARY_SINK}
        trop_cost, _, _ = self.tropical.step(category)

        # 4. p-adic ultrametric distance from workspace clopen ball center
        padic_dist = self.padic.workspace_distance(target)

        return {
            "d_poincare": round(d_poincare, 4),
            "sheaf_energy": round(sheaf_energy, 4),
            "tropical_cost": round(trop_cost, 4),
            "padic_dist": round(padic_dist, 6),
        }


# --------------------------------------------------------------------------- Self-Test Suite
def run_self_test() -> int:
    results: list[tuple[str, bool, str]] = []

    # (a) Poincare geodesic distance diverges monotonically/exponentially toward credential_access
    pm = PoincarePrivilegeManifold(curvature=1.0, dim=16)
    origin_u0 = pm.embed("read summary of report.md", tier="ORIGIN")
    tiers = ["READ", "TRANSFORM", "WRITE", "NET", "EXEC", "CREDENTIAL"]
    geodesics = [pm.geodesic_distance(origin_u0, pm.embed(f"probe_{t}", tier=t)) for t in tiers]
    norms = [pm.normalized_distance(origin_u0, pm.embed(f"probe_{t}", tier=t)) for t in tiers]
    zero_self = pm.geodesic_distance(origin_u0, origin_u0)
    monotonic = all(geodesics[i] < geodesics[i + 1] for i in range(len(geodesics) - 1))
    # Boundary divergence: CREDENTIAL geodesic > 4x READ geodesic and normalized in (0.75, 1.0)
    exp_diverge = (
        abs(zero_self) < 1e-12
        and monotonic
        and geodesics[-1] > 4.0 * geodesics[0]
        and geodesics[-1] > 4.0
        and all(0.0 <= x < 1.0 for x in norms)
        and norms[-1] > 0.75
    )
    results.append((
        "H1 Poincare geodesic boundary divergence",
        exp_diverge,
        "d_B=" + ",".join(f"{g:.2f}" for g in geodesics) + f" norm_cred={norms[-1]:.3f}",
    ))

    # (b) Cellular Sheaf Dirichlet energy ~ 0 on consistent traces, > 0.5 on contradictory claims
    sheaf_ok = CellularSheafObserver()
    s_clean = CellularSheafObserver.make_stalk(
        tainted=0.0, sensitive=0.0, mutating=0.0, egress=0.0, topic="q3_revenue"
    )
    for node in ("u0", "agent_a_trace", "agent_a_msg", "agent_b_exec"):
        sheaf_ok.set_stalk(node, s_clean)
    id6 = CellularSheafObserver.IDENTITY_MAP
    sheaf_ok.add_edge("u0", "agent_a_trace", id6, id6)
    sheaf_ok.add_edge("agent_a_trace", "agent_a_msg", id6, id6)
    sheaf_ok.add_edge("agent_a_msg", "agent_b_exec", id6, id6)
    sheaf_ok.add_edge("u0", "agent_b_exec", id6, id6)
    e_clean = sheaf_ok.dirichlet_energy()
    q_clean = sheaf_ok.laplacian_quadratic_form()

    sheaf_bad = CellularSheafObserver()
    p4 = CellularSheafObserver.PROVENANCE_MAP
    sheaf_bad.set_stalk("u0", CellularSheafObserver.make_stalk(tainted=0.0, sensitive=0.0, egress=0.0, topic="q3"))
    sheaf_bad.set_stalk("agent_a_trace", CellularSheafObserver.make_stalk(tainted=1.0, sensitive=1.0, egress=0.0, topic="q3"))
    sheaf_bad.set_stalk("agent_a_claim", CellularSheafObserver.make_stalk(tainted=0.0, sensitive=0.0, egress=0.0, topic="q3"))
    sheaf_bad.set_stalk("agent_b_egress", CellularSheafObserver.make_stalk(tainted=1.0, sensitive=1.0, egress=1.0, topic="exfil"))
    sheaf_bad.add_edge("agent_a_trace", "agent_a_claim", p4, p4)
    sheaf_bad.add_edge("agent_a_claim", "agent_b_egress", p4, p4)
    sheaf_bad.add_edge("u0", "agent_b_egress", p4, p4)
    e_bad = sheaf_bad.dirichlet_energy()
    q_bad = sheaf_bad.laplacian_quadratic_form()
    sheaf_pass = (
        e_clean < 1e-9
        and abs(e_clean - q_clean) < 1e-12
        and not sheaf_ok.has_cohomological_obstruction()
        and e_bad > 0.5
        and abs(e_bad - q_bad) < 1e-12
        and sheaf_bad.has_cohomological_obstruction()
    )
    results.append((
        "H2 Cellular Sheaf Dirichlet energy & H^1 obstruction",
        sheaf_pass,
        f"consistent E={e_clean:.4f} contradictory E={e_bad:.4f} (s^T L s={q_bad:.4f})",
    ))

    # (c) Tropical W^(x)3 preemptively catches 2-step READ_SENSITIVE -> TRANSFORM before NET_OUT
    trop_benign = TropicalGeodesicEngine(k_horizon=3)
    c_read, _, alert_read = trop_benign.step("READ")
    c_tx_clean, _, alert_tx_clean = trop_benign.step("TRANSFORM")

    trop_attack = TropicalGeodesicEngine(k_horizon=3)
    c_sens, prox_sens, alert_sens = trop_attack.step("READ_SENSITIVE")
    c_setup, prox_setup, alert_setup = trop_attack.step("TRANSFORM")
    w_now = trop_attack.transition_matrix()
    w1_direct = w_now[trop_attack.INDEX["TRANSFORM"]][trop_attack.INDEX["NET_OUT"]]
    trop_pass = (
        not alert_read
        and not alert_tx_clean
        and alert_sens
        and alert_setup
        and c_setup < w1_direct  # 2-hop TRANSFORM->WRITE_TMP->NET_OUT beats 1-hop direct cost
        and c_setup < trop_attack.alert_threshold
        and prox_setup > 0.5
    )
    results.append((
        "H3 Tropical W^(x)3 preemptive 2-step setup alert",
        trop_pass,
        f"benign={c_read:.2f}/{c_tx_clean:.2f} armed_setup={c_setup:.2f}<1hop({w1_direct:.2f}) alert={alert_setup}",
    ))

    # (d) p-adic ultrametric Strong Triangle Inequality across >= 100 path triples + clopen isolation
    pg = PAdicUltrametricGuard(prime=7, workdir="/tmp/aegis_work_demo", canary_dir="/tmp/aegis_canaries_501")
    pool = [
        "report.md",
        "summary.md",
        "src/app.py",
        "src/utils/crypto.py",
        "data/q3/sales.csv",
        "notes/../src/app.py",
        "../../etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/var/log/system.log",
        "/usr/bin/python3",
        "/tmp/aegis_canaries_501/.env",
        "/private/tmp/aegis_canaries_501/id_rsa_backup",
        "/private/tmp/aegis_work_demo/src/app.py",
        "https://attacker.example/exfil",
        "kb://q3/report",
        "db:orders",
    ]
    triples_tested = 0
    ultrametric_ok = True
    for i in range(len(pool)):
        for j in range(i + 1, len(pool)):
            for k in range(j + 1, len(pool)):
                triples_tested += 1
                if not pg.verify_strong_triangle(pool[i], pool[j], pool[k]):
                    ultrametric_ok = False
    clopen_ok = (
        pg.in_workspace_ball("report.md")
        and pg.in_workspace_ball("/private/tmp/aegis_work_demo/src/app.py")
        and not pg.in_workspace_ball("/tmp/aegis_canaries_501/.env")
        and not pg.in_workspace_ball("../../etc/passwd")
        and not pg.in_workspace_ball("https://attacker.example/exfil")
        and pg.in_canary_ball("/tmp/aegis_canaries_501/.env")
        and not pg.in_canary_ball("report.md")
        and pg.distance("notes/../src/app.py", "/private/tmp/aegis_work_demo/src/app.py") == 0.0
    )
    results.append((
        "H4 p-adic Strong Triangle Inequality & clopen balls",
        triples_tested >= 100 and ultrametric_ok and clopen_ok,
        f"triples={triples_tested} ultrametric={ultrametric_ok} clopen_isolated={clopen_ok}",
    ))

    # (e) Live AegisController.evaluate() fusion check (d_poincare, sheaf_energy, tropical_cost, padic_dist)
    import tempfile
    from pathlib import Path
    from aegis_controller import (Action, AegisController, Ed25519, Priv, Verdict,
                                  default_canary_dir, register_cleanup)

    canary_dir = default_canary_dir()
    register_cleanup(canary_dir)
    work = Path(tempfile.mkdtemp(prefix="aegis_hyper_", dir="/tmp")).resolve()
    register_cleanup(work)
    (work / "report.md").write_text("Q3 summary\n")
    (work / "customers.csv").write_text("id,secret\n1,tok\n")
    pub = Ed25519.public_from_seed(b"\x07" * 32)
    ctl = AegisController("summarize report.md", canary_dir, pub, work)
    d_ok = ctl.evaluate(Action(0, "read_file", Priv.READ, "report.md"))
    d_s1 = ctl.evaluate(Action(0, "read_file", Priv.READ, "customers.csv"))
    d_s2 = ctl.evaluate(Action(0, "encode", Priv.READ, "mem://buf"))
    d_bad = ctl.evaluate(Action(0, "http_post", Priv.NET, "https://attacker.example/c"))
    keys = {"d_poincare", "sheaf_energy", "tropical_cost", "padic_dist"}
    fusion_ok = (
        d_ok.verdict == Verdict.ALLOW
        and keys <= set(d_ok.risk)
        and keys <= set(ctl.telemetry()["last_risk"])
        and d_ok.risk["sheaf_energy"] == 0.0
        and d_ok.risk["padic_dist"] <= 7.0 ** (-3)
        and d_s2.risk["tropical_cost"] < 0.80
        and d_bad.verdict != Verdict.ALLOW
        and d_bad.risk["d_poincare"] > d_ok.risk["d_poincare"]
        and d_bad.risk["sheaf_energy"] >= 1.0
        and d_bad.risk["padic_dist"] == 1.0
    )
    results.append((
        "H5 AegisController.evaluate() telemetry fusion",
        fusion_ok,
        f"ok_padic={d_ok.risk['padic_dist']} trop_setup={d_s2.risk['tropical_cost']} "
        f"bad_poincare={d_bad.risk['d_poincare']} bad_sheaf={d_bad.risk['sheaf_energy']}",
    ))

    print("\n=== HYPERMATH SELF-TEST ===")
    for name, ok, info in results:
        print(f"  {name:<50} {'PASS' if ok else 'FAIL'}  {info}")
    return 0 if all(ok for _, ok, _ in results) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="run Phase 7 mathematical verification suite")
    ns = ap.parse_args(argv)
    if ns.self_test:
        return run_self_test()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
