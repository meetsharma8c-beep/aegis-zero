#!/usr/bin/env python3
"""AEGIS-ZERO Ring 0 <-> Ring 1 bridge.

Connects AegisController to the maps pinned by aegis_kernel_hook.bpf.c:

  sandbox_cgroups  <- cgroup v2 id of the agent sandbox (inode number of the cgroup dir)
  protected_pids   <- Aegis daemon tgids (task_kill self-protection)
  canary_inodes    <- (kernel dev_t, ino) of every CanarySentinel decoy
  cap_tokens       <- one entry per PolicyEngine.mint(): struct cap_key -> struct cap_val
  events (ringbuf) -> ProcessTreeFreezer.freeze() + OOBHumanGate.challenge()

Map access uses the raw bpf(2) syscall through ctypes (BPF_OBJ_GET, BPF_MAP_UPDATE_ELEM,
BPF_MAP_DELETE_ELEM) and an mmap()ed ring-buffer consumer; no libbpf/bpftool needed at runtime.
On macOS, or when /sys/fs/bpf/aegis/maps is absent, a dry-run backend records the exact
bytes that would be written so layouts and wiring can still be verified.

  python3 aegis_bpf_bridge.py --test
  sudo python3 aegis_bpf_bridge.py --run --intent "..." --cgroup /sys/fs/cgroup/aegis_sandbox
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse, ctypes, ctypes.util, ipaddress, mmap, os, platform, re, secrets, signal, socket, struct
import tempfile, threading, time
from pathlib import Path
from urllib.parse import urlparse

import aegis_controller as ac
from aegis_controller import Action, AegisController, Priv, ProcessTreeFreezer

C_SOURCE = Path(__file__).with_name("aegis_kernel_hook.bpf.c")
DEFAULT_PIN = Path("/sys/fs/bpf/aegis/maps")

H_FILE_OPEN, H_FILE_PERM, H_UNLINK, H_EXEC, H_CONNECT, H_SENDMSG, H_GETATTR, H_KILL = range(1, 9)
HOOK_NAMES = {1: "file_open", 2: "file_permission", 3: "inode_unlink", 4: "bprm_check_security",
              5: "socket_connect", 6: "socket_sendmsg", 7: "inode_getattr", 8: "task_kill"}
HOOK_PRIV = {1: Priv.WRITE, 2: Priv.READ, 3: Priv.DELETE, 4: Priv.EXEC, 5: Priv.NET, 6: Priv.NET,
             7: Priv.READ, 8: Priv.EXEC}
V_ALLOW_TOKEN, V_DENY_ESCALATE, V_CANARY, V_TAMPER = range(4)
PRIV_HOOKS = {"WRITE": (H_FILE_OPEN,), "DELETE": (H_UNLINK,), "EXEC": (H_EXEC,), "NET": (H_CONNECT, H_SENDMSG)}


# --------------------------------------------------------------------------- C structs
class ObjKey(ctypes.Structure):
    _fields_ = [("dev", ctypes.c_uint64), ("ino", ctypes.c_uint64)]


class CapKey(ctypes.Structure):
    _fields_ = [("tgid", ctypes.c_uint32), ("hook", ctypes.c_uint32),
                ("dev", ctypes.c_uint64), ("ino", ctypes.c_uint64)]


class CapVal(ctypes.Structure):
    _fields_ = [("expires_ns", ctypes.c_uint64), ("tag", ctypes.c_uint8 * 32)]


class AegisEvent(ctypes.Structure):
    _fields_ = [("ts_ns", ctypes.c_uint64), ("cgid", ctypes.c_uint64), ("tgid", ctypes.c_uint32),
                ("pid", ctypes.c_uint32), ("hook", ctypes.c_uint32), ("verdict", ctypes.c_uint32),
                ("dev", ctypes.c_uint64), ("ino", ctypes.c_uint64), ("daddr4", ctypes.c_uint32),
                ("dport", ctypes.c_uint16), ("pad", ctypes.c_uint16), ("comm", ctypes.c_char * 16)]


PY_STRUCTS = {"obj_key": ObjKey, "cap_key": CapKey, "cap_val": CapVal, "aegis_event": AegisEvent}
C_TYPES = {"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8, "char": 1}


def c_layout(src: str, name: str) -> tuple[list[tuple[str, int, int]], int]:
    """Compute (field, offset, size) and sizeof for a struct in the BPF C source (natural alignment)."""
    m = re.search(r"struct\s+" + name + r"\s*\{(.*?)\};", src, re.S)
    if not m:
        raise ValueError(f"struct {name} not found in {C_SOURCE.name}")
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    fields, off, max_align = [], 0, 1
    for decl in body.split(";"):
        decl = decl.strip()
        if not decl:
            continue
        fm = re.fullmatch(r"(__u8|__u16|__u32|__u64|char)\s+(\w+)(?:\[(\d+)\])?", decl)
        if not fm:
            raise ValueError(f"unsupported declaration in struct {name}: {decl!r}")
        size = C_TYPES[fm.group(1)]
        count = int(fm.group(3) or 1)
        off = (off + size - 1) // size * size
        fields.append((fm.group(2), off, size * count))
        off += size * count
        max_align = max(max_align, size)
    return fields, (off + max_align - 1) // max_align * max_align


def c_enum(src: str, name: str) -> dict[str, int]:
    m = re.search(r"enum\s+" + name + r"\s*\{(.*?)\};", src, re.S)
    out, nxt = {}, 0
    for item in m.group(1).split(","):
        item = item.strip()
        if not item:
            continue
        k, _, v = item.partition("=")
        nxt = int(v.strip()) if v.strip() else nxt
        out[k.strip()] = nxt
        nxt += 1
    return out


def kdev(st_dev: int) -> int:
    """User-space st_dev (new_encode_dev) -> kernel dev_t as read from inode->i_sb->s_dev (MKDEV)."""
    try:
        maj, minr = os.major(st_dev), os.minor(st_dev)
    except OverflowError:  # CPython < 3.12 on darwin: makedev>=128 is signed int32, major/minor expect uint32
        u = st_dev & 0xFFFFFFFF
        maj, minr = os.major(u), os.minor(u)
    return (maj << 20) | minr


def monotonic_ns() -> int:
    if hasattr(time, "CLOCK_MONOTONIC") and sys.platform.startswith("linux"):
        return time.clock_gettime_ns(time.CLOCK_MONOTONIC)  # == bpf_ktime_get_ns()
    return time.monotonic_ns()


# --------------------------------------------------------------------------- ring buffer
BPF_RINGBUF_BUSY_BIT, BPF_RINGBUF_DISCARD_BIT, BPF_RINGBUF_HDR_SZ = 1 << 31, 1 << 30, 8


def ringbuf_drain(data, size: int, cons: int, prod: int) -> tuple[list[bytes], int]:
    """Consume committed records from a BPF ring buffer data area.

    `data` must expose the data pages mapped twice back-to-back (as the kernel maps them) so a
    record that wraps around can be read contiguously. Returns (records, new_consumer_pos).
    """
    records, mask = [], size - 1
    while cons < prod:
        off = cons & mask
        hdr_len, _pg = struct.unpack_from("<II", data, off)
        if hdr_len & BPF_RINGBUF_BUSY_BIT:
            break  # producer has reserved but not yet committed
        ln = hdr_len & ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)
        if not hdr_len & BPF_RINGBUF_DISCARD_BIT:
            records.append(bytes(data[off + BPF_RINGBUF_HDR_SZ: off + BPF_RINGBUF_HDR_SZ + ln]))
        cons += (ln + BPF_RINGBUF_HDR_SZ + 7) & ~7
    return records, cons


# --------------------------------------------------------------------------- backends
class DryRunBackend:
    name = "dry-run"

    def __init__(self):
        self.maps: dict[str, dict[bytes, bytes]] = {m: {} for m in
                                                    ("sandbox_cgroups", "protected_pids", "canary_inodes", "cap_tokens")}
        self.events: list[bytes] = []
        self.ops: list[tuple[str, str, str, str]] = []

    def update(self, m: str, key: bytes, val: bytes) -> None:
        self.maps[m][key] = val
        self.ops.append(("update", m, key.hex(), val.hex()))

    def delete(self, m: str, key: bytes) -> bool:
        self.ops.append(("delete", m, key.hex(), ""))
        return self.maps[m].pop(key, None) is not None

    def inject(self, ev: AegisEvent) -> None:
        self.events.append(bytes(ev))

    def read_events(self) -> list[bytes]:
        out, self.events = self.events, []
        return out

    def close(self) -> None:
        return


class LinuxBpfBackend:
    name = "linux-bpf"
    SYS_BPF = {"x86_64": 321, "aarch64": 280, "arm64": 280, "riscv64": 280, "armv7l": 386, "ppc64le": 361, "s390x": 351}
    BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM, BPF_OBJ_GET = 2, 3, 7
    BPF_ANY = 0

    def __init__(self, pin_dir: Path = DEFAULT_PIN):
        self.libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.nr = self.SYS_BPF[platform.machine()]
        self.fds = {m: self._obj_get(pin_dir / m) for m in
                    ("sandbox_cgroups", "protected_pids", "canary_inodes", "cap_tokens", "events")}
        page = mmap.PAGESIZE
        self.rb_size = 1 << 22  # max_entries of the events map in aegis_kernel_hook.bpf.c
        self.cons_map = mmap.mmap(self.fds["events"], page, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
        self.prod_map = mmap.mmap(self.fds["events"], page + 2 * self.rb_size, mmap.MAP_SHARED, mmap.PROT_READ,
                                  offset=page)
        self.data = memoryview(self.prod_map)[page:]

    def _sys(self, cmd: int, attr: ctypes.Array) -> int:
        r = self.libc.syscall(self.nr, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
        if r < 0:
            e = ctypes.get_errno()
            raise OSError(e, f"bpf(cmd={cmd}): {os.strerror(e)}")
        return r

    def _obj_get(self, path: Path) -> int:
        p = ctypes.create_string_buffer(str(path).encode())
        attr = ctypes.create_string_buffer(128)
        struct.pack_into("=QII", attr, 0, ctypes.addressof(p), 0, 0)
        return self._sys(self.BPF_OBJ_GET, attr)

    def update(self, m: str, key: bytes, val: bytes) -> None:
        k, v = ctypes.create_string_buffer(key, len(key)), ctypes.create_string_buffer(val, len(val))
        attr = ctypes.create_string_buffer(128)
        struct.pack_into("=IIQQQ", attr, 0, self.fds[m], 0, ctypes.addressof(k), ctypes.addressof(v), self.BPF_ANY)
        self._sys(self.BPF_MAP_UPDATE_ELEM, attr)

    def delete(self, m: str, key: bytes) -> bool:
        k = ctypes.create_string_buffer(key, len(key))
        attr = ctypes.create_string_buffer(128)
        struct.pack_into("=IIQQQ", attr, 0, self.fds[m], 0, ctypes.addressof(k), 0, 0)
        try:
            self._sys(self.BPF_MAP_DELETE_ELEM, attr)
            return True
        except OSError:
            return False

    def read_events(self) -> list[bytes]:
        cons = struct.unpack_from("<Q", self.cons_map, 0)[0]
        prod = struct.unpack_from("<Q", self.prod_map, 0)[0]
        recs, new = ringbuf_drain(self.data, self.rb_size, cons, prod)
        if new != cons:
            struct.pack_into("<Q", self.cons_map, 0, new)
        return recs

    def close(self) -> None:
        self.data.release()
        self.prod_map.close(); self.cons_map.close()
        for fd in self.fds.values():
            os.close(fd)


def select_backend(pin_dir: Path = DEFAULT_PIN):
    try:
        if sys.platform.startswith("linux") and (pin_dir / "cap_tokens").exists():
            return LinuxBpfBackend(pin_dir)
    except PermissionError:
        pass
    return DryRunBackend()


# --------------------------------------------------------------------------- bridge
class AegisBridge:
    def __init__(self, ctl: AegisController, backend=None, cgroup: Path | None = None,
                 protected: list[int] | None = None):
        self.ctl, self.backend = ctl, backend or select_backend()
        self.cgroup = cgroup
        self.protected = protected or [os.getpid()]
        self.kernel_challenges: list[dict] = []
        self.stop = threading.Event()

    def install(self) -> dict:
        n = {"sandbox_cgroups": 0, "protected_pids": 0, "canary_inodes": 0}
        if self.cgroup is not None:
            cgid = os.stat(self.cgroup).st_ino  # cgroup v2 id == kernfs inode number
            self.backend.update("sandbox_cgroups", struct.pack("=Q", cgid), b"\x01"); n["sandbox_cgroups"] += 1
        for pid in self.protected:
            self.backend.update("protected_pids", struct.pack("=I", pid), b"\x01"); n["protected_pids"] += 1
        for i, path in enumerate(sorted(self.ctl.canary.paths), start=1):
            st = os.stat(path)
            self.backend.update("canary_inodes", bytes(ObjKey(kdev(st.st_dev), st.st_ino)), struct.pack("=I", i))
            n["canary_inodes"] += 1
        self.ctl.policy.on_mint.append(self.on_mint)
        ac.log("BRIDGE", f"{self.backend.name}: installed {n}")
        return n

    def _resolve_file(self, a: Action, create: bool) -> tuple[int, int] | None:
        root = self.ctl.workdir
        p = Path(a.target) if os.path.isabs(a.target) or root is None else root / a.target
        rp = Path(os.path.realpath(p))
        if not rp.exists() and create and isinstance(self.backend, LinuxBpfBackend):
            # Pre-create so the inode is known; CoW already recorded prior non-existence.
            fd = os.open(rp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        try:
            st = os.stat(rp)
        except OSError:
            return None
        return kdev(st.st_dev), st.st_ino

    @staticmethod
    def _resolve_net(target: str) -> tuple[int, int] | None:
        u = urlparse(target if "://" in target else f"tcp://{target}")
        if not u.hostname:
            return None
        try:
            ip = ipaddress.ip_address(u.hostname)
        except ValueError:
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
            except OSError:
                return None
        port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
        if ip.version == 4:
            return port, struct.unpack("=I", ip.packed)[0]  # s_addr as the BPF program reads it
        w = struct.unpack("=IIII", ip.packed)
        return port, ((w[0] ^ w[2]) << 32) | (w[1] ^ w[3])

    def on_mint(self, a: Action, syscall: str, tag: bytes, ttl: float) -> None:
        hooks = PRIV_HOOKS.get(syscall)
        if not hooks:
            return
        ident = self._resolve_net(a.target) if syscall == "NET" else \
            self._resolve_file(a, create=syscall == "WRITE")
        if ident is None:
            ac.log("BRIDGE", f"cannot resolve {a.target} for Ring 0 capability: kernel will deny (fail closed)")
            return
        dev, ino = ident
        val = CapVal(monotonic_ns() + int(ttl * 1e9))
        val.tag[:] = list(tag[:32])
        for h in hooks:
            self.backend.update("cap_tokens", bytes(CapKey(a.pid, h, dev, ino)), bytes(val))
        ac.log("BRIDGE", f"cap_tokens += tgid={a.pid} hooks={[HOOK_NAMES[h] for h in hooks]} dev={dev:#x} ino={ino}")

    def handle_event(self, raw: bytes) -> dict | None:
        if len(raw) < ctypes.sizeof(AegisEvent):
            return None
        ev = AegisEvent.from_buffer_copy(raw[:ctypes.sizeof(AegisEvent)])
        if ev.verdict == V_ALLOW_TOKEN:
            return None
        hook = HOOK_NAMES.get(ev.hook, f"hook{ev.hook}")
        target = (f"{ipaddress.ip_address(struct.pack('=I', ev.daddr4))}:{ev.dport}"
                  if ev.hook in (H_CONNECT, H_SENDMSG) and ev.daddr4 else f"dev={ev.dev:#x},ino={ev.ino}")
        a = Action(ev.tgid, f"kernel:{hook}", HOOK_PRIV.get(ev.hook, Priv.EXEC), target,
                   {"comm": ev.comm.decode(errors="replace"), "cgid": ev.cgid})
        verdict = {V_DENY_ESCALATE: ac.Verdict.ESCALATE, V_CANARY: ac.Verdict.TRIP, V_TAMPER: ac.Verdict.TRIP}[ev.verdict]
        ac.log("RING0-EV", f"{hook} tgid={ev.tgid} comm={a.args['comm']} verdict={verdict} target={target}")
        pids = self.ctl.freezer.freeze(ev.tgid)
        if verdict == ac.Verdict.TRIP and self.ctl.cow is not None:
            self.ctl.rollback()
        payload = self.ctl.gate.challenge(self.ctl.u0, a, f"Ring 0 {hook} interception", self.ctl.taint.lineage,
                                          {"kernel_verdict": ev.verdict, "hook": hook}, verdict != ac.Verdict.TRIP,
                                          self.ctl.workdir)
        rec = {"event": {f: getattr(ev, f) for f, _ in AegisEvent._fields_ if f != "comm"},
               "frozen": pids, "payload": payload}
        self.kernel_challenges.append(rec)
        return rec

    def poll_once(self) -> int:
        recs = self.backend.read_events()
        for r in recs:
            self.handle_event(r)
        return len(recs)

    def run(self, interval: float = 0.02) -> None:
        while not self.stop.is_set():
            if not self.poll_once():
                time.sleep(interval)


# --------------------------------------------------------------------------- self-test
def self_test() -> int:
    results: list[tuple[str, bool, str]] = []
    src = C_SOURCE.read_text()
    for cname, py in PY_STRUCTS.items():
        fields, size = c_layout(src, cname)
        py_fields = [(n, getattr(py, n).offset, getattr(py, n).size) for n, *_ in py._fields_]
        ok = fields == py_fields and size == ctypes.sizeof(py)
        results.append((f"B1 layout struct {cname}", ok, f"C sizeof={size} ctypes sizeof={ctypes.sizeof(py)}"))
    assert ctypes.sizeof(CapKey) == 24 and ctypes.sizeof(CapVal) == 40
    assert ctypes.sizeof(ObjKey) == 16 and ctypes.sizeof(AegisEvent) == 72
    hooks = c_enum(src, "aegis_hook")
    verdicts = c_enum(src, "aegis_verdict")
    py_hooks = {"H_FILE_OPEN": H_FILE_OPEN, "H_FILE_PERM": H_FILE_PERM, "H_UNLINK": H_UNLINK, "H_EXEC": H_EXEC,
                "H_CONNECT": H_CONNECT, "H_SENDMSG": H_SENDMSG, "H_GETATTR": H_GETATTR, "H_KILL": H_KILL}
    py_verd = {"V_ALLOW_TOKEN": V_ALLOW_TOKEN, "V_DENY_ESCALATE": V_DENY_ESCALATE, "V_CANARY": V_CANARY,
               "V_TAMPER": V_TAMPER}
    results.append(("B2 enum aegis_hook/aegis_verdict", hooks == py_hooks and verdicts == py_verd,
                    f"{len(hooks)} hooks, {len(verdicts)} verdicts"))
    results.append(("B3 kernel dev_t encoding", kdev(os.makedev(8, 3)) == 0x800003 and kdev(os.makedev(253, 7)) == 0xFD00007,
                    f"makedev(8,3)->{kdev(os.makedev(8, 3)):#x}"))

    size = 4096
    ring = bytearray(size)

    def put(pos: int, payload: bytes, flags: int = 0) -> int:
        hdr = struct.pack("<II", len(payload) | flags, 0)
        blob = hdr + payload
        for i, b in enumerate(blob):
            ring[(pos + i) % size] = b
        return pos + ((len(payload) + 8 + 7) & ~7)

    ev = AegisEvent(1, 2, 3, 4, H_FILE_OPEN, V_CANARY, 5, 6, 0, 0, 0, b"agent")
    start = size - 40  # forces a wrap-around record
    p1 = put(start, bytes(ev))
    p2 = put(p1, b"discarded!", BPF_RINGBUF_DISCARD_BIT)
    p3 = put(p2, bytes(ev))
    put(p3, b"in-flight", BPF_RINGBUF_BUSY_BIT)
    recs, cons = ringbuf_drain(bytes(ring) * 2, size, start, p3 + 24)
    parsed = [AegisEvent.from_buffer_copy(r) for r in recs]
    results.append(("B4 ringbuf drain (wrap/discard/busy)", len(recs) == 2 and cons == p3 and all(
        e.verdict == V_CANARY and e.comm == b"agent" for e in parsed), f"records={len(recs)} cons={cons - start}"))

    # B5 dry-run integration with a real controller, real process tree, real CoW
    work = Path(tempfile.mkdtemp(prefix="aegis_bridge_", dir="/tmp")); ac.register_cleanup(work)
    keys = Path(tempfile.mkdtemp(prefix="aegis_keys_", dir="/tmp")); ac.register_cleanup(keys)
    canaries = Path(tempfile.mkdtemp(prefix="aegis_canaries_bridge_", dir="/tmp")); ac.register_cleanup(canaries)
    (work / "summary.md").write_text("old\n")
    ac.ensure_operator_keypair(keys)
    fz = ProcessTreeFreezer()
    ctl = AegisController("summarize report.md and write the summary to summary.md", canaries,
                          ac.load_operator_pubkey(keys), work, fz)
    be = DryRunBackend()
    br = AegisBridge(ctl, be, cgroup=work, protected=[os.getpid(), os.getppid()])
    n = br.install()
    agent = ac.spawn_agent(); fz.register(agent.pid)
    dec = ctl.evaluate(Action(agent.pid, "write_file", Priv.WRITE, "summary.md", {"content": "x"}))
    st = os.stat(work / "summary.md")
    tag = bytes.fromhex(dec.token.split("#")[1])
    want = bytes(CapKey(agent.pid, H_FILE_OPEN, kdev(st.st_dev), st.st_ino))
    got_val = CapVal.from_buffer_copy(be.maps["cap_tokens"].get(want, bytes(40)))
    cap_ok = want in be.maps["cap_tokens"] and bytes(got_val.tag) == tag and got_val.expires_ns > monotonic_ns()
    net = ctl.policy.mint(Action(agent.pid, "http_post", Priv.NET, "https://10.1.2.3:8443/x"), "NET")
    nk = bytes(CapKey(agent.pid, H_CONNECT, 8443, struct.unpack("=I", bytes([10, 1, 2, 3]))[0]))
    results.append(("B5 maps populated + cap_tokens bytes", n == {"sandbox_cgroups": 1, "protected_pids": 2,
                    "canary_inodes": 3} and cap_ok and nk in be.maps["cap_tokens"] and bool(net),
                    f"{len(be.ops)} map ops, cap tag match={cap_ok}"))

    canary = sorted(ctl.canary.paths)[0]
    cst = os.stat(canary)
    be.inject(AegisEvent(monotonic_ns(), st.st_ino, agent.pid, agent.pid, H_GETATTR, V_CANARY,
                         kdev(cst.st_dev), cst.st_ino, 0, 0, 0, b"sleep"))
    handled = br.poll_once()
    rec = br.kernel_challenges[-1] if br.kernel_challenges else {"frozen": [], "payload": {"approvable": True}}
    frozen = bool(rec["frozen"]) and all(ac.process_state(p).startswith("T") for p in rec["frozen"])
    pending = rec["payload"]["challenge"] in ctl.gate.pending if rec.get("payload") else False
    ac.reap(agent, fz)
    results.append(("B6 ringbuf event -> freeze + OOB challenge", handled == 1 and frozen and pending
                    and rec["payload"]["approvable"] is False, f"frozen={rec['frozen']}"))

    if isinstance(select_backend(), LinuxBpfBackend):
        lb = select_backend()
        k = bytes(CapKey(os.getpid(), H_FILE_OPEN, 0, 0))
        lb.update("cap_tokens", k, bytes(CapVal(monotonic_ns() + 10**9)))
        results.append(("B7 live kernel map update/delete", lb.delete("cap_tokens", k), "linux-bpf"))
        lb.close()
    else:
        results.append(("B7 live kernel map update/delete", True, f"skipped on {sys.platform}: no {DEFAULT_PIN}"))

    print("\n=== BPF BRIDGE SELF-TEST ===")
    for name, ok, info in results:
        print(f"  {name:<44} {'PASS' if ok else 'FAIL'}  {info}")
    return 0 if all(ok for _, ok, _ in results) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--intent")
    ap.add_argument("--cgroup", type=Path, default=Path("/sys/fs/cgroup/aegis_sandbox"))
    ap.add_argument("--pin-dir", type=Path, default=DEFAULT_PIN)
    ap.add_argument("--workdir", type=Path, default=Path.cwd())
    ap.add_argument("--key-dir", type=Path, default=None)
    ns = ap.parse_args()
    if ns.test:
        return self_test()
    if not ns.run or not ns.intent:
        ap.error("use --test, or --run --intent '...'")
    ac.register_cleanup(ac.default_canary_dir())
    ctl = AegisController(ns.intent, ac.default_canary_dir(), ac.load_operator_pubkey(ns.key_dir), ns.workdir.resolve())
    br = AegisBridge(ctl, select_backend(ns.pin_dir), ns.cgroup)
    br.install()
    signal.signal(signal.SIGTERM, lambda *_: br.stop.set())
    try:
        br.run()
    except KeyboardInterrupt:
        pass
    finally:
        br.backend.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
