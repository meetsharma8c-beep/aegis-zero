// SPDX-License-Identifier: GPL-2.0
/*
 * AEGIS-ZERO Ring 0 enforcement: BPF LSM program.
 *
 * Build:  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *         clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c aegis_kernel_hook.bpf.c -o aegis_kernel_hook.bpf.o
 * Needs:  CONFIG_BPF_LSM=y, "bpf" in lsm= boot parameter, cgroup v2, kernel >= 5.15.
 *
 * Semantics (fail-closed):
 *   - Only tasks whose cgroup id is in `sandbox_cgroups` are governed.
 *   - Canary inode touched (open/stat/unlink/exec)  -> -EPERM + SIGSTOP + CRITICAL event.
 *   - Privileged op (write-open, unlink, exec, connect, sendmsg) without a valid
 *     single-use capability in `cap_tokens` -> -EPERM + SIGSTOP + ESCALATE event.
 *     User space then freezes the whole cgroup (cgroup.freeze=1) and evaluates.
 *   - Capabilities are keyed on the *resolved* (dev, ino) object, not a path
 *     string, so post-check symlink swaps cannot redirect an approved op (anti-TOCTOU).
 *   - Signals against protected Aegis daemon PIDs from the sandbox are denied.
 *   - If the controller dies, no tokens are minted, so every privileged op is denied.
 *
 * LSM hooks cannot block waiting on user space; the "pause" is realised as
 * synchronous deny + SIGSTOP of the caller, then atomic cgroup freeze by Ring 1.
 * The agent retries only after a token is installed.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define EPERM 1
#define SIGSTOP 19
#define MAY_WRITE 0x2
#define FMODE_WRITE 0x2
#define AF_INET 2
#define AF_INET6 10

enum aegis_hook {
	H_FILE_OPEN = 1, H_FILE_PERM = 2, H_UNLINK = 3, H_EXEC = 4,
	H_CONNECT = 5, H_SENDMSG = 6, H_GETATTR = 7, H_KILL = 8,
};

enum aegis_verdict { V_ALLOW_TOKEN = 0, V_DENY_ESCALATE = 1, V_CANARY = 2, V_TAMPER = 3 };

struct obj_key { __u64 dev; __u64 ino; };

struct cap_key {
	__u32 tgid;
	__u32 hook;
	__u64 dev;
	__u64 ino;     /* for sockets: dst addr hash in ino, port in dev */
};

struct cap_val {
	__u64 expires_ns;
	__u8  tag[32]; /* HMAC-SHA256 tag (verified by Ring 1 before insertion; kept for audit) */
};

struct aegis_event {
	__u64 ts_ns;
	__u64 cgid;
	__u32 tgid;
	__u32 pid;
	__u32 hook;
	__u32 verdict;
	__u64 dev;
	__u64 ino;
	__u32 daddr4;
	__u16 dport;
	__u16 pad;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);   /* cgroup id */
	__type(value, __u8);
} sandbox_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct obj_key);
	__type(value, __u32); /* canary id */
} canary_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct cap_key);
	__type(value, struct cap_val);
} cap_tokens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);   /* protected tgid (aegis daemons) */
	__type(value, __u8);
} protected_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

static __always_inline int in_sandbox(__u64 *cgid_out)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	*cgid_out = cgid;
	return bpf_map_lookup_elem(&sandbox_cgroups, &cgid) != NULL;
}

static __always_inline void emit(__u64 cgid, __u32 hook, __u32 verdict,
				 __u64 dev, __u64 ino, __u32 daddr, __u16 dport)
{
	struct aegis_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	__u64 id = bpf_get_current_pid_tgid();

	if (!e)
		return; /* ring full: enforcement still happens below; telemetry loss only */
	e->ts_ns = bpf_ktime_get_ns();
	e->cgid = cgid;
	e->tgid = id >> 32;
	e->pid = (__u32)id;
	e->hook = hook;
	e->verdict = verdict;
	e->dev = dev;
	e->ino = ino;
	e->daddr4 = daddr;
	e->dport = dport;
	e->pad = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/* Consume a single-use capability. Returns 1 if valid (and deletes it). */
static __always_inline int consume_cap(__u32 hook, __u64 dev, __u64 ino)
{
	struct cap_key k = {};
	struct cap_val *v;

	k.tgid = bpf_get_current_pid_tgid() >> 32;
	k.hook = hook;
	k.dev = dev;
	k.ino = ino;
	v = bpf_map_lookup_elem(&cap_tokens, &k);
	if (!v)
		return 0;
	if (bpf_ktime_get_ns() > v->expires_ns) {
		bpf_map_delete_elem(&cap_tokens, &k);
		return 0;
	}
	/* delete returns 0 only for the one racer that actually removed it */
	return bpf_map_delete_elem(&cap_tokens, &k) == 0;
}

static __always_inline int deny_and_stop(__u64 cgid, __u32 hook, __u32 verdict,
					 __u64 dev, __u64 ino, __u32 daddr, __u16 dport)
{
	emit(cgid, hook, verdict, dev, ino, daddr, dport);
	bpf_send_signal(SIGSTOP); /* whole thread group; Ring 1 then freezes the cgroup */
	return -EPERM;
}

static __always_inline int inode_ident(struct inode *inode, struct obj_key *k)
{
	if (!inode)
		return 0;
	k->ino = BPF_CORE_READ(inode, i_ino);
	k->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return 1;
}

static __always_inline int is_canary(struct obj_key *k)
{
	return bpf_map_lookup_elem(&canary_inodes, k) != NULL;
}

SEC("lsm/file_open")
int BPF_PROG(aegis_file_open, struct file *file, int ret)
{
	struct obj_key k = {};
	__u64 cgid;
	unsigned int fmode;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!inode_ident(BPF_CORE_READ(file, f_inode), &k))
		return -EPERM;
	if (is_canary(&k))
		return deny_and_stop(cgid, H_FILE_OPEN, V_CANARY, k.dev, k.ino, 0, 0);
	fmode = BPF_CORE_READ(file, f_mode);
	if (!(fmode & FMODE_WRITE))
		return 0; /* reads on non-canary objects are governed by Ring 1 taint, not Ring 0 */
	if (consume_cap(H_FILE_OPEN, k.dev, k.ino))
		return 0;
	return deny_and_stop(cgid, H_FILE_OPEN, V_DENY_ESCALATE, k.dev, k.ino, 0, 0);
}

SEC("lsm/file_permission")
int BPF_PROG(aegis_file_permission, struct file *file, int mask, int ret)
{
	struct obj_key k = {};
	__u64 cgid;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!inode_ident(BPF_CORE_READ(file, f_inode), &k))
		return -EPERM;
	/* catches fds inherited/passed via SCM_RIGHTS that bypassed file_open */
	if (is_canary(&k))
		return deny_and_stop(cgid, H_FILE_PERM, V_CANARY, k.dev, k.ino, 0, 0);
	return 0;
}

SEC("lsm/inode_getattr")
int BPF_PROG(aegis_inode_getattr, const struct path *path, int ret)
{
	struct obj_key k = {};
	__u64 cgid;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!inode_ident(BPF_CORE_READ(path, dentry, d_inode), &k))
		return 0;
	if (is_canary(&k)) /* stat() on a honeytoken is a zero-tolerance trip */
		return deny_and_stop(cgid, H_GETATTR, V_CANARY, k.dev, k.ino, 0, 0);
	return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(aegis_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
	struct obj_key k = {};
	__u64 cgid;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!inode_ident(BPF_CORE_READ(dentry, d_inode), &k))
		return -EPERM;
	if (is_canary(&k))
		return deny_and_stop(cgid, H_UNLINK, V_CANARY, k.dev, k.ino, 0, 0);
	if (consume_cap(H_UNLINK, k.dev, k.ino))
		return 0;
	return deny_and_stop(cgid, H_UNLINK, V_DENY_ESCALATE, k.dev, k.ino, 0, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct obj_key k = {};
	__u64 cgid;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!inode_ident(BPF_CORE_READ(bprm, file, f_inode), &k))
		return -EPERM;
	if (is_canary(&k))
		return deny_and_stop(cgid, H_EXEC, V_CANARY, k.dev, k.ino, 0, 0);
	if (consume_cap(H_EXEC, k.dev, k.ino))
		return 0;
	return deny_and_stop(cgid, H_EXEC, V_DENY_ESCALATE, k.dev, k.ino, 0, 0);
}

static __always_inline int sock_ident(struct sockaddr *addr, int addrlen,
				      __u32 *daddr, __u16 *dport, __u64 *h)
{
	__u16 fam;

	if (!addr || addrlen < (int)sizeof(struct sockaddr_in))
		return 0;
	fam = BPF_CORE_READ(addr, sa_family);
	if (fam == AF_INET) {
		struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
		*daddr = BPF_CORE_READ(in4, sin_addr.s_addr);
		*dport = bpf_ntohs(BPF_CORE_READ(in4, sin_port));
		*h = *daddr;
		return 1;
	}
	if (fam == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
		__u32 w0 = BPF_CORE_READ(in6, sin6_addr.in6_u.u6_addr32[0]);
		__u32 w1 = BPF_CORE_READ(in6, sin6_addr.in6_u.u6_addr32[1]);
		__u32 w2 = BPF_CORE_READ(in6, sin6_addr.in6_u.u6_addr32[2]);
		__u32 w3 = BPF_CORE_READ(in6, sin6_addr.in6_u.u6_addr32[3]);
		*daddr = 0;
		*dport = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		*h = ((__u64)(w0 ^ w2) << 32) | (w1 ^ w3);
		return 1;
	}
	return 0; /* AF_UNIX / AF_NETLINK etc. handled by seccomp profile */
}

SEC("lsm/socket_connect")
int BPF_PROG(aegis_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	__u64 cgid, h = 0;
	__u32 daddr = 0;
	__u16 dport = 0;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	if (!sock_ident(address, addrlen, &daddr, &dport, &h))
		return 0;
	if (consume_cap(H_CONNECT, dport, h))
		return 0;
	return deny_and_stop(cgid, H_CONNECT, V_DENY_ESCALATE, dport, h, daddr, dport);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(aegis_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
	__u64 cgid, h = 0;
	__u32 daddr = 0;
	__u16 dport = 0;
	struct sockaddr *name;
	int namelen;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	name = BPF_CORE_READ(msg, msg_name);
	namelen = BPF_CORE_READ(msg, msg_namelen);
	/* connected sockets already passed socket_connect; unconnected UDP (e.g. DNS
	 * exfil via sendto) carries an explicit destination and needs its own cap. */
	if (!name)
		return 0;
	if (!sock_ident(name, namelen, &daddr, &dport, &h))
		return 0;
	if (consume_cap(H_SENDMSG, dport, h))
		return 0;
	return deny_and_stop(cgid, H_SENDMSG, V_DENY_ESCALATE, dport, h, daddr, dport);
}

SEC("lsm/task_kill")
int BPF_PROG(aegis_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	__u64 cgid;
	__u32 target;

	if (ret)
		return ret;
	if (!in_sandbox(&cgid))
		return 0;
	target = BPF_CORE_READ(p, tgid);
	if (bpf_map_lookup_elem(&protected_pids, &target))
		return deny_and_stop(cgid, H_KILL, V_TAMPER, 0, target, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
