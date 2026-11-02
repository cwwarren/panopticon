// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define DNS_PORT 53

enum ring_class {
	CLASS_PROC,
	CLASS_NET,
	CLASS_FILE,
	NR_CLASSES,
};

enum rec_type {
	REC_EXEC = 1,
	REC_CGROUP,
	REC_CONNECT,
	REC_ACCEPT,
	REC_LISTEN,
	REC_UDP_SEND,
	REC_DNS_QUERY,
	REC_DNS_ANSWER,
	REC_FILE,
	REC_FILE_REPEAT,
};

enum rec_flag {
	FLAG_SNAPSHOT = 1,
	FLAG_TRUNCATED = 2,
	FLAG_SATURATED = 4,
};

enum limits {
	PATH_MAX_REC = 512,
	ARGV_MAX_REC = 1024,
	ARGV_MAX_ARGS = 32,
	CGROUP_PATH_MAX = 256,
	DNS_MAX = 512,
	NAME_MAX_REC = 64,
};

enum ring_class anchor_ring_class;
enum rec_type anchor_rec_type;
enum rec_flag anchor_rec_flag;
enum limits anchor_limits;

#define PROC_RING (256 << 10)
#define NET_RING (256 << 10)
#define FILE_RING (64 << 10)
#define PROC_SLACK 4096
#define NET_SLACK 2048
#define FILE_SLACK 512

#define UDP_SEEN 4
#define UDP_CAP 16

struct rec_hdr {
	__u16 len;
	__u8 type;
	__u8 flags;
	__u32 reserved;
	__u64 jiffies;
};

struct actor {
	__u64 proc;
	__u64 image_proc;
	__u64 image_seq;
	__u64 cgroup;
	__u32 pid;
	__u32 tid;
};

struct exec_rec {
	struct rec_hdr h;
	__u64 proc;
	__u64 exec_seq;
	__u64 spawner;
	__u64 prev_image_proc;
	__u64 prev_image_seq;
	__u64 parent;
	__u64 cgroup;
	__u64 exe_ino;
	__s64 exe_ctime;
	__u64 cap_eff;
	__u32 exe_dev;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 egid;
	__u32 loginuid;
	__u32 sessionid;
	__u32 argc;
	__u16 path_len;
	__u16 argv_len;
	__u32 pad;
	__u8 data[];
};

struct cgroup_rec {
	struct rec_hdr h;
	__u64 id;
	__u16 path_len;
	__u8 pad[6];
	__u8 path[];
};

struct sock_rec {
	struct rec_hdr h;
	struct actor a;
	__u64 cookie;
	__u32 netns;
	__u16 sport;
	__u16 dport;
	__u8 family;
	__u8 proto;
	__u16 payload_len;
	__u32 pad;
	__u8 saddr[16];
	__u8 daddr[16];
	__u8 payload[];
};

struct file_key {
	__u64 proc;
	__u64 seq;
	__u64 ino;
	__u64 child_ino;
	__u32 dev;
	__u32 mask;
};

struct file_rec {
	struct rec_hdr h;
	struct actor a;
	struct file_key k;
	__u16 name_len;
	__u8 pad[6];
	__u8 name[];
};

struct file_repeat_rec {
	struct rec_hdr h;
	struct file_key k;
	__u64 count;
};

#define EXEC_MAX (sizeof(struct exec_rec) + PATH_MAX_REC + ARGV_MAX_REC)
#define CGROUP_MAX (sizeof(struct cgroup_rec) + CGROUP_PATH_MAX)
#define SOCK_MAX (sizeof(struct sock_rec) + DNS_MAX)
#define FILE_MAX (sizeof(struct file_rec) + NAME_MAX_REC)

struct exec_rec anchor_exec;
struct cgroup_rec anchor_cgroup;
struct sock_rec anchor_sock;
struct file_rec anchor_file;
struct file_repeat_rec anchor_file_repeat;

struct ctl {
	__u64 head;
	__u64 pad0[7];
	__u64 tail;
	__u64 pad1[7];
	__u64 drops;
	__u64 pad2[7];
};

struct ring_proc_value {
	__u8 data[PROC_RING + PROC_SLACK];
};

struct ring_net_value {
	__u8 data[NET_RING + NET_SLACK];
};

struct ring_file_value {
	__u8 data[FILE_RING + FILE_SLACK];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ring_proc_value);
} ring_proc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ring_net_value);
} ring_net SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ring_file_value);
} ring_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ctl);
} ctl SEC(".maps");

struct task_meta {
	__u64 spawner;
	__u64 image_proc;
	__u64 image_seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_meta);
} task_meta SEC(".maps");

struct file_seen {
	__u64 jiffies;
	__u64 repeats;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct file_key);
	__type(value, struct file_seen);
} file_seen SEC(".maps");

struct udp_meta {
	__u32 daddr[UDP_SEEN];
	__u16 dport[UDP_SEEN];
	__u8 next;
	__u8 distinct;
	__u8 dns;
	__u8 pad[5];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct udp_meta);
} udp_meta SEC(".maps");

struct snap_value {
	__u8 data[EXEC_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct snap_value);
} snap_scratch SEC(".maps");

const volatile __u32 nr_cpus = 1;
const volatile __u32 agent_tgid = 0;
__u64 our_group;
__u64 clock_jiffies;
__u64 file_window;

extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;

struct ring_slot {
	struct ctl *c;
	__u64 head;
};

static __always_inline void *reserve(void *ring, __u32 class, __u32 size, __u32 max, struct ring_slot *s)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 idx = class * nr_cpus + cpu;
	struct ctl *c = bpf_map_lookup_elem(&ctl, &idx);
	__u8 *base = bpf_map_lookup_elem(ring, &cpu);
	__u64 head, tail;

	if (!c || !base)
		return NULL;
	head = c->head;
	tail = __atomic_load_n(&c->tail, __ATOMIC_ACQUIRE);
	if (head + max - tail > size) {
		c->drops += 1;
		return NULL;
	}
	s->c = c;
	s->head = head;
	return base + (head & (size - 1));
}

static __always_inline void commit(struct ring_slot *s, struct rec_hdr *h, __u32 len, __u8 type, __u8 flags)
{
	len = (len + 7) & ~7;
	h->len = len;
	h->type = type;
	h->flags = flags;
	h->reserved = 0;
	h->jiffies = bpf_jiffies64();
	__atomic_store_n(&s->c->head, s->head + len, __ATOMIC_RELEASE);
}

static __always_inline void fill_actor(struct actor *a)
{
	struct task_struct *leader = bpf_get_current_task_btf()->group_leader;
	struct task_meta *m = bpf_task_storage_get(&task_meta, leader, 0, 0);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 own_seq = leader->self_exec_id;

	a->proc = leader->thread_pid->ino;
	if (m && m->image_proc) {
		a->image_proc = m->image_proc;
		a->image_seq = m->image_seq;
	} else {
		a->image_proc = a->proc;
		a->image_seq = own_seq;
	}
	a->cgroup = bpf_get_current_cgroup_id();
	a->pid = pid_tgid >> 32;
	a->tid = (__u32)pid_tgid;
}

static __always_inline void fill_sock(struct sock_rec *r, struct sock *sk)
{
	__u16 family = sk->__sk_common.skc_family;

	fill_actor(&r->a);
	r->cookie = bpf_get_socket_cookie(sk);
	r->netns = sk->__sk_common.skc_net.net->ns.inum;
	r->sport = sk->__sk_common.skc_num;
	r->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	r->family = family;
	r->proto = sk->sk_protocol;
	r->payload_len = 0;
	r->pad = 0;
	if (family == AF_INET6) {
		bpf_probe_read_kernel(r->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_probe_read_kernel(r->daddr, 16, &sk->__sk_common.skc_v6_daddr);
	} else {
		__builtin_memset(r->saddr, 0, 16);
		__builtin_memset(r->daddr, 0, 16);
		*(__u32 *)r->saddr = sk->__sk_common.skc_rcv_saddr;
		*(__u32 *)r->daddr = sk->__sk_common.skc_daddr;
	}
}

static __always_inline void emit_sock(struct sock *sk, __u8 type)
{
	struct sock_rec *r;
	struct ring_slot s;

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, SOCK_MAX, &s);
	if (r) {
		fill_sock(r, sk);
		commit(&s, &r->h, sizeof(*r), type, 0);
	}
	bpf_preempt_enable();
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	struct task_struct *leader = parent->group_leader;
	__u64 own_seq = leader->self_exec_id;
	struct task_meta *cm, *pm;

	if (child->tgid == parent->tgid)
		return 0;
	cm = bpf_task_storage_get(&task_meta, child, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cm)
		return 0;
	cm->spawner = leader->thread_pid->ino;
	pm = bpf_task_storage_get(&task_meta, leader, 0, 0);
	if (pm && pm->image_proc) {
		cm->image_proc = pm->image_proc;
		cm->image_seq = pm->image_seq;
	} else {
		cm->image_proc = cm->spawner;
		cm->image_seq = own_seq;
	}
	return 0;
}

SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(on_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *file = bprm->file;
	struct inode *inode = file->f_inode;
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	__u64 proc = task->thread_pid->ino;
	__u64 seq = task->self_exec_id;
	__u64 spawner = 0, prev_proc = 0, prev_seq = 0;
	__u32 path_len = 0, pos = 0;
	__u8 flags = 0;
	struct task_meta *m;
	struct exec_rec *r;
	struct ring_slot s;
	char *argv;
	long n;

	m = bpf_task_storage_get(&task_meta, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (m) {
		spawner = m->spawner;
		prev_proc = m->image_proc;
		prev_seq = m->image_seq;
		m->image_proc = proc;
		m->image_seq = seq;
	}

	bpf_preempt_disable();
	r = reserve(&ring_proc, CLASS_PROC, PROC_RING, EXEC_MAX, &s);
	if (r) {
		r->proc = proc;
		r->exec_seq = seq;
		r->spawner = spawner;
		r->prev_image_proc = prev_proc;
		r->prev_image_seq = prev_seq;
		r->parent = BPF_CORE_READ(task, real_parent, group_leader, thread_pid, ino);
		r->cgroup = bpf_get_current_cgroup_id();
		r->exe_ino = inode->i_ino;
		r->exe_ctime = inode->i_ctime_sec;
		r->cap_eff = BPF_CORE_READ(task, cred, cap_effective.val);
		r->exe_dev = inode->i_sb->s_dev;
		r->pid = task->tgid;
		r->ppid = BPF_CORE_READ(task, real_parent, tgid);
		r->uid = BPF_CORE_READ(task, cred, uid.val);
		r->euid = BPF_CORE_READ(task, cred, euid.val);
		r->gid = BPF_CORE_READ(task, cred, gid.val);
		r->egid = BPF_CORE_READ(task, cred, egid.val);
		r->loginuid = task->loginuid.val;
		r->sessionid = task->sessionid;
		r->argc = argc;
		r->pad = 0;

		n = bpf_d_path(&file->f_path, (char *)r->data, PATH_MAX_REC);
		if (n > 1)
			path_len = (n - 1) & (PATH_MAX_REC - 1);
		argv = (char *)r->data + path_len;
		for (int i = 0; i < ARGV_MAX_ARGS; i++) {
			if (i >= argc)
				break;
			if (pos >= ARGV_MAX_REC) {
				flags |= FLAG_TRUNCATED;
				break;
			}
			n = bpf_probe_read_user_str(argv + (pos & (ARGV_MAX_REC - 1)), ARGV_MAX_REC - pos, (const void *)p);
			if (n <= 0)
				break;
			pos += n;
			p += n;
		}
		if (argc > ARGV_MAX_ARGS)
			flags |= FLAG_TRUNCATED;
		r->path_len = path_len;
		r->argv_len = pos;
		commit(&s, &r->h, sizeof(*r) + path_len + pos, REC_EXEC, flags);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("tp_btf/cgroup_mkdir")
int BPF_PROG(on_cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
	struct cgroup_rec *r;
	struct ring_slot s;
	__u32 len = 0;
	long n;

	bpf_preempt_disable();
	r = reserve(&ring_proc, CLASS_PROC, PROC_RING, CGROUP_MAX, &s);
	if (r) {
		r->id = cgrp->kn->id;
		__builtin_memset(r->pad, 0, sizeof(r->pad));
		n = bpf_probe_read_kernel_str(r->path, CGROUP_PATH_MAX, path);
		if (n > 1)
			len = (n - 1) & (CGROUP_PATH_MAX - 1);
		r->path_len = len;
		commit(&s, &r->h, sizeof(*r) + len, REC_CGROUP, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(on_tcp4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (!ret)
		emit_sock(sk, REC_CONNECT);
	return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(on_tcp6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	struct in6_addr daddr = sk->__sk_common.skc_v6_daddr;

	if (ret)
		return 0;
	if (daddr.in6_u.u6_addr32[0] == 0 && daddr.in6_u.u6_addr32[1] == 0 &&
	    daddr.in6_u.u6_addr32[2] == bpf_htonl(0xffff))
		return 0;
	emit_sock(sk, REC_CONNECT);
	return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(on_accept, struct sock *sk, struct proto_accept_arg *arg, struct sock *ret)
{
	if (ret)
		emit_sock(ret, REC_ACCEPT);
	return 0;
}

SEC("fexit/inet_listen")
int BPF_PROG(on_listen, struct socket *sock, int backlog, int ret)
{
	if (!ret)
		emit_sock(sock->sk, REC_LISTEN);
	return 0;
}

static __always_inline bool udp_seen(struct udp_meta *m, __u32 daddr, __u16 dport)
{
	for (int i = 0; i < UDP_SEEN; i++)
		if (m->daddr[i] == daddr && m->dport[i] == dport)
			return true;
	return false;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(on_udp_send, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
	struct sockaddr_in sin = {};
	void *name = msg->msg_name;
	__u32 daddr = sk->__sk_common.skc_daddr, plen = 0;
	__u16 dport = sk->__sk_common.skc_dport;
	struct udp_meta *m;
	struct sock_rec *r;
	struct ring_slot s;
	__u8 flags = 0, slot;
	bool dns;

	barrier_var(daddr);
	barrier_var(dport);
	if (ret < 0)
		return 0;
	if (name) {
		bpf_probe_read_kernel(&sin, sizeof(sin), name);
		if (sin.sin_family != AF_INET)
			return 0;
		daddr = sin.sin_addr.s_addr;
		dport = sin.sin_port;
	}
	dns = dport == bpf_htons(DNS_PORT);
	m = bpf_sk_storage_get(&udp_meta, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!m)
		return 0;
	if (!dns && (udp_seen(m, daddr, dport) || m->distinct >= UDP_CAP))
		return 0;
	if (!udp_seen(m, daddr, dport)) {
		slot = m->next & (UDP_SEEN - 1);
		m->daddr[slot] = daddr;
		m->dport[slot] = dport;
		m->next = slot + 1;
		m->distinct += 1;
		if (m->distinct == UDP_CAP)
			flags |= FLAG_SATURATED;
	}
	if (dns)
		m->dns = 1;

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, SOCK_MAX, &s);
	if (r) {
		fill_sock(r, sk);
		__builtin_memset(r->daddr, 0, 16);
		*(__u32 *)r->daddr = daddr;
		r->dport = bpf_ntohs(dport);
		if (dns && msg->msg_iter.iter_type == ITER_UBUF) {
			plen = ret;
			if (plen > DNS_MAX)
				plen = DNS_MAX;
			barrier_var(plen);
			if (bpf_probe_read_user(r->payload, plen, msg->msg_iter.ubuf))
				plen = 0;
		}
		r->payload_len = plen;
		commit(&s, &r->h, sizeof(*r) + plen, dns ? REC_DNS_QUERY : REC_UDP_SEND, flags);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(on_udp_consume, struct sock *sk, struct sk_buff *skb, int len)
{
	struct udp_meta *m = bpf_sk_storage_get(&udp_meta, sk, 0, 0);
	unsigned char *head;
	struct iphdr ip;
	struct udphdr udp;
	struct sock_rec *r;
	struct ring_slot s;
	__u32 plen;

	if (!m || !m->dns || len <= 0)
		return 0;
	head = skb->head;
	if (bpf_probe_read_kernel(&ip, sizeof(ip), head + skb->network_header) || ip.version != 4)
		return 0;
	if (bpf_probe_read_kernel(&udp, sizeof(udp), head + skb->transport_header))
		return 0;
	plen = bpf_ntohs(udp.len) - sizeof(udp);

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, SOCK_MAX, &s);
	if (r) {
		fill_sock(r, sk);
		__builtin_memset(r->saddr, 0, 16);
		__builtin_memset(r->daddr, 0, 16);
		*(__u32 *)r->saddr = ip.daddr;
		*(__u32 *)r->daddr = ip.saddr;
		r->sport = bpf_ntohs(udp.dest);
		r->dport = bpf_ntohs(udp.source);
		if (plen > DNS_MAX)
			plen = DNS_MAX;
		barrier_var(plen);
		if (bpf_probe_read_kernel(r->payload, plen, head + skb->transport_header + sizeof(udp)))
			plen = 0;
		r->payload_len = plen;
		commit(&s, &r->h, sizeof(*r) + plen, REC_DNS_ANSWER, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("fentry/inotify_update_watch")
int BPF_PROG(on_inotify_watch, struct fsnotify_group *group, struct inode *inode, __u32 arg)
{
	if ((bpf_get_current_pid_tgid() >> 32) == agent_tgid)
		our_group = (__u64)group;
	return 0;
}

SEC("fentry/inotify_handle_inode_event")
int BPF_PROG(on_inotify_event, struct fsnotify_mark *mark, __u32 mask, struct inode *inode, struct inode *dir,
	     const struct qstr *name, __u32 cookie)
{
	struct inode *obj = dir ? dir : inode;
	struct task_struct *leader;
	struct file_seen *seen, fresh = {};
	struct file_key k = {};
	struct file_rec *r;
	struct ring_slot s;
	__u64 now;
	__u32 len = 0;

	if (!our_group || (__u64)mark->group != our_group)
		return 0;
	leader = bpf_get_current_task_btf()->group_leader;
	now = bpf_jiffies64();
	k.proc = leader->thread_pid->ino;
	k.seq = leader->self_exec_id;
	k.ino = obj->i_ino;
	k.child_ino = inode->i_ino;
	k.dev = obj->i_sb->s_dev;
	k.mask = mask;
	seen = bpf_map_lookup_elem(&file_seen, &k);
	if (seen && now - seen->jiffies < file_window) {
		__sync_fetch_and_add(&seen->repeats, 1);
		return 0;
	}
	if (seen) {
		seen->jiffies = now;
	} else {
		fresh.jiffies = now;
		bpf_map_update_elem(&file_seen, &k, &fresh, BPF_NOEXIST);
	}

	bpf_preempt_disable();
	r = reserve(&ring_file, CLASS_FILE, FILE_RING, FILE_MAX, &s);
	if (r) {
		fill_actor(&r->a);
		r->k = k;
		__builtin_memset(r->pad, 0, sizeof(r->pad));
		if (name) {
			len = name->len;
			if (len > NAME_MAX_REC)
				len = NAME_MAX_REC;
			barrier_var(len);
			if (bpf_probe_read_kernel(r->name, len, name->name))
				len = 0;
		}
		r->name_len = len;
		commit(&s, &r->h, sizeof(*r) + len, REC_FILE, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("iter/bpf_map_elem")
int file_flush(struct bpf_iter__bpf_map_elem *ctx)
{
	struct file_key *k = ctx->key;
	struct file_seen *v = ctx->value;
	struct file_repeat_rec r = {};

	if (!k || !v || !v->repeats)
		return 0;
	r.count = __sync_lock_test_and_set(&v->repeats, 0);
	r.h.len = sizeof(r);
	r.h.type = REC_FILE_REPEAT;
	r.h.jiffies = bpf_jiffies64();
	r.k = *k;
	bpf_seq_write(ctx->meta->seq, &r, sizeof(r));
	return 0;
}

SEC("iter.s/task")
int snapshot(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct mm_struct *mm;
	struct file *exe;
	struct exec_rec *r;
	__u32 zero = 0, argv_len = 0, len;
	unsigned long start, end;

	if (!task || task->pid != task->tgid)
		return 0;
	mm = task->mm;
	if (!mm)
		return 0;
	r = bpf_map_lookup_elem(&snap_scratch, &zero);
	if (!r)
		return 0;
	r->proc = task->thread_pid->ino;
	r->exec_seq = task->self_exec_id;
	r->spawner = 0;
	r->prev_image_proc = 0;
	r->prev_image_seq = 0;
	r->parent = BPF_CORE_READ(task, real_parent, group_leader, thread_pid, ino);
	r->cgroup = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
	r->cap_eff = BPF_CORE_READ(task, cred, cap_effective.val);
	r->pid = task->tgid;
	r->ppid = BPF_CORE_READ(task, real_parent, tgid);
	r->uid = BPF_CORE_READ(task, cred, uid.val);
	r->euid = BPF_CORE_READ(task, cred, euid.val);
	r->gid = BPF_CORE_READ(task, cred, gid.val);
	r->egid = BPF_CORE_READ(task, cred, egid.val);
	r->loginuid = task->loginuid.val;
	r->sessionid = task->sessionid;
	r->argc = 0;
	r->pad = 0;
	r->exe_ino = 0;
	r->exe_dev = 0;
	r->exe_ctime = 0;
	exe = mm->exe_file;
	if (exe) {
		r->exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
		r->exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
		r->exe_ctime = BPF_CORE_READ(exe, f_inode, i_ctime_sec);
	}
	start = mm->arg_start;
	end = mm->arg_end;
	if (end > start) {
		argv_len = end - start;
		if (argv_len > ARGV_MAX_REC)
			argv_len = ARGV_MAX_REC;
		barrier_var(argv_len);
		if (bpf_copy_from_user_task(r->data, argv_len, (void *)start, task, 0))
			argv_len = 0;
	}
	r->path_len = 0;
	r->argv_len = argv_len;
	len = (sizeof(*r) + argv_len + 7) & ~7;
	r->h.len = len;
	r->h.type = REC_EXEC;
	r->h.flags = FLAG_SNAPSHOT;
	r->h.reserved = 0;
	r->h.jiffies = bpf_jiffies64();
	if (len > EXEC_MAX)
		return 0;
	bpf_seq_write(seq, r, len);
	return 0;
}

SEC("syscall")
int clock_now(void *ctx)
{
	clock_jiffies = bpf_jiffies64();
	return 0;
}
