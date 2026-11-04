// SPDX-License-Identifier: GPL-2.0
#include "ring.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define AF_PACKET 17
#define DNS_PORT 53
#define PTRACE_MODE_ATTACH 0x02
#define NS_FLAGS (0x00000080 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x20000000 | 0x40000000)
#define IS_ERR_PTR(p) ((unsigned long)(p) >= (unsigned long)-4095)
#define ADMIN_STR 256
#define BPF_NAME 16
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define PATH_WALK 256
#define PATH_DEPTH 24
#define PATH_NAME 64
#define EXE_UPPER 1
#define STDIN_SOCK 2
#define SYSCTL_DEPTH 8
#define SYSCTL_NAME 64
#define SYSCTL_VALUE 256

enum rec_flag {
	FLAG_SNAPSHOT = 1,
	FLAG_TRUNCATED = 2,
	FLAG_SATURATED = 4,
};

enum admin_op {
	ADMIN_MODULE_FILE = 1,
	ADMIN_MODULE_DATA,
	ADMIN_KEXEC_FILE,
	ADMIN_KEXEC_DATA,
	ADMIN_BPF_LOAD,
	ADMIN_PTRACE,
	ADMIN_TRACEME,
	ADMIN_SETUID,
	ADMIN_SETGID,
	ADMIN_CAPSET,
	ADMIN_MOUNT,
	ADMIN_MOVE_MOUNT,
	ADMIN_UMOUNT,
	ADMIN_PIVOT_ROOT,
	ADMIN_SETTIME,
	ADMIN_SYSCTL,
	ADMIN_NS_CREATE,
	ADMIN_SETNS,
	ADMIN_USERNS,
	ADMIN_KILL,
	ADMIN_BPF_ACCESS,
	ADMIN_ANON_INODE,
};

enum limits {
	PATH_MAX_REC = 512,
	ARGV_MAX_REC = 1024,
	ARGV_MAX_ARGS = 32,
	CGROUP_PATH_MAX = 256,
	DNS_MAX = 512,
	NAME_MAX_REC = 255,
};

enum ring_class anchor_ring_class;
enum rec_type anchor_rec_type;
enum rec_flag anchor_rec_flag;
enum limits anchor_limits;
enum admin_op anchor_admin_op;

#define FS_IN_IGNORED 0x00008000

#define UDP_SEEN 4
#define UDP_CAP 16

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
	__u64 cwd_ino;
	__u32 exe_dev;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 egid;
	__u32 loginuid;
	__u32 sessionid;
	__u32 cwd_dev;
	__u32 argc;
	__u32 tty;
	__u32 exe_nlink;
	__u32 exe_magic;
	__u16 exe_mode;
	__u16 path_len;
	__u16 argv_len;
	__u16 exe_flags;
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
	__u16 pad;
	__s32 wd;
	__u8 name[];
};

struct file_repeat_rec {
	struct rec_hdr h;
	struct file_key k;
	__u64 count;
};

struct unwatch_rec {
	struct rec_hdr h;
	__s32 wd;
	__u32 pad;
};

struct exit_rec {
	struct rec_hdr h;
	struct actor a;
	__u64 start_boottime;
	__u64 cpu_ns;
	__u32 exit_code;
	__u32 pad;
};

struct login_rec {
	struct rec_hdr h;
	struct actor a;
	__u32 loginuid;
	__u32 sessionid;
};

struct admin_rec {
	struct rec_hdr h;
	struct actor a;
	__u64 arg[4];
	__u32 op;
	__u16 len0;
	__u16 len1;
	__u8 data[];
};

struct raw_rec {
	struct rec_hdr h;
	struct actor a;
	__u32 netns;
	__u16 family;
	__u16 type;
	__u32 protocol;
	__u32 pad;
};

struct unix_rec {
	struct rec_hdr h;
	struct actor a;
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

#define EXEC_MAX (sizeof(struct exec_rec) + PATH_MAX_REC + ARGV_MAX_REC)
#define CGROUP_MAX (sizeof(struct cgroup_rec) + CGROUP_PATH_MAX)
#define SOCK_MAX (sizeof(struct sock_rec) + DNS_MAX)
#define FILE_MAX (sizeof(struct file_rec) + NAME_MAX_REC)
#define ADMIN_MAX (sizeof(struct admin_rec) + 2 * ADMIN_STR)

struct exec_rec anchor_exec;
struct cgroup_rec anchor_cgroup;
struct sock_rec anchor_sock;
struct file_rec anchor_file;
struct file_repeat_rec anchor_file_repeat;
struct unwatch_rec anchor_unwatch;
struct exit_rec anchor_exit;
struct login_rec anchor_login;
struct admin_rec anchor_admin;
struct raw_rec anchor_raw;
struct unix_rec anchor_unix;
struct nat_rec anchor_nat;

struct path_rec {
	struct rec_hdr h;
	__u64 ino;
	__u32 dev;
	__u16 len;
	__u16 pad;
	__u8 path[];
};

struct path_rec anchor_path;

struct ovl_inode___pano {
	struct inode vfs_inode;
	struct dentry *__upperdentry;
} __attribute__((preserve_access_index));

/* The compressed-module ids are new in 6.19; older kernels read compressed modules as READING_MODULE
 * and lack both enumerators, so they are resolved by name at load time. */
enum kernel_read_file_id___pano { READING_MODULE_COMPRESSED___pano };
enum kernel_load_data_id___pano { LOADING_MODULE_COMPRESSED___pano };

struct ring_proc_value {
	__u8 data[PROC_RING + PROC_SLACK];
};

struct ring_net_value {
	__u8 data[NET_RING + NET_SLACK];
};

struct ring_file_value {
	__u8 data[FILE_RING + FILE_SLACK];
};

struct ring_admin_value {
	__u8 data[ADMIN_RING + ADMIN_SLACK];
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
	__type(value, struct ring_admin_value);
} ring_admin SEC(".maps");

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

#define FILE_DEAD ((__u64)-1)
#define FILE_GONE ((__u64)-2)
#define EEXIST 17

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, struct file_seen);
} file_seen SEC(".maps");

struct udp_dst {
	__u64 addr[2];
	__u16 port;
	__u16 pad[3];
};

struct udp_meta {
	struct udp_dst seen[UDP_SEEN];
	__u8 next;
	__u8 distinct;
	__u8 dns;
	__u8 pad[5];
};

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct inode_key);
	__type(value, __u8);
} unix_watch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct inode_key);
	__type(value, __u8);
} cwd_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} our_maps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} our_progs SEC(".maps");

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

const volatile __u32 agent_tgid = 0;
const volatile __u64 file_window = 1;
__u64 our_group;
__u64 clock_jiffies;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz) __ksym;
extern const void proc_dostring __ksym __weak;
extern const void proc_dostring_coredump __ksym __weak;
extern const void proc_dobool __ksym __weak;
extern const void proc_dointvec __ksym __weak;
extern const void proc_dointvec_minmax __ksym __weak;
extern const void proc_dointvec_jiffies __ksym __weak;
extern const void proc_dointvec_ms_jiffies __ksym __weak;
extern const void proc_dointvec_userhz_jiffies __ksym __weak;
extern const void proc_dointvec_minmax_sysadmin __ksym __weak;
extern const void proc_dointvec_minmax_coredump __ksym __weak;
extern const void proc_dointvec_minmax_bpf_enable __ksym __weak;
extern const void proc_dointvec_minmax_bpf_restricted __ksym __weak;
extern const void proc_douintvec __ksym __weak;
extern const void proc_douintvec_minmax __ksym __weak;
extern const void proc_dou8vec_minmax __ksym __weak;
extern const void proc_doulongvec_minmax __ksym __weak;
extern const void proc_doulongvec_ms_jiffies_minmax __ksym __weak;
extern const void yama_dointvec_minmax __ksym __weak;
extern const void bpf_unpriv_handler __ksym __weak;
extern const void mmap_min_addr_handler __ksym __weak;
extern const void devinet_sysctl_forward __ksym __weak;
extern const void devinet_conf_proc __ksym __weak;
extern const void ipv4_doint_and_flush __ksym __weak;
extern const void addrconf_sysctl_forward __ksym __weak;
extern const void addrconf_sysctl_disable __ksym __weak;

static __always_inline bool value_handler(const void *h)
{
	return h && (h == &proc_dostring || h == &proc_dostring_coredump || h == &proc_dobool ||
		     h == &proc_dointvec || h == &proc_dointvec_minmax || h == &proc_dointvec_jiffies ||
		     h == &proc_dointvec_ms_jiffies || h == &proc_dointvec_userhz_jiffies ||
		     h == &proc_dointvec_minmax_sysadmin || h == &proc_dointvec_minmax_coredump ||
		     h == &proc_dointvec_minmax_bpf_enable || h == &proc_dointvec_minmax_bpf_restricted ||
		     h == &proc_douintvec || h == &proc_douintvec_minmax || h == &proc_dou8vec_minmax ||
		     h == &proc_doulongvec_minmax || h == &proc_doulongvec_ms_jiffies_minmax ||
		     h == &yama_dointvec_minmax || h == &bpf_unpriv_handler || h == &mmap_min_addr_handler ||
		     h == &devinet_sysctl_forward || h == &devinet_conf_proc || h == &ipv4_doint_and_flush ||
		     h == &addrconf_sysctl_forward || h == &addrconf_sysctl_disable);
}

static __always_inline void fill_actor(struct actor *a)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *leader;
	struct task_meta *m;
	__u64 proc, seq;

	bpf_rcu_read_lock();
	leader = bpf_get_current_task_btf()->group_leader;
	proc = leader->thread_pid->ino;
	seq = leader->self_exec_id;
	m = bpf_task_storage_get(&task_meta, leader, 0, 0);
	if (m && m->image_proc) {
		a->image_proc = m->image_proc;
		a->image_seq = m->image_seq;
	} else {
		a->image_proc = proc;
		a->image_seq = seq;
	}
	bpf_rcu_read_unlock();
	a->proc = proc;
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

static __always_inline __u16 exe_flags(struct task_struct *task, struct inode *inode)
{
	struct file **fds = BPF_CORE_READ(task, files, fdt, fd);
	__u16 flags = 0;

	if (bpf_core_type_exists(struct ovl_inode___pano) &&
	    BPF_CORE_READ(inode, i_sb, s_magic) == OVERLAYFS_SUPER_MAGIC) {
		long delta = bpf_core_field_offset(struct ovl_inode___pano, __upperdentry) -
			     bpf_core_field_offset(struct ovl_inode___pano, vfs_inode);
		void *upper = NULL;

		bpf_probe_read_kernel(&upper, sizeof(upper), (void *)((unsigned long)inode + delta));
		if (upper)
			flags |= EXE_UPPER;
	}
	for (int i = 0; i < 3; i++) {
		struct file *f = NULL;

		bpf_probe_read_kernel(&f, sizeof(f), &fds[i]);
		if (f && (BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT) == S_IFSOCK)
			flags |= STDIN_SOCK << i;
	}
	return flags;
}

static __always_inline void emit_path(__u32 dev, __u64 ino, struct dentry *d, struct vfsmount *vmnt)
{
	struct inode_key k = { .ino = ino, .dev = dev };
	struct mount *mnt = (void *)((unsigned long)vmnt - bpf_core_field_offset(struct mount, mnt));
	struct path_rec *r;
	struct ring_slot s;
	__u32 pos = 0;
	__u8 one = 1;
	long n;

	if (!ino || bpf_map_lookup_elem(&cwd_seen, &k))
		return;
	bpf_map_update_elem(&cwd_seen, &k, &one, BPF_ANY);
	r = reserve(&ring_proc, CLASS_PROC, PROC_RING, sizeof(*r) + PATH_WALK, &s);
	if (!r)
		return;
	for (int i = 0; i < PATH_DEPTH; i++) {
		struct dentry *root = BPF_CORE_READ(mnt, mnt.mnt_root);
		struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);

		if (d == root) {
			if (parent == mnt)
				break;
			d = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = parent;
			continue;
		}
		if (pos >= PATH_WALK - PATH_NAME)
			break;
		n = bpf_probe_read_kernel_str(r->path + (pos & (PATH_WALK - 1)), PATH_NAME, BPF_CORE_READ(d, d_name.name));
		if (n <= 0)
			break;
		pos += n;
		d = BPF_CORE_READ(d, d_parent);
	}
	r->ino = ino;
	r->dev = dev;
	r->len = pos;
	r->pad = 0;
	commit(&s, &r->h, sizeof(*r) + pos, REC_PATH, 0);
}

static __always_inline __u32 tty_dev(struct task_struct *task)
{
	struct tty_struct *tty = BPF_CORE_READ(task, signal, tty);

	if (!tty)
		return 0;
	return (BPF_CORE_READ(tty, driver, major) << 20) |
	       (BPF_CORE_READ(tty, driver, minor_start) + BPF_CORE_READ(tty, index));
}

static __always_inline struct admin_rec *admin_begin(struct ring_slot *s, __u32 op)
{
	struct admin_rec *r = reserve(&ring_admin, CLASS_ADMIN, ADMIN_RING, ADMIN_MAX, s);

	if (r) {
		fill_actor(&r->a);
		__builtin_memset(r->arg, 0, sizeof(r->arg));
		r->op = op;
	}
	return r;
}

static __always_inline void admin_commit(struct ring_slot *s, struct admin_rec *r, __u32 len0, __u32 len1)
{
	r->len0 = len0;
	r->len1 = len1;
	commit(s, &r->h, sizeof(*r) + len0 + len1, REC_ADMIN, 0);
}

static __always_inline void admin_emit(__u32 op, __u64 a0, __u64 a1, __u64 a2, __u64 a3)
{
	struct admin_rec *r;
	struct ring_slot s;

	bpf_preempt_disable();
	r = admin_begin(&s, op);
	if (r) {
		r->arg[0] = a0;
		r->arg[1] = a1;
		r->arg[2] = a2;
		r->arg[3] = a3;
		admin_commit(&s, r, 0, 0);
	}
	bpf_preempt_enable();
}

static __always_inline void admin_paths(__u32 op, const struct path *p0, const struct path *p1)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 len0 = 0, len1 = 0;
	long n;

	bpf_preempt_disable();
	r = admin_begin(&s, op);
	if (r) {
		n = bpf_path_d_path(p0, (char *)r->data, ADMIN_STR);
		if (n > 1)
			len0 = (n - 1) & (ADMIN_STR - 1);
		n = bpf_path_d_path(p1, (char *)r->data + len0, ADMIN_STR);
		if (n > 1)
			len1 = (n - 1) & (ADMIN_STR - 1);
		admin_commit(&s, r, len0, len1);
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
	struct path pwd;
	__u64 cwd_ino;
	__u32 cwd_dev;
	struct task_meta *m;
	struct exec_rec *r;
	struct ring_slot s;
	char *argv;
	long n;

	BPF_CORE_READ_INTO(&pwd, task, fs, pwd);
	cwd_ino = BPF_CORE_READ(pwd.dentry, d_inode, i_ino);
	cwd_dev = BPF_CORE_READ(pwd.dentry, d_inode, i_sb, s_dev);
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
		r->cwd_ino = cwd_ino;
		r->cwd_dev = cwd_dev;
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
		r->tty = tty_dev(task);
		r->exe_nlink = inode->i_nlink;
		r->exe_magic = inode->i_sb->s_magic;
		r->exe_mode = inode->i_mode;
		r->exe_flags = exe_flags(task, inode);

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
		emit_path(cwd_dev, cwd_ino, pwd.dentry, pwd.mnt);
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

SEC("fexit/inet_bind")
int BPF_PROG(on_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (!ret && sock->type == SOCK_DGRAM)
		emit_sock(sock->sk, REC_BIND);
	return 0;
}

SEC("fexit/inet6_bind")
int BPF_PROG(on_bind6, struct socket *sock, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (!ret && sock->type == SOCK_DGRAM)
		emit_sock(sock->sk, REC_BIND);
	return 0;
}

SEC("fexit/inet_listen")
int BPF_PROG(on_listen, struct socket *sock, int backlog, int ret)
{
	if (!ret)
		emit_sock(sock->sk, REC_LISTEN);
	return 0;
}

static __always_inline bool udp_seen(struct udp_meta *m, const __u64 *addr, __u16 port)
{
	for (int i = 0; i < UDP_SEEN; i++)
		if (m->seen[i].addr[0] == addr[0] && m->seen[i].addr[1] == addr[1] && m->seen[i].port == port)
			return true;
	return false;
}

static __always_inline void udp_emit(struct sk_buff *skb, __u8 family, const __u64 *saddr, const __u64 *daddr,
				     __u16 port)
{
	struct sock *sk = skb->sk;
	bool dns = port == bpf_htons(DNS_PORT), seen;
	struct udp_meta *m;
	struct sock_rec *r;
	struct ring_slot s;
	__u8 flags = 0, slot;
	__u32 plen = 0, off = 0;
	__u64 head;

	m = bpf_sk_storage_get(&udp_meta, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!m)
		return;
	seen = udp_seen(m, daddr, port);
	if (!dns && (seen || m->distinct >= UDP_CAP))
		return;
	if (!seen) {
		slot = m->next & (UDP_SEEN - 1);
		m->seen[slot].addr[0] = daddr[0];
		m->seen[slot].addr[1] = daddr[1];
		m->seen[slot].port = port;
		m->next = slot + 1;
		if (m->distinct < UDP_CAP && ++m->distinct == UDP_CAP)
			flags |= FLAG_SATURATED;
	}
	if (dns) {
		m->dns = 1;
		off = skb->transport_header + sizeof(struct udphdr);
		if (skb->tail > off)
			plen = skb->tail - off;
		if (plen > DNS_MAX)
			plen = DNS_MAX;
	}

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, SOCK_MAX, &s);
	if (r) {
		fill_sock(r, sk);
		r->family = family;
		__builtin_memcpy(r->saddr, saddr, 16);
		__builtin_memcpy(r->daddr, daddr, 16);
		r->dport = bpf_ntohs(port);
		barrier_var(plen);
		if (plen && (bpf_core_read(&head, sizeof(head), &skb->head) ||
			     bpf_probe_read_kernel(r->payload, plen, (void *)(head + off))))
			plen = 0;
		r->payload_len = plen;
		commit(&s, &r->h, sizeof(*r) + plen, dns ? REC_DNS_QUERY : REC_UDP_SEND, flags);
	}
	bpf_preempt_enable();
}

SEC("fentry/udp_send_skb")
int BPF_PROG(on_udp_send, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
{
	__u64 saddr[2] = { fl4->saddr }, daddr[2] = { fl4->daddr };

	udp_emit(skb, AF_INET, saddr, daddr, fl4->uli.ports.dport);
	return 0;
}

SEC("fentry/udp_v6_send_skb")
int BPF_PROG(on_udp6_send, struct sk_buff *skb, struct flowi6 *fl6, struct inet_cork *cork)
{
	__u64 saddr[2], daddr[2];

	__builtin_memcpy(saddr, &fl6->saddr, sizeof(saddr));
	__builtin_memcpy(daddr, &fl6->daddr, sizeof(daddr));
	udp_emit(skb, AF_INET6, saddr, daddr, fl6->uli.ports.dport);
	return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(on_udp_consume, struct sock *sk, struct sk_buff *skb, int len)
{
	struct udp_meta *m = bpf_sk_storage_get(&udp_meta, sk, 0, 0);
	struct ipv6hdr ip6 = {};
	struct iphdr ip = {};
	unsigned char *head, *nh;
	struct udphdr udp;
	struct sock_rec *r;
	struct ring_slot s;
	__u8 version;
	__u32 plen;

	if (!m || !m->dns || len <= 0)
		return 0;
	head = skb->head;
	nh = head + skb->network_header;
	if (bpf_probe_read_kernel(&version, 1, nh))
		return 0;
	version >>= 4;
	if (version == 4) {
		if (bpf_probe_read_kernel(&ip, sizeof(ip), nh))
			return 0;
	} else if (version == 6) {
		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), nh))
			return 0;
	} else {
		return 0;
	}
	if (bpf_probe_read_kernel(&udp, sizeof(udp), head + skb->transport_header))
		return 0;
	plen = bpf_ntohs(udp.len) - sizeof(udp);

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, SOCK_MAX, &s);
	if (r) {
		fill_sock(r, sk);
		__builtin_memset(r->saddr, 0, 16);
		__builtin_memset(r->daddr, 0, 16);
		if (version == 4) {
			r->family = AF_INET;
			*(__u32 *)r->saddr = ip.daddr;
			*(__u32 *)r->daddr = ip.saddr;
		} else {
			r->family = AF_INET6;
			__builtin_memcpy(r->saddr, &ip6.daddr, 16);
			__builtin_memcpy(r->daddr, &ip6.saddr, 16);
		}
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

static __always_inline void emit_raw(__u16 family, __u16 type, __u32 protocol, __u32 netns)
{
	struct raw_rec *r;
	struct ring_slot s;

	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, sizeof(*r), &s);
	if (r) {
		fill_actor(&r->a);
		r->netns = netns;
		r->family = family;
		r->type = type;
		r->protocol = protocol;
		r->pad = 0;
		commit(&s, &r->h, sizeof(*r), REC_RAW_SOCKET, 0);
	}
	bpf_preempt_enable();
}

SEC("fexit/packet_create")
int BPF_PROG(on_packet_create, struct net *net, struct socket *sock, int protocol, int kern, int ret)
{
	if (!ret && !kern)
		emit_raw(AF_PACKET, sock->type, bpf_ntohs(protocol), net->ns.inum);
	return 0;
}

SEC("fexit/raw_sk_init")
int BPF_PROG(on_raw_init, struct sock *sk, int ret)
{
	if (!ret && !BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock))
		emit_raw(AF_INET, SOCK_RAW, sk->sk_protocol, sk->__sk_common.skc_net.net->ns.inum);
	return 0;
}

SEC("fexit/rawv6_init_sk")
int BPF_PROG(on_raw6_init, struct sock *sk, int ret)
{
	if (!ret && !BPF_CORE_READ_BITFIELD_PROBED(sk, sk_kern_sock))
		emit_raw(AF_INET6, SOCK_RAW, sk->sk_protocol, sk->__sk_common.skc_net.net->ns.inum);
	return 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(on_unix_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
	struct unix_sock *u = bpf_core_cast(other, struct unix_sock);
	struct inode *inode = u->path.dentry->d_inode;
	struct inode_key k = {};
	struct unix_rec *r;
	struct ring_slot s;

	k.ino = inode->i_ino;
	k.dev = inode->i_sb->s_dev;
	if (!k.ino || !bpf_map_lookup_elem(&unix_watch, &k))
		return 0;
	bpf_preempt_disable();
	r = reserve(&ring_net, CLASS_NET, NET_RING, sizeof(*r), &s);
	if (r) {
		fill_actor(&r->a);
		r->ino = k.ino;
		r->dev = k.dev;
		r->pad = 0;
		commit(&s, &r->h, sizeof(*r), REC_UNIX_CONNECT, 0);
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
	struct file_repeat_rec *rr;
	struct file_key k = {};
	struct unwatch_rec *u;
	struct file_rec *r;
	struct ring_slot s;
	__u64 now, j, n;
	__u32 len = 0;
	__u8 flags = 0;
	__s32 wd;

	if (!our_group || (__u64)mark->group != our_group)
		return 0;
	wd = bpf_core_cast(mark, struct inotify_inode_mark)->wd;
	if (mask & FS_IN_IGNORED) {
		bpf_preempt_disable();
		u = reserve(&ring_file, CLASS_FILE, FILE_RING, sizeof(*u), &s);
		if (u) {
			u->wd = wd;
			u->pad = 0;
			commit(&s, &u->h, sizeof(*u), REC_UNWATCH, 0);
		}
		bpf_preempt_enable();
		return 0;
	}
	if ((bpf_get_current_pid_tgid() >> 32) == agent_tgid)
		return 0;
	leader = bpf_get_current_task_btf()->group_leader;
	now = bpf_jiffies64();
	k.proc = leader->thread_pid->ino;
	k.seq = leader->self_exec_id;
	k.ino = obj->i_ino;
	k.child_ino = inode->i_ino;
	k.dev = obj->i_sb->s_dev;
	k.mask = mask;
	bpf_preempt_disable();
	seen = bpf_map_lookup_elem(&file_seen, &k);
	if (seen) {
		j = *(volatile __u64 *)&seen->jiffies;
		if (j < FILE_GONE && (__s64)(now - j) < (__s64)file_window) {
			n = __sync_fetch_and_add(&seen->repeats, 1);
			barrier_var(n);
			if (*(volatile __u64 *)&seen->jiffies >= FILE_GONE &&
			    (n = __sync_lock_test_and_set(&seen->repeats, 0))) {
				rr = reserve(&ring_file, CLASS_FILE, FILE_RING, sizeof(*rr), &s);
				if (rr) {
					rr->k = k;
					rr->count = n;
					commit(&s, &rr->h, sizeof(*rr), REC_FILE_REPEAT, 0);
				}
			}
			bpf_preempt_enable();
			return 0;
		}
		if (j != FILE_GONE)
			__sync_val_compare_and_swap(&seen->jiffies, j, now);
	} else {
		fresh.jiffies = now;
		n = bpf_map_update_elem(&file_seen, &k, &fresh, BPF_NOEXIST);
		if (n && n != -EEXIST)
			flags = FLAG_SATURATED;
	}

	r = reserve(&ring_file, CLASS_FILE, FILE_RING, FILE_MAX, &s);
	if (r) {
		fill_actor(&r->a);
		r->k = k;
		r->pad = 0;
		r->wd = wd;
		if (name) {
			len = name->len;
			if (len > NAME_MAX_REC)
				len = NAME_MAX_REC;
			barrier_var(len);
			if (bpf_probe_read_kernel(r->name, len, name->name))
				len = 0;
		}
		r->name_len = len;
		commit(&s, &r->h, sizeof(*r) + len, REC_FILE, flags);
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
	__u64 now = bpf_jiffies64(), j;
	bool gone;

	if (!k || !v)
		return 0;
	r.k = *k;
	j = *(volatile __u64 *)&v->jiffies;
	gone = j == FILE_GONE ||
	       (j == FILE_DEAD && __sync_val_compare_and_swap(&v->jiffies, FILE_DEAD, FILE_GONE) == FILE_DEAD);
	if (!gone && j < FILE_GONE && (__s64)(now - j) >= (__s64)file_window)
		__sync_val_compare_and_swap(&v->jiffies, j, FILE_DEAD);
	r.count = __sync_lock_test_and_set(&v->repeats, 0);
	if (r.count) {
		r.h.len = sizeof(r);
		r.h.type = REC_FILE_REPEAT;
		r.h.jiffies = now;
		bpf_seq_write(ctx->meta->seq, &r, sizeof(r));
	}
	if (gone)
		bpf_map_delete_elem(&file_seen, &r.k);
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
	r->cwd_ino = BPF_CORE_READ(task, fs, pwd.dentry, d_inode, i_ino);
	r->cwd_dev = BPF_CORE_READ(task, fs, pwd.dentry, d_inode, i_sb, s_dev);
	r->pid = task->tgid;
	r->ppid = BPF_CORE_READ(task, real_parent, tgid);
	r->uid = BPF_CORE_READ(task, cred, uid.val);
	r->euid = BPF_CORE_READ(task, cred, euid.val);
	r->gid = BPF_CORE_READ(task, cred, gid.val);
	r->egid = BPF_CORE_READ(task, cred, egid.val);
	r->loginuid = task->loginuid.val;
	r->sessionid = task->sessionid;
	r->argc = 0;
	r->tty = tty_dev(task);
	r->exe_nlink = 0;
	r->exe_magic = 0;
	r->exe_mode = 0;
	r->exe_flags = 0;
	r->exe_ino = 0;
	r->exe_dev = 0;
	r->exe_ctime = 0;
	exe = mm->exe_file;
	if (exe) {
		r->exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
		r->exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
		r->exe_ctime = BPF_CORE_READ(exe, f_inode, i_ctime_sec);
		r->exe_nlink = BPF_CORE_READ(exe, f_inode, i_nlink);
		r->exe_magic = BPF_CORE_READ(exe, f_inode, i_sb, s_magic);
		r->exe_mode = BPF_CORE_READ(exe, f_inode, i_mode);
		r->exe_flags = exe_flags(task, BPF_CORE_READ(exe, f_inode));
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

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *task, bool group_dead)
{
	struct signal_struct *sig = task->signal;
	struct exit_rec *r;
	struct ring_slot s;

	if (!group_dead)
		return 0;
	bpf_preempt_disable();
	r = reserve(&ring_proc, CLASS_PROC, PROC_RING, sizeof(*r), &s);
	if (r) {
		fill_actor(&r->a);
		r->start_boottime = task->group_leader->start_boottime;
		r->cpu_ns = sig->utime + sig->stime + task->utime + task->stime;
		r->exit_code = task->exit_code;
		r->pad = 0;
		commit(&s, &r->h, sizeof(*r), REC_EXIT, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("fexit/audit_set_loginuid")
int BPF_PROG(on_login, __u32 loginuid, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct login_rec *r;
	struct ring_slot s;

	if (ret)
		return 0;
	bpf_preempt_disable();
	r = reserve(&ring_proc, CLASS_PROC, PROC_RING, sizeof(*r), &s);
	if (r) {
		fill_actor(&r->a);
		r->loginuid = task->loginuid.val;
		r->sessionid = task->sessionid;
		commit(&s, &r->h, sizeof(*r), REC_LOGIN, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm.s/kernel_read_file")
int BPF_PROG(on_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 op, len = 0;
	long n;

	if (id == READING_MODULE ||
	    (bpf_core_enum_value_exists(enum kernel_read_file_id___pano, READING_MODULE_COMPRESSED___pano) &&
	     id == bpf_core_enum_value(enum kernel_read_file_id___pano, READING_MODULE_COMPRESSED___pano)))
		op = ADMIN_MODULE_FILE;
	else if (id == READING_KEXEC_IMAGE || id == READING_KEXEC_INITRAMFS)
		op = ADMIN_KEXEC_FILE;
	else
		return 0;
	bpf_preempt_disable();
	r = admin_begin(&s, op);
	if (r) {
		r->arg[0] = file->f_inode->i_sb->s_dev;
		r->arg[1] = file->f_inode->i_ino;
		n = bpf_d_path(&file->f_path, (char *)r->data, ADMIN_STR);
		if (n > 1)
			len = (n - 1) & (ADMIN_STR - 1);
		admin_commit(&s, r, len, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm/kernel_load_data")
int BPF_PROG(on_kernel_load_data, enum kernel_load_data_id id, bool contents)
{
	if (id == LOADING_MODULE ||
	    (bpf_core_enum_value_exists(enum kernel_load_data_id___pano, LOADING_MODULE_COMPRESSED___pano) &&
	     id == bpf_core_enum_value(enum kernel_load_data_id___pano, LOADING_MODULE_COMPRESSED___pano)))
		admin_emit(ADMIN_MODULE_DATA, 0, 0, 0, 0);
	else if (id == LOADING_KEXEC_IMAGE || id == LOADING_KEXEC_INITRAMFS)
		admin_emit(ADMIN_KEXEC_DATA, 0, 0, 0, 0);
	return 0;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(on_bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr, struct bpf_token *token, bool kernel)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 len = 0;
	long n;

	if (kernel)
		return 0;
	bpf_preempt_disable();
	r = admin_begin(&s, ADMIN_BPF_LOAD);
	if (r) {
		r->arg[0] = prog->type;
		r->arg[1] = prog->expected_attach_type;
		r->arg[2] = prog->len;
		r->arg[3] = prog->aux->attach_btf_id;
		n = bpf_probe_read_kernel_str(r->data, BPF_NAME, prog->aux->name);
		if (n > 1)
			len = (n - 1) & (BPF_NAME - 1);
		admin_commit(&s, r, len, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(on_ptrace_access, struct task_struct *child, unsigned int mode)
{
	if (mode & PTRACE_MODE_ATTACH)
		admin_emit(ADMIN_PTRACE, child->group_leader->thread_pid->ino, child->tgid, mode, 0);
	return 0;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(on_ptrace_traceme, struct task_struct *parent)
{
	admin_emit(ADMIN_TRACEME, parent->group_leader->thread_pid->ino, parent->tgid, 0, 0);
	return 0;
}

static __always_inline bool gains_root(__u32 old, __u32 new)
{
	return old != 0 && new == 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(on_setuid, struct cred *new, const struct cred *old, int flags)
{
	__u32 ou = old->uid.val, oe = old->euid.val, os = old->suid.val, of = old->fsuid.val;
	__u32 nu = new->uid.val, ne = new->euid.val, ns = new->suid.val, nf = new->fsuid.val;

	if (nu != ou || gains_root(oe, ne) || gains_root(os, ns) || gains_root(of, nf))
		admin_emit(ADMIN_SETUID, ou | (__u64)oe << 32, nu | (__u64)ne << 32, os | (__u64)of << 32,
			   ns | (__u64)nf << 32);
	return 0;
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(on_setgid, struct cred *new, const struct cred *old, int flags)
{
	__u32 og = old->gid.val, oe = old->egid.val, os = old->sgid.val, of = old->fsgid.val;
	__u32 ng = new->gid.val, ne = new->egid.val, ns = new->sgid.val, nf = new->fsgid.val;

	if (ng != og || gains_root(oe, ne) || gains_root(os, ns) || gains_root(of, nf))
		admin_emit(ADMIN_SETGID, og | (__u64)oe << 32, ng | (__u64)ne << 32, os | (__u64)of << 32,
			   ns | (__u64)nf << 32);
	return 0;
}

SEC("lsm/capset")
int BPF_PROG(on_capset, struct cred *new, const struct cred *old, const kernel_cap_t *effective,
	     const kernel_cap_t *inheritable, const kernel_cap_t *permitted)
{
	__u64 oe = old->cap_effective.val, ne = effective->val, np = permitted->val, ni = inheritable->val;

	if (oe != ne || old->cap_permitted.val != np || old->cap_inheritable.val != ni)
		admin_emit(ADMIN_CAPSET, oe, ne, np, ni);
	return 0;
}

SEC("lsm.s/sb_mount")
int BPF_PROG(on_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags,
	     void *data)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 len0 = 0, len1 = 0;
	long n;

	bpf_preempt_disable();
	r = admin_begin(&s, ADMIN_MOUNT);
	if (r) {
		r->arg[0] = flags;
		if (type)
			bpf_probe_read_kernel_str(&r->arg[1], 2 * sizeof(r->arg[1]), type);
		n = bpf_d_path((struct path *)path, (char *)r->data, ADMIN_STR);
		if (n > 1)
			len0 = (n - 1) & (ADMIN_STR - 1);
		if (dev_name) {
			n = bpf_probe_read_kernel_str(r->data + len0, ADMIN_STR, dev_name);
			if (n > 1)
				len1 = (n - 1) & (ADMIN_STR - 1);
		}
		admin_commit(&s, r, len0, len1);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm/move_mount")
int BPF_PROG(on_move_mount, const struct path *from_path, const struct path *to_path)
{
	admin_paths(ADMIN_MOVE_MOUNT, to_path, from_path);
	return 0;
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(on_pivot_root, const struct path *old_path, const struct path *new_path)
{
	admin_paths(ADMIN_PIVOT_ROOT, new_path, old_path);
	return 0;
}

SEC("lsm/sb_umount")
int BPF_PROG(on_umount, struct vfsmount *mnt, int flags)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 len = 0;
	long n;

	bpf_preempt_disable();
	r = admin_begin(&s, ADMIN_UMOUNT);
	if (r) {
		r->arg[0] = flags;
		r->arg[1] = mnt->mnt_sb->s_dev;
		n = bpf_probe_read_kernel_str(r->data, ADMIN_STR, mnt->mnt_sb->s_type->name);
		if (n > 1)
			len = (n - 1) & (ADMIN_STR - 1);
		admin_commit(&s, r, len, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm/settime")
int BPF_PROG(on_settime, const struct timespec64 *ts, const struct timezone *tz)
{
	if (ts)
		admin_emit(ADMIN_SETTIME, ts->tv_sec, ts->tv_nsec, 0, 0);
	return 0;
}

SEC("fexit/proc_sys_write")
int BPF_PROG(on_sysctl_write, struct kiocb *iocb, struct iov_iter *iter, ssize_t ret)
{
	struct file *f = iocb->ki_filp;
	struct dentry *d = f->f_path.dentry;
	const struct ctl_table *table;
	struct proc_inode *pi;
	struct admin_rec *r;
	struct ring_slot s;
	__u32 pos = 0, vlen = 0;
	__u64 inode;
	long n;
	int maxlen;

	if (bpf_core_read(&inode, sizeof(inode), &f->f_inode))
		return 0;
	pi = bpf_core_cast((void *)(inode - bpf_core_field_offset(struct proc_inode, vfs_inode)), struct proc_inode);
	table = pi->sysctl_entry;
	maxlen = table->maxlen;
	bpf_preempt_disable();
	r = admin_begin(&s, ADMIN_SYSCTL);
	if (r) {
		for (int i = 0; i < SYSCTL_DEPTH; i++) {
			struct dentry *parent = d->d_parent;

			if (parent == d || pos >= ADMIN_STR - SYSCTL_NAME)
				break;
			n = bpf_probe_read_kernel_str(r->data + (pos & (ADMIN_STR - 1)), SYSCTL_NAME, d->d_name.name);
			if (n <= 0)
				break;
			pos += n;
			d = parent;
		}
		pos &= ADMIN_STR - 1;
		r->arg[0] = ret;
		r->arg[1] = maxlen;
		if (maxlen > 0 && value_handler(table->proc_handler))
			vlen = maxlen;
		if (vlen > SYSCTL_VALUE)
			vlen = SYSCTL_VALUE;
		barrier_var(vlen);
		if (vlen && bpf_probe_read_kernel(r->data + pos, vlen, table->data))
			vlen = 0;
		admin_commit(&s, r, pos, vlen);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("fexit/create_new_namespaces")
int BPF_PROG(on_ns_create, __u64 flags, struct task_struct *tsk, struct user_namespace *user_ns,
	     struct fs_struct *new_fs, struct nsproxy *ret)
{
	if ((flags & NS_FLAGS) && !IS_ERR_PTR(ret))
		admin_emit(ADMIN_NS_CREATE, flags & NS_FLAGS, tsk != bpf_get_current_task_btf(), ret->net_ns->ns.inum,
			   ret->mnt_ns->ns.inum);
	return 0;
}

#define NS_INSTALL(fn, flag)                                                         \
	SEC("fexit/" #fn)                                                            \
	int BPF_PROG(on_##fn, struct nsset *nsset, struct ns_common *ns, int ret)    \
	{                                                                            \
		if (!ret)                                                            \
			admin_emit(ADMIN_SETNS, flag, ns->inum, 0, 0);               \
		return 0;                                                            \
	}

NS_INSTALL(cgroupns_install, 0x02000000)
NS_INSTALL(ipcns_install, 0x08000000)
NS_INSTALL(mntns_install, 0x00020000)
NS_INSTALL(netns_install, 0x40000000)
NS_INSTALL(pidns_install, 0x20000000)
NS_INSTALL(timens_install, 0x00000080)
NS_INSTALL(userns_install, 0x10000000)
NS_INSTALL(utsns_install, 0x04000000)

#define KILL_SIGNALS ((1ULL << 1) | (1ULL << 2) | (1ULL << 3) | (1ULL << 9) | (1ULL << 15) | (1ULL << 19))

SEC("lsm/task_kill")
int BPF_PROG(on_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	if (sig > 0 && sig < 64 && (KILL_SIGNALS & (1ULL << sig)) &&
	    p->tgid != (bpf_get_current_pid_tgid() >> 32))
		admin_emit(ADMIN_KILL, p->group_leader->thread_pid->ino, p->tgid, sig, 0);
	return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(on_bpf_map, struct bpf_map *map, unsigned int fmode)
{
	__u32 id = map->id;

	if ((bpf_get_current_pid_tgid() >> 32) != agent_tgid && bpf_map_lookup_elem(&our_maps, &id))
		admin_emit(ADMIN_BPF_ACCESS, 0, id, fmode, 0);
	return 0;
}

SEC("lsm/bpf_prog")
int BPF_PROG(on_bpf_prog, struct bpf_prog *prog)
{
	__u32 id = prog->aux->id;

	if ((bpf_get_current_pid_tgid() >> 32) != agent_tgid && bpf_map_lookup_elem(&our_progs, &id))
		admin_emit(ADMIN_BPF_ACCESS, 1, id, 0, 0);
	return 0;
}

SEC("lsm/inode_init_security_anon")
int BPF_PROG(on_anon_inode, struct inode *inode, const struct qstr *name, const struct inode *context_inode)
{
	struct admin_rec *r;
	struct ring_slot s;
	__u32 len = 0;
	long n;

	bpf_preempt_disable();
	r = admin_begin(&s, ADMIN_ANON_INODE);
	if (r) {
		n = bpf_probe_read_kernel_str(r->data, PATH_NAME, name->name);
		if (n > 1)
			len = (n - 1) & (PATH_NAME - 1);
		admin_commit(&s, r, len, 0);
	}
	bpf_preempt_enable();
	return 0;
}

SEC("lsm/userns_create")
int BPF_PROG(on_userns_create, const struct cred *cred)
{
	admin_emit(ADMIN_USERNS, cred->euid.val, 0, 0, 0);
	return 0;
}
