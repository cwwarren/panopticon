// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CPUS 32
#define SPSC_SLOTS 65536

char LICENSE[] SEC("license") = "GPL";

struct event {
	__u64 ts;
	__u64 pid_tgid;
	__u64 pidfs_ino;
	__u64 cgroup_id;
	__u64 pad[4];
};

struct ctl {
	__u64 head;
	__u32 busy;
	__u32 pad_busy;
	__u64 pad0[6];
	__u64 tail;
	__u64 pad1[7];
	__u64 drops;
	__u64 pad2[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 << 20);
} rb_shared SEC(".maps");

struct rb_inner {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__array(values, struct rb_inner);
} rb_percpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} perf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, MAX_CPUS);
	__type(key, __u32);
	__type(value, struct ctl);
} spsc_ctl SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, MAX_CPUS * SPSC_SLOTS);
	__type(key, __u32);
	__type(value, struct event);
} spsc_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;

static __always_inline void fill_nots(struct event *e)
{
	struct task_struct *task = bpf_get_current_task_btf();

	e->pid_tgid = bpf_get_current_pid_tgid();
	e->pidfs_ino = task->group_leader->thread_pid->ino;
	e->cgroup_id = bpf_get_current_cgroup_id();
}

static __always_inline void fill(struct event *e)
{
	e->ts = bpf_ktime_get_boot_ns();
	fill_nots(e);
}

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &zero);

	if (d)
		*d += 1;
}

SEC("fentry")
int BPF_PROG(empty)
{
	return 0;
}

SEC("fentry")
int BPF_PROG(filter)
{
	__u64 key = bpf_get_current_cgroup_id() ^ bpf_get_current_pid_tgid();

	if (bpf_map_lookup_elem(&watched, &key))
		count_drop();
	return 0;
}

SEC("fentry")
int BPF_PROG(file_filter, struct file *file)
{
	struct inode *inode = file->f_inode;
	__u64 key = ((__u64)inode->i_sb->s_dev << 32) ^ inode->i_ino;

	if (bpf_map_lookup_elem(&watched, &key))
		count_drop();
	return 0;
}

SEC("fentry")
int BPF_PROG(context_nots)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);

	if (e)
		fill_nots(e);
	return 0;
}

SEC("fentry")
int BPF_PROG(context)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);

	if (e)
		fill(e);
	return 0;
}

SEC("fentry")
int BPF_PROG(context_jiffies)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&scratch, &zero);

	if (e) {
		e->ts = bpf_jiffies64();
		fill_nots(e);
	}
	return 0;
}

SEC("fentry")
int BPF_PROG(rb_shared_default)
{
	struct event *e = bpf_ringbuf_reserve(&rb_shared, sizeof(*e), 0);

	if (!e) {
		count_drop();
		return 0;
	}
	fill(e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry")
int BPF_PROG(rb_shared_out)
{
	struct event *e = bpf_ringbuf_reserve(&rb_shared, sizeof(*e), 0);

	if (!e) {
		count_drop();
		return 0;
	}
	fill(e);
	bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("fentry")
int BPF_PROG(rb_percpu_out)
{
	__u32 cpu = bpf_get_smp_processor_id();
	void *rb = bpf_map_lookup_elem(&rb_percpu, &cpu);
	struct event *e;

	if (!rb)
		return 0;
	e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill(e);
	bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("fentry")
int BPF_PROG(perf_out)
{
	struct event e = {};

	fill(&e);
	if (bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, &e, sizeof(e)) < 0)
		count_drop();
	return 0;
}

static __always_inline int spsc_emit(bool with_ts, bool busy)
{
	__u32 cpu = bpf_get_smp_processor_id();
	struct ctl *c = bpf_map_lookup_elem(&spsc_ctl, &cpu);
	struct event *e;
	__u64 head, tail;
	__u32 idx;

	if (!c)
		return 0;
	bpf_preempt_disable();
	if (busy && __sync_lock_test_and_set(&c->busy, 1)) {
		__sync_fetch_and_add(&c->drops, 1);
		bpf_preempt_enable();
		return 0;
	}
	head = c->head;
	tail = __atomic_load_n(&c->tail, __ATOMIC_ACQUIRE);
	if (head - tail >= SPSC_SLOTS) {
		c->drops += 1;
	} else {
		idx = cpu * SPSC_SLOTS + (__u32)(head & (SPSC_SLOTS - 1));
		e = bpf_map_lookup_elem(&spsc_data, &idx);
		if (e) {
			if (with_ts)
				fill(e);
			else
				fill_nots(e);
			__atomic_store_n(&c->head, head + 1, __ATOMIC_RELEASE);
		}
	}
	if (busy)
		__atomic_store_n(&c->busy, 0, __ATOMIC_RELEASE);
	bpf_preempt_enable();
	return 0;
}

SEC("fentry")
int BPF_PROG(spsc_out)
{
	return spsc_emit(true, false);
}

SEC("fentry")
int BPF_PROG(spsc_nots)
{
	return spsc_emit(false, false);
}

SEC("fentry")
int BPF_PROG(spsc_busy)
{
	return spsc_emit(false, true);
}
