// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum ring_class {
	CLASS_PROC,
	CLASS_NET,
	CLASS_FILE,
	CLASS_ADMIN,
	CLASS_NAT,
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
	REC_EXIT,
	REC_LOGIN,
	REC_ADMIN,
	REC_RAW_SOCKET,
	REC_UNIX_CONNECT,
	REC_NAT,
	REC_PATH,
	REC_BIND,
	REC_UNWATCH,
};

#define PROC_RING (256 << 10)
// Net's fastest one-CPU producers (a loopback connect loop, 29 MB/s, or a connect scan of off-host
// addresses, 27 MB/s, on the AL2023 VM) fill 256 KiB in 9 ms; 1 MiB holds 36 ms.
#define NET_RING (1 << 20)
#define FILE_RING (64 << 10)
#define ADMIN_RING (64 << 10)
#define NAT_RING (64 << 10)
#define PROC_SLACK 4096
#define NET_SLACK 2048
#define FILE_SLACK 512
#define ADMIN_SLACK 1024
#define NAT_SLACK 256

struct rec_hdr {
	__u16 len;
	__u8 type;
	__u8 flags;
	__u32 reserved;
	__u64 jiffies;
};

struct nat_rec {
	struct rec_hdr h;
	__u8 orig_src[16];
	__u8 orig_dst[16];
	__u8 reply_src[16];
	__u8 reply_dst[16];
	__u16 orig_sport;
	__u16 orig_dport;
	__u16 reply_sport;
	__u16 reply_dport;
	__u32 netns;
	__u8 family;
	__u8 proto;
	__u8 manip;
	__u8 pad;
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

struct ring_nat_value {
	__u8 data[NAT_RING + NAT_SLACK];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ring_nat_value);
} ring_nat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ctl);
} ctl SEC(".maps");

const volatile __u32 nr_cpus = 1;

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
	if (__sync_lock_test_and_set(&c->busy, 1)) {
		__sync_fetch_and_add(&c->drops, 1);
		return NULL;
	}
	head = c->head;
	tail = __atomic_load_n(&c->tail, __ATOMIC_ACQUIRE);
	if (head + max - tail > size) {
		__sync_fetch_and_add(&c->drops, 1);
		__atomic_store_n(&c->busy, 0, __ATOMIC_RELEASE);
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
	__atomic_store_n(&s->c->busy, 0, __ATOMIC_RELEASE);
}
