// SPDX-License-Identifier: GPL-2.0
#include "ring.h"

char LICENSE[] SEC("license") = "GPL";

#define IPS_SRC_NAT 0x10
#define IPS_DST_NAT 0x20
#define NFCT_PTRMASK (~7UL)

SEC("fentry/__nf_conntrack_confirm")
int BPF_PROG(on_nat, struct sk_buff *skb)
{
	struct nf_conn *ct = (void *)(skb->_nfct & NFCT_PTRMASK);
	struct nf_conntrack_tuple o, p;
	struct nat_rec *r;
	struct ring_slot s;
	unsigned long status;

	if (!ct)
		return 0;
	status = BPF_CORE_READ(ct, status);
	if (!(status & (IPS_SRC_NAT | IPS_DST_NAT)))
		return 0;
	if (bpf_core_read(&o, sizeof(o), &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple) ||
	    bpf_core_read(&p, sizeof(p), &ct->tuplehash[IP_CT_DIR_REPLY].tuple))
		return 0;
	bpf_preempt_disable();
	r = reserve(&ring_nat, CLASS_NAT, NAT_RING, sizeof(*r), &s);
	if (r) {
		__builtin_memcpy(r->orig_src, &o.src.u3, 16);
		__builtin_memcpy(r->orig_dst, &o.dst.u3, 16);
		__builtin_memcpy(r->reply_src, &p.src.u3, 16);
		__builtin_memcpy(r->reply_dst, &p.dst.u3, 16);
		r->orig_sport = bpf_ntohs(o.src.u.all);
		r->orig_dport = bpf_ntohs(o.dst.u.all);
		r->reply_sport = bpf_ntohs(p.src.u.all);
		r->reply_dport = bpf_ntohs(p.dst.u.all);
		r->netns = BPF_CORE_READ(ct, ct_net.net, ns.inum);
		r->family = o.src.l3num;
		r->proto = o.dst.protonum;
		r->manip = (status & IPS_SRC_NAT ? 1 : 0) | (status & IPS_DST_NAT ? 2 : 0);
		r->pad = 0;
		commit(&s, &r->h, sizeof(*r), REC_NAT, 0);
	}
	bpf_preempt_enable();
	return 0;
}
