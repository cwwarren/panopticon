// SPDX-License-Identifier: GPL-2.0
#include "ring.h"

char LICENSE[] SEC("license") = "GPL";

#define NF_ACCEPT 1
#define NF_NAT_MANIP_SRC 0

SEC("fexit/nf_nat_setup_info")
int BPF_PROG(on_nat, struct nf_conn *ct, void *range, int maniptype, unsigned int ret)
{
	struct nf_conntrack_tuple *o = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	struct nf_conntrack_tuple *p = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	union nf_inet_addr *was, *now;
	__u16 was_port, now_port;
	struct nat_rec *r;
	struct ring_slot s;

	if (ret != NF_ACCEPT)
		return 0;
	if (maniptype == NF_NAT_MANIP_SRC) {
		was = &o->src.u3;
		now = &p->dst.u3;
		was_port = o->src.u.all;
		now_port = p->dst.u.all;
	} else {
		was = &o->dst.u3;
		now = &p->src.u3;
		was_port = o->dst.u.all;
		now_port = p->src.u.all;
	}
	if (was->all[0] == now->all[0] && was->all[1] == now->all[1] && was->all[2] == now->all[2] &&
	    was->all[3] == now->all[3] && was_port == now_port)
		return 0;
	bpf_preempt_disable();
	r = reserve(&ring_nat, CLASS_NAT, NAT_RING, sizeof(*r), &s);
	if (r) {
		__builtin_memcpy(r->orig_src, &o->src.u3, 16);
		__builtin_memcpy(r->orig_dst, &o->dst.u3, 16);
		__builtin_memcpy(r->reply_src, &p->src.u3, 16);
		__builtin_memcpy(r->reply_dst, &p->dst.u3, 16);
		r->orig_sport = bpf_ntohs(o->src.u.all);
		r->orig_dport = bpf_ntohs(o->dst.u.all);
		r->reply_sport = bpf_ntohs(p->src.u.all);
		r->reply_dport = bpf_ntohs(p->dst.u.all);
		r->netns = ct->ct_net.net->ns.inum;
		r->family = o->src.l3num;
		r->proto = o->dst.protonum;
		r->manip = maniptype;
		r->pad = 0;
		commit(&s, &r->h, sizeof(*r), REC_NAT, 0);
	}
	bpf_preempt_enable();
	return 0;
}
