#ifndef HANDLER_NETWORK_TCP_H
#define HANDLER_NETWORK_TCP_H

#define PIN_GLOBAL_NS 2

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char name[64];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
} tcp_v4_event_t;

typedef struct {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
} tuple_v4_t;

// This helper builds the tuple with sock struct populated from connect
__attribute__((always_inline))
static int read_tuple_v4(tuple_v4_t *tup, struct sock *skp)
{
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	possible_net_t skc_net;

	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

#ifdef CONFIG_NET_NS
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif

	tup->saddr = saddr;
	tup->daddr = daddr;
	tup->sport = sport;
	tup->dport = dport;
	tup->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

// Helper to check if family is AF_INET ot AF_INET6
__attribute__((always_inline))
static bool check_family(struct sock *sk, u16 expected_family) {
	u16 family = 0;
	bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

	return family == expected_family;
}

#endif /* HANDLER_NETWORK_TCP_H */