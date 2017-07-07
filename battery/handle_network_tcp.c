/* handle_network_tcp.c

 This file build the BPF battery to trace established TCP network connections

 Functions Probed
 ----------------
 * tcp_v4_connect : Kprobe/Kretprobe
 * tcp_set_state : Kprobe
 * tcp_close : Kprobe

 Short Description
 -----------------
 The actual established TCP connection information is only obtained if we hook
 onto the tcp_set_state function. As tcp_set_state events don't have the PID
 context, the only acceptable approach in this case would be to keep a map of
 a tuple->PID with key as an ipv4 tuple (containing skp derived stuff - saddr,
 daddr etc. from the tcp_v4_connect call) and value as PID. We can then use the
 tuple from this map during tcp_set_state and fill out the our final event struct.

 TCP network event tracing is based on upstream work by Iago in IOVisor BCC
 tcptracer.py [https://github.com/iovisor/bcc/blob/master/tools/tcptracer.py]

*/

#include <linux/kconfig.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

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

// This is the event map where the outgoing perf event is stored. It will be updated
// from the tcp_set_state call which is when we know that connection is established
struct bpf_map_def SEC("maps/events") tcp_v4_event =
{
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

// This stores the sock * to match kprobe and kretprobe for tcp_v4_connect call
struct bpf_map_def SEC("maps/tcp_v4_connectsock") tcp_v4_connectsock =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
};

// This is stores the PID for a given tuple which will be updated during tcp_v4_connect
// call and looked up during tcp_set_state to get the corresponding PID
struct bpf_map_def SEC("maps/tuple_pid_v4") tuple_pid_v4 =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(tuple_v4_t),
	.value_size = sizeof(__u64),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

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

SEC("kretprobe/handle_tcp_v4_connect")
int kretprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		bpf_map_delete_elem(&tcp_v4_connectsock, &pid);
		return 0;
	}

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&tcp_v4_connectsock, &pid);
	if (skpp == 0) {
		return 0;   // missed entry
	}

	struct sock *skp = *skpp;
	bpf_map_delete_elem(&tcp_v4_connectsock, &pid);

	tuple_v4_t tup = { };
	if (!read_tuple_v4(&tup, skp)) {
	return 0;
	}

	bpf_map_update_elem(&tuple_pid_v4, &tup, &pid, BPF_ANY);
	return 0;
};

SEC("kprobe/handle_tcp_v4_connect")
int kprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	struct sock *skp;
	skp = (struct sock *) PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&tcp_v4_connectsock, &pid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/handle_tcp_set_state")
int kretprobe__handle_tcp_set_state(struct pt_regs *ctx)
{
	// Dummy probe, needed by design
	return 0;
};

SEC("kprobe/handle_tcp_set_state")
int kprobe__handle_tcp_set_state(struct pt_regs *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
	struct sock *skp;
	int state;

	skp =  (struct sock *) PT_REGS_PARM1(ctx);
	state = (int) PT_REGS_PARM2(ctx);
	if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
		return 0;
	}

	if (check_family(skp, AF_INET)) {
		tuple_v4_t tup = { };
		if (!read_tuple_v4(&tup, skp)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			bpf_map_delete_elem(&tuple_pid_v4, &tup);
			return 0;
		}

		u64 *pid;
		pid = bpf_map_lookup_elem(&tuple_pid_v4, &tup);
		if (pid == 0) {
			return 0;	// missed entry
		}

		tcp_v4_event_t ev = {
			.timestamp = bpf_ktime_get_ns(),
			.pid = (*pid) >> 32,
			.ret = 0,
			.name = "tcp_set_v4_connect",
			.saddr = tup.saddr,
			.daddr = tup.daddr,
			.sport = ntohs(tup.sport),
			.dport = ntohs(tup.dport),
			.netns = tup.netns,
		};

		bpf_perf_event_output(ctx, &tcp_v4_event, cpu, &ev, sizeof(ev));
		bpf_map_delete_elem(&tuple_pid_v4, &tup);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
