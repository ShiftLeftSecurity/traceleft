/* handle_network_*.c

 This file builds the BPF battery to trace established TCP network connections

 Functions Probed
 ----------------
 * tcp_v4_connect : Kprobe/Kretprobe
 * tcp_v6_connect : Kprobe/Kretprobe
 * tcp_set_state : Kprobe
 * tcp_close : Kprobe
 * inet_csk_accept : Kretprobe

 Short Description
 -----------------
 The actual established TCP connection information is only obtained if we hook
 onto the tcp_set_state function. As tcp_set_state events don't have the PID
 context, the only acceptable approach in this case would be to keep a map of
 a tuple->PID with key as an ipv{4,6} tuple (containing skp derived stuff - saddr,
 daddr etc. from the tcp_v{4,6}_connect call) and value as PID. We can then use the
 tuple from this map during tcp_set_state and fill out the our final event struct.

 TCP network event tracing is based on upstream work by Iago in IOVisor BCC
 tcptracer.py [https://github.com/iovisor/bcc/blob/master/tools/tcptracer.py]

*/

#include <linux/kconfig.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/bpf.h>
#pragma clang diagnostic pop
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
#include "handle_network_tcp.h"

// This is the event map where the outgoing perf event is stored. It will be updated
// from the tcp_set_state call which is when we know that connection is established
struct bpf_map_def SEC("maps/events") tcp_event =
{
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

// This stores the PID for a given tuple which will be updated during tcp_v4_connect
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

// This stores the PID for a given tuple which will be updated during tcp_v6_connect
// call and looked up during tcp_set_state to get the corresponding PID
struct bpf_map_def SEC("maps/tuple_pid_v6") tuple_pid_v6 =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(tuple_v6_t),
	.value_size = sizeof(__u64),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

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
			.name = "connect_v4",
			.saddr = tup.saddr,
			.daddr = tup.daddr,
			.sport = ntohs(tup.sport),
			.dport = ntohs(tup.dport),
			.netns = tup.netns,
		};

		bpf_perf_event_output(ctx, &tcp_event, cpu, &ev, sizeof(ev));
		bpf_map_delete_elem(&tuple_pid_v4, &tup);
	} else if (check_family(skp, AF_INET6)) {
		tuple_v6_t tup = { };
		if (!read_tuple_v6(&tup, skp)) {
			return 0;
		}

		if (state == TCP_CLOSE) {
			bpf_map_delete_elem(&tuple_pid_v6, &tup);
			return 0;
		}

		u64 *pid;
		pid = bpf_map_lookup_elem(&tuple_pid_v6, &tup);
		if (pid == 0) {
			return 0;	// missed entry
		}

		tcp_v6_event_t ev = {
			.timestamp = bpf_ktime_get_ns(),
			.pid = (*pid) >> 32,
			.ret = 0,
			.name = "connect_v6",
			.saddr = {tup.saddr[0], tup.saddr[1], tup.saddr[2], tup.saddr[3]},
			.daddr = {tup.daddr[0], tup.daddr[1], tup.daddr[2], tup.daddr[3]},
			.sport = ntohs(tup.sport),
			.dport = ntohs(tup.dport),
			.netns = tup.netns,
		};

		bpf_perf_event_output(ctx, &tcp_event, cpu, &ev, sizeof(ev));
		bpf_map_delete_elem(&tuple_pid_v6, &tup);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
