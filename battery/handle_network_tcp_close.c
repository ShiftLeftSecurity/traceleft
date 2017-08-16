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

#include "../bpf/events-map.h"
#include "network-maps.h"

SEC("kretprobe/handle_tcp_close")
int kretprobe__handle_tcp_close(struct pt_regs *ctx)
{
	// Dummy probe, needed by design
	return 0;
};

SEC("kprobe/handle_tcp_close")
int kprobe__handle_tcp_close(struct pt_regs *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();

	struct sock *skp;
	u8 oldstate;

	skp = (struct sock *) PT_REGS_PARM1(ctx);
	// Read previous state and don't record events for connections
	// that were not established
	bpf_probe_read(&oldstate, sizeof(oldstate), (u8 *)&skp->sk_state);
	if (oldstate == TCP_SYN_SENT ||
	    oldstate == TCP_SYN_RECV ||
	    oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}

	if (check_family(skp, AF_INET)) {
		tuple_v4_t tup = { };
		if (!read_tuple_v4(&tup, skp)) {
			bpf_map_delete_elem(&tuple_pid_v4, &tup);
			return 0;
		}

		tcp_v4_event_t ev = {
			.common = {
				.timestamp = bpf_ktime_get_ns(),
				.tgid = pid >> 32,
				.ret = 0,
				.name = "close_v4",
				.hash = 0,
			},
			.saddr = tup.saddr,
			.daddr = tup.daddr,
			.sport = ntohs(tup.sport),
			.dport = ntohs(tup.dport),
			.netns = tup.netns,
		};

		bpf_perf_event_output(ctx, &events, cpu, &ev, sizeof(ev));
		bpf_map_delete_elem(&tuple_pid_v4, &tup);
	} else if (check_family(skp, AF_INET6)) {
		tuple_v6_t tup = { };
		if (!read_tuple_v6(&tup, skp)) {
			bpf_map_delete_elem(&tuple_pid_v6, &tup);
			return 0;
		}

		tcp_v6_event_t ev = {
			.common = {
				.timestamp = bpf_ktime_get_ns(),
				.tgid = pid >> 32,
				.ret = 0,
				.name = "close_v6",
				.hash = 0,
			},
			.saddr = {tup.saddr[0], tup.saddr[1], tup.saddr[2], tup.saddr[3]},
			.daddr = {tup.daddr[0], tup.daddr[1], tup.daddr[2], tup.daddr[3]},
			.sport = ntohs(tup.sport),
			.dport = ntohs(tup.dport),
			.netns = tup.netns,
		};

		bpf_perf_event_output(ctx, &events, cpu, &ev, sizeof(ev));
		bpf_map_delete_elem(&tuple_pid_v6, &tup);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

