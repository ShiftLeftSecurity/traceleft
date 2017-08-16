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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "handle_network_tcp.h"
#pragma clang diagnostic pop

#include "../bpf/events-map.h"
#include "network-maps.h"

SEC("kprobe/handle_inet_csk_accept")
int kretprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	// Dummy probe, needed by design
	return 0;
};

SEC("kretprobe/handle_inet_csk_accept")
int kprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	struct sock *skp = (struct sock *) PT_REGS_RC(ctx);
	u32 cpu = bpf_get_smp_processor_id();
	u64 pid = bpf_get_current_pid_tgid();

	if (skp == NULL) {
		return 0;
	}

	u16 lport, dport;
	u32 net_ns_inum;

	lport = 0;
	dport = 0;

	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	bpf_probe_read(&lport, sizeof(lport), &skp->__sk_common.skc_num);

#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif

	if (check_family(skp, AF_INET)) {
		tcp_v4_event_t ev = {
			.common = {
				.timestamp = bpf_ktime_get_ns(),
				.tgid = pid >> 32,
				.ret = 0,
				.name = "accept_v4",
				.hash = 0,
			},
			.sport = lport,
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};

		bpf_probe_read(&ev.saddr, sizeof(u32), &skp->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&ev.daddr, sizeof(u32), &skp->__sk_common.skc_daddr);

		if (ev.saddr != 0 && ev.daddr != 0 && ev.sport != 0 && ev.dport != 0) {
			bpf_perf_event_output(ctx, &events, cpu, &ev, sizeof(ev));
		}
	} else if (check_family(skp, AF_INET6)) {
		tcp_v6_event_t ev = {
			.common = {
				.timestamp = bpf_ktime_get_ns(),
				.tgid = pid >> 32,
				.ret = 0,
				.name = "accept_v6",
				.hash = 0,
			},
			.sport = lport,
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};

		bpf_probe_read(&ev.saddr, sizeof(ev.saddr),
			       &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&ev.daddr, sizeof(ev.daddr),
			       &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

		// do not send event if any IP address is 0 or any port is 0
		if ((ev.saddr[0] | ev.saddr[1] | ev.saddr[2] | ev.saddr[3]) != 0 &&
		    (ev.daddr[0] | ev.daddr[1] | ev.daddr[2] | ev.daddr[3]) != 0 &&
		    ev.sport != 0 && ev.dport != 0) {
			bpf_perf_event_output(ctx, &events, cpu, &ev, sizeof(ev));
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
