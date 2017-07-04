#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/ptrace.h>
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
    u64 skp;
    u32 saddr;
    u32 daddr;
    u16 dport;
} tcp_v4_connect_event_t;

struct bpf_map_def SEC("maps/tcp_v4_connect_event") tcp_v4_connect_event =
{
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "traceleft",
};

struct bpf_map_def SEC("maps/tcp_v4_connectargs") tcp_v4_connectargs =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(tcp_v4_connect_event_t),
    .max_entries = 1024,
};

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    tcp_v4_connect_event_t *ev;
    ev = (tcp_v4_connect_event_t *) bpf_map_lookup_elem(&tcp_v4_connectargs, &pid);
    if (ev == 0) {
        return 0;
    }
    tcp_v4_connect_event_t event = *ev;
    event.ret = ret;

    
    struct sock *skp;
    skp = (struct sock *) event.skp;
    if (ret != 0) {
        /* missed entry */
        bpf_map_delete_elem(&tcp_v4_connectargs, &pid);
        return 0;
    }

    event.saddr = 0;
    event.daddr = 0;
    event.dport = 0;
    bpf_probe_read(&event.saddr, sizeof(event.saddr), &skp->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&event.daddr, sizeof(event.daddr), &skp->__sk_common.skc_daddr);
    bpf_probe_read(&event.dport, sizeof(event.dport), &skp->__sk_common.skc_dport);

    bpf_perf_event_output(ctx, &tcp_v4_connect_event, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&tcp_v4_connectargs, &pid);
    return 0;
};

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    tcp_v4_connect_event_t event = {
        .timestamp = bpf_ktime_get_ns(),
        .name = "tcp_v4_connect",
        .pid = pid >> 32,
        .ret = PT_REGS_RC(ctx),
    };
    event.skp = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&tcp_v4_connectargs, &pid, &event, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
