#include <uapi/linux/ptrace.h>
#include <linux/kconfig.h>

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define PIN_GLOBAL_NS 2

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char name[64];
} event_t;

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/events") event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

struct bpf_map_def SEC("maps/handle_tcp_v4_connect_progs") handle_tcp_v4_connect_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_tcp_v4_connect_progs_ret") handle_tcp_v4_connect_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_inet_csk_accept_progs") handle_inet_csk_accept_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_inet_csk_accept_progs_ret") handle_inet_csk_accept_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

SEC("kprobe/tcp_v4_connect")
int kprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs, pid >> 32);
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs, 0);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__handle_tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs_ret, pid >> 32);
	bpf_tail_call(ctx, (void *)&handle_tcp_v4_connect_progs_ret, 0);

	return 0;
}

SEC("kprobe/inet_csk_accept")
int kprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs, pid >> 32);
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs, 0);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__handle_inet_csk_accept(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs_ret, pid >> 32);
	bpf_tail_call(ctx, (void *)&handle_inet_csk_accept_progs_ret, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
