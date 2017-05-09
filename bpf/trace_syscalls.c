#include <uapi/linux/ptrace.h>
#include <linux/kconfig.h>

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

typedef struct {
	u64 timestamp;
	char syscall[64];
	char buffer[256];
	u32 pid;
	u32 fd;
	int32_t ret;
	u32 padding;
} event_t;

struct bpf_map_def SEC("maps/handle_open_progs") handle_open_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_open_progs_ret") handle_open_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_read_progs") handle_read_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_read_progs_ret") handle_read_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_write_progs") handle_write_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_write_progs_ret") handle_write_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/events") event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
};

SEC("kprobe/SyS_read")
int kprobe__sys_read(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_read_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_read")
int kretprobe__sys_read(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_read_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_write")
int kprobe__sys_write(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_write_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_write")
int kretprobe__handle_write(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_write_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_open")
int kprobe__handle_open(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_open_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_open")
int kretprobe__handle_open(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_open_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
