#include <uapi/linux/ptrace.h>
#include <linux/kconfig.h>

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define PIN_GLOBAL_NS 2

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
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

struct bpf_map_def SEC("maps/handle_close_progs") handle_close_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_close_progs_ret") handle_close_progs_ret = {
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

struct bpf_map_def SEC("maps/handle_mkdir_progs") handle_mkdir_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_mkdir_progs_ret") handle_mkdir_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchown_progs") handle_fchown_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchown_progs_ret") handle_fchown_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchownat_progs") handle_fchownat_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchownat_progs_ret") handle_fchownat_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmod_progs") handle_fchmod_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmod_progs_ret") handle_fchmod_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmodat_progs") handle_fchmodat_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_fchmodat_progs_ret") handle_fchmodat_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chmod_progs") handle_chmod_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chmod_progs_ret") handle_chmod_progs_ret = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chown_progs") handle_chown_progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 32768,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps/handle_chown_progs_ret") handle_chown_progs_ret = {
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
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
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

SEC("kprobe/SyS_close")
int kprobe__handle_close(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_close_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_close")
int kretprobe__handle_close(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_close_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_mkdir")
int kprobe__handle_mkdir(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_mkdir_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_mkdir")
int kretprobe__handle_mkdir(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_mkdir_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_chown")
int kprobe__handle_chown(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_chown_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_chown")
int kretprobe__handle_chwon(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_chown_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_fchown")
int kprobe__handle_fchown(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchown_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_fchown")
int kretprobe__handle_fchwon(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchown_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_fchownat")
int kprobe__handle_fchownat(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchownat_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_fchownat")
int kretprobe__handle_fchownat(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchownat_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_chmod")
int kprobe__handle_chmod(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_chmod_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_chmod")
int kretprobe__handle_chmod(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_chmod_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_fchmod")
int kprobe__handle_fchmod(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchmod_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_fchmod")
int kretprobe__handle_fchmod(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchmod_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kprobe/SyS_fchmodat")
int kprobe__handle_fchmodat(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs, pid >> 32);
	// TODO insert default handler here

	return 0;
}

SEC("kretprobe/SyS_fchmodat")
int kretprobe__handle_fchmodat(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	bpf_tail_call(ctx, (void *)&handle_fchmodat_progs_ret, pid >> 32);
	// TODO insert default handler here

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
