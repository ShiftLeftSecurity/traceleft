#include <linux/kconfig.h>

#include <linux/bpf.h>
#include "bpf_helpers.h"

// this has to match the struct in trace_syscalls.c
// TODO share it
typedef struct {
	u64 timestamp;
	char syscall[64];
	char buffer[256];
	u32 pid;
	u32 fd;
	int32_t ret;
	u32 padding;
} event_t;

#define PIN_GLOBAL_NS 2

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
	.program = "traceleft",
};

/* pid -> struct pt_regs */
struct bpf_map_def SEC("maps/args") args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pt_regs),
	.max_entries = 1024,
};

SEC("kprobe/handle_read")
int kprobe__handle_read(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();

	struct pt_regs args = { };
	bpf_probe_read(&args, sizeof(args), ctx);

	bpf_map_update_elem(&args_map, &pid, &args, BPF_ANY);

	return 0;
}

SEC("kretprobe/handle_read")
int kretprobe__handle_read(struct pt_regs *ctx)
{
	struct pt_regs *args;
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();

	args = bpf_map_lookup_elem(&args_map, &pid);
	if (args == NULL) {
		return 0;
	}
	bpf_map_delete_elem(&args_map, &pid);

	event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.syscall = "read",
		.pid = pid >> 32,
		.fd = (u32)PT_REGS_PARM1(args),
		.ret = PT_REGS_RC(ctx),
	};

	bpf_probe_read(&evt.buffer, sizeof(evt.buffer), (void *)PT_REGS_PARM2(args));

	bpf_perf_event_output(ctx, &event, cpu, &evt, sizeof(evt));

	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
