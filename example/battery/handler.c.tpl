#include <linux/kconfig.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

typedef struct {
	u64 timestamp;
    char syscall[64];
	u32 pid;
	int32_t ret;
} {{ .EventName }}_event_t;

#define PIN_GLOBAL_NS 2

struct bpf_map_def SEC("maps/events") {{ .EventName }}_event =
{
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};

struct bpf_map_def SEC("maps/{{ .EventName }}_args") {{ .EventName }}args =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pt_regs),
	.max_entries = 1024,
};

SEC("kretprobe/handle_{{ .EventName }}")
int kretprobe__handle_{{ .EventName }}(struct pt_regs *ctx)
{
	struct pt_regs *args;
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();

	args = bpf_map_lookup_elem(&{{ .EventName }}args, &pid);
	if (args == NULL) {
		return 0;
	}
	bpf_map_delete_elem(&{{ .EventName }}args, &pid);

	{{ .EventName }}_event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.syscall = "{{ .EventName }}",
		.pid = pid >> 32,
		.ret = PT_REGS_RC(ctx),
	};

	bpf_perf_event_output(ctx, &{{ .EventName }}_event, cpu, &evt, sizeof(evt));
	return 0;
};

SEC("kprobe/handle_{{ .EventName }}")
int kprobe__handle_{{ .EventName }}(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	struct pt_regs args = { };
	bpf_probe_read(&args, sizeof(args), ctx);
	bpf_map_update_elem(&{{ .EventName }}args, &pid, &args, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;