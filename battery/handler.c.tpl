{{/* The following comment will be added in all handlers */}}
// Generated file, do not edit.
// Source: handler.c.tpl
// Event name: {{ .Name }}
// Event args: {{ .Args }}

#include <linux/kconfig.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/bpf.h>
#pragma clang diagnostic pop
#include <linux/types.h>
#include "bpf_helpers.h"
#include "event-structs-generated.h"

#include "../bpf/events-map.h"

struct bpf_map_def SEC("maps/{{ .Name }}_args") {{ .Name }}args =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pt_regs),
	.max_entries = 1024,
};

SEC("kretprobe/handle_{{ .Name }}")
int kretprobe__handle_{{ .Name }}(struct pt_regs *ctx)
{
	struct pt_regs *args;
	u64 pid = bpf_get_current_pid_tgid();
	u32 cpu = bpf_get_smp_processor_id();

	args = bpf_map_lookup_elem(&{{ .Name }}args, &pid);
	if (args == NULL) {
		return 0;
	}
	bpf_map_delete_elem(&{{ .Name }}args, &pid);

	{{ .Name }}_event_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.name = "{{ .Name }}",
		.pid = pid >> 32,
		.ret = PT_REGS_RC(ctx),
		.hash = fnv64a_init(),
	};

	fnv64a_update(&evt.hash, (char *)&evt.pid, sizeof(evt.pid));
	fnv64a_update(&evt.hash, (char *)&evt.ret, sizeof(evt.ret));
	fnv64a_update(&evt.hash, (char *)evt.name, sizeof(evt.name));

	{{range $index, $element := .Args -}}
	    {{if eq $element.Type "char"}}
	bpf_probe_read(&evt.{{ $element.Name }}, sizeof(evt.{{ $element.Name }}), (void *) PT_REGS_PARM{{ $element.Position }}(args));
	    {{- else }}
	evt.{{ $element.Name }} = ({{ $element.Type }}) PT_REGS_PARM{{ $element.Position }}(args);
	    {{- end }}
	{{- end }}

	{{ range $index, $element := .Args }}
	fnv64a_update(&evt.hash, (char *)&evt.{{ $element.Name }}, sizeof(evt.{{ $element.Name }}));
	{{- end }}

	bpf_perf_event_output(ctx, &events, cpu, &evt, sizeof(evt));
	return 0;
};

SEC("kprobe/handle_{{ .Name }}")
int kprobe__handle_{{ .Name }}(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	struct pt_regs args = { };
	bpf_probe_read(&args, sizeof(args), ctx);
	bpf_map_update_elem(&{{ .Name }}args, &pid, &args, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader to set the current running
// kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

