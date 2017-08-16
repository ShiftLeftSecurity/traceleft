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
#include "../bpf/program-id-map.h"

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
	u64 *program_id = bpf_map_lookup_elem(&program_id_per_pid, &pid);

	args = bpf_map_lookup_elem(&{{ .Name }}args, &pid);
	if (args == NULL) {
		return 0;
	}
	bpf_map_delete_elem(&{{ .Name }}args, &pid);

	{{ .Name }}_event_t evt = {
		.common = {
			.timestamp = bpf_ktime_get_ns(),
			.program_id = program_id ? *program_id : 0,
			.name = "{{ .Name }}",
			.tgid = pid >> 32,
			.ret = PT_REGS_RC(ctx),
			.hash = fnv64a_init(),
		},
	};

	fnv64a_update(&evt.common.hash, (char *)&evt.common.program_id, sizeof(evt.common.program_id));
	fnv64a_update(&evt.common.hash, (char *)&evt.common.tgid, sizeof(evt.common.tgid));
	fnv64a_update(&evt.common.hash, (char *)&evt.common.ret, sizeof(evt.common.ret));
	fnv64a_update(&evt.common.hash, (char *)evt.common.name, sizeof(evt.common.name));

	{{range $index, $element := .Args -}}
	    {{if eq $element.Type "char"}}
	bpf_probe_read(&evt.{{ $element.Name }}, sizeof(evt.{{ $element.Name }}), (void *) PT_REGS_PARM{{ $element.Position }}(args));
	    {{- else }}
	evt.{{ $element.Name }} = ({{ $element.Type }}) PT_REGS_PARM{{ $element.Position }}(args);
	    {{- end }}
	{{- end }}

	{{ range $index, $element := .Args }}
	fnv64a_update(&evt.common.hash, (char *)&evt.{{ $element.Name }}, sizeof(evt.{{ $element.Name }}));
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

