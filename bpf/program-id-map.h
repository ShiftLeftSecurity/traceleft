/* Map globally pinned used by both the main BPF module and the handlers.
 * To use the map in a BPF program, just include this file.
 */

#pragma once

#include "bpf_helpers.h"

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

/* Each PID (technically TGIDs) has an opaque program_id that needs to be
 * passed in the events. It is populated by userspace.
 * */
struct bpf_map_def SEC("maps/program_id_per_pid") program_id_per_pid = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 32768,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};
