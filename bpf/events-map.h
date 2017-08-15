/* Map globally pinned used by both the main BPF module and the handlers.
 * To use the map in a BPF program, just include this file.
 */

#pragma once

#include "bpf_helpers.h"

#include "events-struct.h"

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "traceleft",
};
