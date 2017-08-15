/* Map globally pinned used by both the main BPF module and the handlers.
 * To use the map in a BPF program, just include this file.
 */

#pragma once

#include "bpf_helpers.h"

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

// This stores the PID for a given tuple which will be updated during tcp_v4_connect
// call and looked up during tcp_set_state to get the corresponding PID
struct bpf_map_def SEC("maps/tuple_pid_v4") tuple_pid_v4 =
{
       .type = BPF_MAP_TYPE_HASH,
       .key_size = sizeof(tuple_v4_t),
       .value_size = sizeof(__u64),
       .max_entries = 1024,
       .map_flags = 0,
       .pinning = PIN_GLOBAL_NS,
       .namespace = "traceleft",
};

// This stores the PID for a given tuple which will be updated during tcp_v6_connect
// call and looked up during tcp_set_state to get the corresponding PID
struct bpf_map_def SEC("maps/tuple_pid_v6") tuple_pid_v6 =
{
       .type = BPF_MAP_TYPE_HASH,
       .key_size = sizeof(tuple_v6_t),
       .value_size = sizeof(__u64),
       .max_entries = 1024,
       .map_flags = 0,
       .pinning = PIN_GLOBAL_NS,
       .namespace = "traceleft",
};
