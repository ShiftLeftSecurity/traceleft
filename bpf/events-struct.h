#ifndef EVENTS_STRUCT_H
#define EVENTS_STRUCT_H

#define COMMON_EVENT_FLAG_INCOMPLETE_PROBE_READ 0x01

/* Common part of all events.
 * #include'd both in the BPF module and in Go.
 */
typedef struct {
	uint64_t timestamp;
	uint64_t program_id;
	int64_t  tgid;
	int64_t  ret;
	char     name[64];
	uint64_t hash;
	uint64_t flags;
} common_event_t;

#endif
