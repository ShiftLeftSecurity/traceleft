#ifndef EVENTS_STRUCT_H
#define EVENTS_STRUCT_H

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
} common_event_t;

#endif
