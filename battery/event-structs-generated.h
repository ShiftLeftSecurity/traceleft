
// Generated file, do not edit.
// Source: metagenerator.go


#include "../bpf/events-struct.h"

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for chmod from event-structs-generated.go
	char filename[256];
	u64 mode;
} chmod_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for chown from event-structs-generated.go
	char filename[256];
	uid_t user;
	gid_t group;
} chown_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for close from event-structs-generated.go
	u64 fd;
} close_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for fchmod from event-structs-generated.go
	u64 fd;
	u64 mode;
} fchmod_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for fchmodat from event-structs-generated.go
	s64 dfd;
	char filename[256];
	u64 mode;
} fchmodat_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for fchown from event-structs-generated.go
	u64 fd;
	uid_t user;
	gid_t group;
} fchown_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for fchownat from event-structs-generated.go
	s64 dfd;
	char filename[256];
	uid_t user;
	gid_t group;
	s64 flag;
} fchownat_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for mkdir from event-structs-generated.go
	char pathname[256];
	u64 mode;
} mkdir_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for mkdirat from event-structs-generated.go
	s64 dfd;
	char pathname[256];
	u64 mode;
} mkdirat_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for open from event-structs-generated.go
	char filename[256];
	s64 flags;
	u64 mode;
} open_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for read from event-structs-generated.go
	u64 fd;
	char buf[256];
	int64_t count;
} read_event_t;

typedef struct {
	// fields matching struct CommonEvent from tracer.go
	common_event_t common;

	// fields matching the struct for write from event-structs-generated.go
	u64 fd;
	char buf[256];
	int64_t count;
} write_event_t;
