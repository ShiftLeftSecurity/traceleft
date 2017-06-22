
// Generated file, do not edit.
// Source: metagenerator.go


typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	char filename[256];
	u64 mode;
} chmod_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	char filename[256];
	uid_t user;
	gid_t group;
} chown_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	u64 fd;
} close_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	u64 fd;
	u64 mode;
} fchmod_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	s64 dfd;
	char filename[256];
	u64 mode;
} fchmodat_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	u64 fd;
	uid_t user;
	gid_t group;
} fchown_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	s64 dfd;
	char filename[256];
	uid_t user;
	gid_t group;
	s64 flag;
} fchownat_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	char pathname[256];
	u64 mode;
} mkdir_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	s64 dfd;
	char pathname[256];
	u64 mode;
} mkdirat_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	char filename[256];
	s64 flags;
	u64 mode;
} open_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	u64 fd;
	char buf[256];
	int64_t count;
} read_event_t;

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	u64 fd;
	char buf[256];
	int64_t count;
} write_event_t;
