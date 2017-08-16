/* Common part of all events.
 * #include'd both in the BPF module and in Go.
 */
typedef struct {
	uint64_t timestamp;
	int64_t  tgid;
	int64_t  ret;
	char     name[64];
	uint64_t hash;
} event_t;
