#ifndef HANDLER_NETWORK_TCP_H
#define HANDLER_NETWORK_TCP_H

#define PIN_GLOBAL_NS 2

typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char name[64];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
} tcp_v4_event_t;

typedef struct {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
} tuple_v4_t;

#endif /* HANDLER_NETWORK_TCP_H */