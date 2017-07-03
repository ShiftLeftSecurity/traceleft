# traceleft

## Instructions

```
make
make handlers
make
sudo build/bin/slagent trace $PID1,$PID2:battery/out/handle_read.bpf $PID3:battery/out/handle_chown.bpf
```

The `$PID` is optional and can be skipped to load a handler as default handler.

## Update Protocol Buffer golang source files

The source files whith Protocol Buffer definitions are checked in to the
repository, to update them run

```
make protogen
```

## Update metagenerated event structs

Golang and C structs for events are checked in to the repository, to update them run

```
make metagen
```

This will go through `/sys/kernel/debug/tracing/events/syscalls` and generate
the structures according to the `format` file present on each syscall.

## Design

### Probes

traceleft adds k{ret,}probes for all traced syscalls (see
`bpf/trace_syscalls.c` for a list). The only thing the trace probes do is tail
calling handler probes (or return 0 - i.e. do nothing - if no probe was set).

Examples:

```
// kprobe
bpf_tail_call(ctx, (void *)&handle_open_progs, pid >> 32); // exec process-specific handler, if set or
bpf_tail_call(ctx, (void *)&handle_open_progs, 0);  // exec default handler, if set or
return 0;                                                  // do nothing

// kretprobe, same principle
bpf_tail_call(ctx, (void *)&handle_open_progs_ret, pid >> 32);
bpf_tail_call(ctx, (void *)&handle_open_progs_ret, 0);
return 0;
```

The handler maps follow the scheme `handle_SYSCALL_progs{,_ret}` where
`SYSCALL` is the name of the traced syscall w/o `[Ss]y[Ss]_` prefix.

traceleft provides a single map of type `BPF_MAP_TYPE_PROG_ARRAY` which
handlers must use to send events. All events start with a common section

```
struct {
        u64 timestamp;
        int64_t pid;
        long ret;
        char syscall[64];
}
```

to enable the tracer to dispatch events. Specific fields follow after.

The Probe (see `probe/probe.go`; responsible for loading process-specific as
well as default handler probes) expects handler probes to follow the scheme
`kprobe/handle_SYSCALL` and `kretprobe/handle_SYSCALL`, i.e. the name of a
k{,ret}probe defines which handler map to update.

Handler probes can be loaded for a specific pid or as default handler (pid == 0).
