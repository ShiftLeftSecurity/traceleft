# traceleft

## Instructions

### Run example slagent

```bash
make
sudo build/bin/slagent trace $PID1,$PID2:battery/out/handle_syscall_read.bpf $PID3:battery/out/handle_syscall_chown.bpf
```

The `$PID` is optional and can be skipped to load a handler as default handler.

To send events to the demo server (`metrics/echoserver`) instead of logging to
stdout, use `--collector-insecure --collector-addr localhost:50051 `:

```
sudo build/bin/slagent trace --collector-insecure --collector-addr localhost:50051 $(find battery/out/*)
```

In a second terminal, run the echoserver to see an event counter:

```
go run metrics/echoserver/main.go
```

### Update Protocol Buffer golang source files

The source files whith Protocol Buffer definitions are checked in to the
repository, to update them run

```
make protogen
```

### Update metagenerated event structs

Golang and C structs for events are checked in to the repository, to update them run

```
make metagen
```

This will go through `/sys/kernel/debug/tracing/events/syscalls` and generate
the structures according to the `format` file present on each syscall.

### Run Tests

```bash
sudo -E tests/run.sh
```

#### Expected output

```bash
Using outfile /tmp/traceleft-test-cli-out-Ecw373
Using outdir /tmp/traceleft-trace-out
Running test_sys_chmod with PID: 7996               [PASSED]
Running test_sys_chown with PID: 8045               [PASSED]
Running test_sys_close with PID: 8099               [PASSED]
...
```

### Analyse performances

slagent offers [HTTP endpoints with profiling information](https://golang.org/pkg/net/http/pprof/).
To enable them, use `--pprof-listen-addr=localhost:9090`.
Then, you can access one of the profiling endpoint:

```bash
go tool pprof http://localhost:9090/debug/pprof/heap
go tool pprof http://localhost:9090/debug/pprof/profile
```

#### eBPF performances

eBPF programs run in the kernel and their CPU usage are not accounted in the slagent process. This can be monitored with:
```bash
sudo perf top
```

Then, look for `__bpf_prog_run`.
