# TraceLeft

TraceLeft is a library to trace applications as well as a small CLI tool 
(`traceleft`) which acts as a reference implementation of the framework. 
It uses Linux [eBPF](https://lwn.net/Articles/740157/) and 
[Kprobes](https://www.kernel.org/doc/Documentation/kprobes.txt) to install 
probes on Linux function calls (both APIs and other internal functions) 
in order to receive callbacks for syscalls, file and network events of a 
traced process. TraceLeft is built using [gobpf](https://github.com/iovisor/gobpf) 
and takes inspiration from the [BCC](https://github.com/iovisor/bcc) toolset. 
TraceLeft has been designed as a framework to build configuration driven system 
auditing tools as well as application tracing tools used for network and syscall
monitoring. TraceLeft has been tested on kernel versions `v4.11+` with eBPF support 
for Kprobes ans Kretprobes. Though eBPF support for static tracepoints has 
landed in recent kernels, one of the early goals of TraceLeft was to have it run 
on older kernels with early eBPF support. Tracepoint support is in the works.

The following diagram shows how a set of syscalls and other events from an 
application can be hooked onto using TraceLeft and then eventually tracked through 
the lifecycle of the traced application

![block-diagram](traceleft-block.png)

Decisions on what process to track and what data to collect per-event can be 
configured to a very fine granularity using Proto/JSON configs. Targeted eBPF handlers 
are generated based on a pre-defined [`config.json`](examples/config.json). Such a
config eventually generates a [battery](battery) of compiled eBPF programs that 
handle each syscall or a network event as the configuration desires. All the eBPF 
handlers are controlled via a main eBPF program. When each handler fires as the tracked
application executes, it generates an **_Event_** which is transmitted via the `perf` map 
to userspace. And event can then be aggregated via a reference 
[event aggregator](documentation/event-aggregation.md) implementation that allows
setting filtering rules on each collected event and provides specifications for 
aggregating events and transfering them over the wire in proto format or to a local 
file.

Detailed documentation can be found in [documentation](documentation) directory.

## Quickstart

Building the `traceleft` binary requires Docker

```bash
make
sudo build/bin/traceleft trace $PID1,$PID2:battery/out/handle_syscall_read.bpf $PID3:battery/out/handle_syscall_chown.bpf
```

The `$PID` is optional and can be skipped to load a handler as default handler
and trace all processes instead.


## Tests

Test can be run using the testing script provided in `tests` directory:


```bash
sudo -E tests/run.sh
```

### Expected output

```bash
Using outfile /tmp/traceleft-test-cli-out-Ecw373
Using outdir /tmp/traceleft-trace-out
Running test_sys_chmod with PID: 7996               [PASSED]
Running test_sys_chown with PID: 8045               [PASSED]
Running test_sys_close with PID: 8099               [PASSED]
...
```

## Contributors

 - Suchakra Sharma ([ShiftLeft Inc.](https://shiftleft.io))
 - Iago López Galeiras ([Kinvolk](https://kinvolk.io))
 - Michael Schubert ([Kinvolk](https://kinvolk.io))
 - Alban Crequy ([Kinvolk](https://kinvolk.io))
  

©2018 Shiftleft Inc.