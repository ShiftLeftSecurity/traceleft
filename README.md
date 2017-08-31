# traceleft

traceleft is a library to trace applications. It uses Linux eBPF and kprobes to
install probes on Linux function calls (both API and internal functions) in
order to receive callbacks for syscalls, file and network events of a traced
process.

It also includes a small CLI tool with the same name for demo and testing
purposes.

Detailed documentation can be found in [Documentation/](Documentation/).

## Quickstart

```bash
make
sudo build/bin/traceleft trace $PID1,$PID2:battery/out/handle_syscall_read.bpf $PID3:battery/out/handle_syscall_chown.bpf
```

The `$PID` is optional and can be skipped to load a handler as default handler
and trace all processes instead.


## Tests

Test can be run with the following command:


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
