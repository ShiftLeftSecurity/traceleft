# How to add a new syscall

## 1. Update the "event specification"

`examples/config.json` contains the currently used specification example and
defines the names of the syscall events to trace as well as their arguments
with

* `position`: e.g. `2` for second argument to function,
* `name`: the name of the argument, e.g. "buf",
* `type`: e.g. `char`,
* `suffix` (type suffix): e.g. `[256]` for a variable `char buf[256]` (optional)
* `hashFunc`can be:
  * "string": hash until a NULL character that terminates the string; useful for paths
  * "skip": do not hash this parameter at all; it is used for the read() or write() buffers
  * "" (empty string, the default): hash, with a fixed size for the field

## 2. Add syscall to `consideredSyscalls`

`consideredSyscalls` is a currently hard coded list of syscalls in
`metagenerator/metagenerator.go` for which to generate event structures and
methods.

## 3. Update `trace_events.c` program sources

* Add `progs` and `progs_ret` maps
* Add a `kprobe` and `kretprobe` for the new syscall

Best start with a copy of an existing map/kprobe pair.

## 3. Run `make metagen` to generate the event structures

A new `foo_event_t` gets added to `battery/event-structs-generated.h` etc.

## 4. Run `make pregen` to build BPF programs

## 5. Run `make traceleft` to build traceleft

## 6. Add a test

A test directory should have:

* a test script, named after the test directory with a `.script` suffix,
  e.g. `test_sys_read.script`
* an executable file to run, named after the test directory, e.g.
  `test_sys_read`
* `expects.log`: the expected tracer output, with placeholders `%PID%`, `%FD%`
  and `%BASEDIR%` if required

If your test is written in C, also name the file after the test directory (e.g.
`test_sys_read.c`). The test Makefile automatically picks up the C file and
builds it before running the tests.

All tests get the path to a "stampfile" as the first argument and must call
`stampwait` as a first step.

The second argument is the path to a fifo file which can be used to signal
readiness from `tests/cli` to the test.
