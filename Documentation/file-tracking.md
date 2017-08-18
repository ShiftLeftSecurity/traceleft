# File Tracking

File operation syscalls usually work with file descriptors, which are basically
a number for processes to refer to currently open files.

This creates a challenge, since what we're interested in is the path of the
underlying file. However, when we get syscalls events like read or write, we'll
see only the file descriptor.

We'll describe how we solved this problem and the drawbacks and limitations of
the implementation.

## Implementation and caveats

[`fd_install`][fd_install] is a kernel function that installs a new file
descriptor in the file descriptor table of a process. It is called every time a
file descriptor is made available to a process. We hook into `fd_install`
(kprobe and kretprobe) and pass the file descriptor number to userspace. Then,
userspace will call [`readlink`][readlink] on `/proc/$PID/fd/$FD_NUMBER` to get
the path that file descriptor points to and store it in a Go map `(pid, fd) ->
path`. Then, when we get a file event, we check the map and print the path
along with the file descriptor number.

This is a best-effort solution: we'll miss short-lived file descriptors because
we might not have time to look up in `/proc` before the file descriptor or even
the process disappears.

With this schema, we might report incorrect events. Consider the case of a
short-lived file descriptor followed by an open call. We might record the wrong
file path to the map because we'll read the path of the newly opened file.

To address this problem, we record in the map the inode number, along with the
device major and minor numbers. Then, at the time we receive a file event, we
check that the file living in the path recorded in the map corresponds with the
`(inode, major, minor)` tuple recorded. If so, we include the path in the
event. If not, we consider it "unknown". If there's no file in that path
anymore, we consider the file `deleted` and we offer the possible path.

Checking the path at the time we receive a file event would not work for
containers, since the path we have stored is relative to the mount namespace of
the container. To fix that, we prepend `/proc/$PID/root/` to the path so we get
the file system view of the process. Also, we detect in userspace if the
process has a mount namespace that's not the host's and include this
information in the event.

Finally, to clean up the map when a file descriptor is closed, we delete the
`(pid, fd)` entry in the map when we receive a close event. Note that we can
leak entries if we don't trace close events or we miss close kretprobes. In
that case, we assume the library user will clean up the map for a given PID
when the process exits.

## Alternative designs considered

Before choosing the implementation described above, we've considered several
alternative designs.

### Trace VFS functions like read/write

The idea was tracing VFS kernel functions (e.g. `vfs_read`) and walking up
`struct dentry` from `(struct file)->(struct path)->(struct dentry)` to get the
components of the path. We would concatenate them in kernel space and pass the
path directly to userspace.

#### Pros
* We can do everything in kernel so it’s efficient and accurate (except the
  mountpoint issue mentioned later).

#### Cons
* You can’t use loops in BPF. This can be mitigated via unrolled loops and/or
  tail calls. There’s a limit of 32 tail calls and a limit of 4096 instructions
  per program so you can’t do this indefinitely. The stack is limited to 512
  bytes so you can’t have a large buffer on it. This can be worked around [by
  using a single-element
  map](http://cilium.readthedocs.io/en/latest/bpf/#llvm). However: [per CPU
  maps are only supported from kernel
  4.6](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) so
  we’d need to detect the core number and create one element per core in a
  global map. In any case, we couldn’t find a way to pass information outside
  the stack to a perf event.
* String concatenation is very hard to do on BPF
* You can’t build a full path from a `dentry`, it will stop at the mountpoint
  boundary.

### Save the path passed to the syscall `open()` in a bpf map. The map would be `(pid, fd) -> path`

Then, on subsequent calls to `read()`, `write()` or related functions, we’ll
fetch the path and send it on the perf event as if it were another argument.

#### Pros
* We can do everything in kernel so it’s efficient and accurate (except the
  mount ns and relative paths issue mentioned later).

#### Cons
* Again, the stack is limited to 512 bytes so you can’t have a large buffer on
  it. This is more of a problem here because functions like `read()` or
  `write()` also have buffers we want to pass (at least partially) to
  userspace. In practice this means the max length of the path is around 128
  characters.
* If we miss `close()` k{ret}probes, the entry on the map will leak.
* There’s no map-in-map support until kernel 4.12, so we’ll need one map that
  can fit all the combinations of (pid, fd) that might happen at one particular
  time. This should not be a huge problem.
* We’ll get the path the user passed to `open()`, which can be relative or
  referring to a different mount namespace.

[fd_install]: http://elixir.free-electrons.com/linux/v4.12.8/source/fs/file.c#L625
[readlink]: https://linux.die.net/man/2/readlink
