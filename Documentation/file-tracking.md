# File Tracking

File operation syscalls usually work with file descriptors, which are basically
a number for processes to refer to currently open files.

This creates a challenge, since what we're interested in is the path of the
underlying file. However, when we get syscalls events like read or write, we'll
see only the file descriptor.

We'll describe how we solved this problem and the drawbacks and limitations of
the implementation.

## Implementation and caveats

We keep a userspace Go map `(pid, fd) -> path` which we populate by hooking
into `fd_install` (kprobe and kretprobe) and reading `/proc/$PID/fd/$FD_NUMBER`
in userspace. Then, when we get a file event, we check the map and print the
path along with the file descriptor number.

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
