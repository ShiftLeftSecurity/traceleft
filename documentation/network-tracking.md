# Network Tracking

Tracking network connections is handled specially by TraceLeft. The handlers
are not generated, but handwritten, and we trace internal kernel functions, not
syscalls as high-level syscalls are not sufficient for such tracking

We trace the following functions:

* `tcp_v4_connect` (kprobe/kretprobe)
* `tcp_v6_connect` (kprobe/kretprobe)
* `tcp_set_state` (kprobe)
* `tcp_close` (kprobe)
* `inet_csk_accept` (kretprobe)

This gives us the ability to emit events when a new connection is established,
when a connection is closed, and when an incoming connection is accepted.

To trace connect events, users need to enable the `tcp_set_state` handler,
apart from the `tcp_v4_connect` one for IPv4 connections, and `tcp_v6_connect`
for IPv6 connections.

To trace close and accept events, enabling the corresponding handlers is
sufficient.

## Example

Here we enable all network handlers:

```
# build/bin/traceleft trace battery/out/handle_network_*
name connect_v4 pid 5435 program id 0 return value 0 Saddr 192.168.35.127 Daddr 172.217.16.174 Sport 50630 Dport 80 Netns 4026531973
name close_v4 pid 5435 program id 0 return value 0 Saddr 192.168.35.127 Daddr 172.217.16.174 Sport 50630 Dport 80 Netns 4026531973
name close_v6 pid 5471 program id 0 return value 0 Saddr ::1 Daddr ::1 Sport 39192 Dport 9090 Netns 4026531973
name connect_v4 pid 5471 program id 0 return value 0 Saddr 127.0.0.1 Daddr 127.0.0.1 Sport 49956 Dport 9090 Netns 4026531973
name accept_v4 pid 5468 program id 0 return value 0 Saddr 127.0.0.1 Daddr 127.0.0.1 Sport 9090 Dport 49956 Netns 4026531973
name connect_v6 pid 5513 program id 0 return value 0 Saddr ::1 Daddr ::1 Sport 34646 Dport 8080 Netns 4026531973
name accept_v6 pid 5512 program id 0 return value 0 Saddr ::1 Daddr ::1 Sport 8080 Dport 34646 Netns 4026531973
```

## Kernel Compatibility

Since we're tracing internal kernel functions and we access internal kernel
structures, these can change at any time. This means we need to compile the
handlers for the particular kernel version where they will run. This is not yet
implemented, we compile with whatever the Fedora 26 Docker image ships.
