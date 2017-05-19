# traceleft

## Instructions

```
$ make
$ ./example --build-events config.json
$ make
$ sudo ./example --event-map $PID1,$PID2:battery/out/handle_read.bpf;$PID3:battery/out/handle_chown.bpf
```
