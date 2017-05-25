# traceleft

## Instructions

```
make
bin/slagent gen-handler
make
sudo bin/slagent trace $PID1,$PID2:battery/out/handle_read.bpf $PID3:battery/out/handle_chown.bpf
```
