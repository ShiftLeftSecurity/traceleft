# TraceLeft Profiling & Performance

## `pprof`

TraceLeft offers [HTTP endpoints with profiling information](https://golang.org/pkg/net/http/pprof/).
To enable them, use `--pprof-listen-addr=localhost:9090`.
Then, you can access one of the profiling endpoint:

```bash
go tool pprof http://localhost:9090/debug/pprof/heap
go tool pprof http://localhost:9090/debug/pprof/profile
```

## eBPF Performance

eBPF programs run in the kernel and their CPU usage are not accounted in the
`traceleft` process. This can be monitored with:

```bash
sudo perf top
```

Then, look for `__bpf_prog_run`.

## Performance Tests with `nginx`

First, start a nginx container

```
docker run -ti --net=host nginx
```

Then, in a second terminal, trace the `nginx` worker process:

```
sudo ./build/bin/traceleft trace --pprof-listen-addr=localhost:9090 \
  $(for h in battery/out/*; do echo -n "$(pgrep -f 'nginx: worker'):$h "; done)
```

Finally, in a third terminal, start generating a lot of requests:

```
while true; do curl localhost; done
```

With `top` and `perf top` you should see that even with a lot of requests
resource usage is fairly moderate.
