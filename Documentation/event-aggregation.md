# Event aggregation

Because of the large amount of events, it is not possible to send all of them
to a server. Instead, an aggregation spec specifies how to reduce that large
amount of data to a smaller set that can be sent.

## Traceleft API

The CLI tool (cli/cmd/trace.go) gives an example how to use the API. The
classic way to use the API is to have the tracer on one side getting the events
and forwarding them through a Golang channel to the aggregator.

The aggregator is created via `metrics.NewAggregator(...)`. The aggregator
handles the events according to the aggregation spec defined below.

## Aggregation spec

`examples/aggregator-spec.json`

```json
{
    "channels": [
        {
            "id": "1",
            "type": "file",
            "path": "/tmp/traceleft.log"
        },
        {
            "id": "2",
            "type": "grpc",
            "path": "localhost:50051"
        }
    ],
    "events": [
        {
            "name": "open",
            "channel": "1",
            "stream": "filesystem",
            "group": "system_metrics",
            "rule": "arg1 == '/tmp/a.txt'",
            "function": {
                "id": "sigma",
                "parameters": "frequency=100;threshold=0"
            },
            "output": {
                "metrics": "alerts_per_sec",
                "format": "collector_spec_pb"
            }
        }
    ]
}
```

### Channels

The aggregation spec can define several channels. Traceleft supports two kinds of
channels:

- "file": writing the events in a file in a text format
- "grpc": send the events through a gRPC socket


### Event filters

The aggregation spec can define several event filters. Each event filter has:

- a rule defining specifying which events it cares about
- a processing function executed for each received
- an output function defining what is reported to the channel and how


### Processing functions

Currently one processing function is defined: "sigma". It has the following
parameters:

- "frequency": how many events to receive before passing an event to the output function
- "threshold": currently unimplemented

### Output functions

Currently one output function is defined: "alerts\_per\_sec". It just sends one
event per second with a counter.

- "format": currently unimplemented.

## Implementation

The aggregator is implemented in the `metrics` directory.

- `aggregator.go`: define the aggregator object
- `spec.go`: define the aggregation spec
- `processing-functions.go`: define the processing functions
- `output.go`: define the output functions

## Testing

Start the gRPC listener (server-side):
```
go run metrics/echoserver/main.go
```

Start the agent:
```
touch /tmp/traceleft.log
sudo ./build/bin/traceleft trace --collector-insecure --aggregation-spec examples/aggregator-spec.json battery/out/handle_syscall_open.bpf
```

Generate events:
```
while true ; do echo -n > /tmp/a.txt ; done
```

## Limitations

* Unimplemented yet:
  - The aggregation code should be rewritten to be more readable
  - File descriptors are not translated to paths on gRPC
  - The rule parsing and matching are not implemented yet. This is currently hard-coded.
  - The rule matching cannot match paths based on a file descriptor yet.
