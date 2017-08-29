package metrics

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

var (
	/* factories initialized in output.go's and processing-functions.go's init() */
	processingFuncBuilder map[string]func(*Aggregator, int) processingFunc = make(map[string]func(*Aggregator, int) processingFunc)
	outputFuncBuilder     map[string]func(*Aggregator, int) outputFunc     = make(map[string]func(*Aggregator, int) outputFunc)
)

type Aggregator struct {
	stop chan bool

	// channels to output files and grpc
	channels map[string]aggregationChannel

	// see examples in examples/aggregator-spec.json
	aggregationSpec AggregationSpec

	tracerCtx tracer.Context
}

// internal types

type SendEvent struct {
	data    *tracer.EventData
	spec    *EventSpec
	counter int
}

func (e SendEvent) String(tracerCtx tracer.Context) string {
	return fmt.Sprintf("%+v %s", e.data.Common, e.data.Event.String(e.data.Common.Ret))
}

type ChannelKind int

const (
	File ChannelKind = iota
	Grpc
)

type aggregationChannel struct {
	Kind    ChannelKind
	Id      string
	Handler interface{}
}

type GrpcHandler struct {
	Conn   *grpc.ClientConn
	Client tracer.MetricCollectorClient
}

type AggregatorOptions struct {
	DialInsecure bool
}

func NewAggregator(opts AggregatorOptions, incoming <-chan *tracer.EventData, spec AggregationSpec, tracerCtx tracer.Context) (*Aggregator, error) {
	channels := make(map[string]aggregationChannel)
	for _, c := range spec.Channels {
		switch c.Type {
		case "file":
			f, err := os.OpenFile(c.Path, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return nil, fmt.Errorf("error opening output file %q: %v", c.Path, err)
			}

			channels[c.Id] = aggregationChannel{Kind: File, Id: c.Id, Handler: f}
		case "grpc":
			var dialOptions []grpc.DialOption
			if opts.DialInsecure {
				dialOptions = append(dialOptions, grpc.WithInsecure())
			} else {
				serverName := strings.Split(c.Path, ":")[0]
				creds := credentials.NewClientTLSFromCert(nil, serverName)
				dialOptions = append(dialOptions, grpc.WithTransportCredentials(creds))
			}

			conn, err := grpc.Dial(c.Path, dialOptions...)
			if err != nil {
				return nil, err
			}
			client := tracer.NewMetricCollectorClient(conn)

			h := GrpcHandler{
				Conn:   conn,
				Client: client,
			}

			channels[c.Id] = aggregationChannel{Kind: Grpc, Id: c.Id, Handler: h}
		}
	}

	aggregator := &Aggregator{
		channels:        channels,
		stop:            make(chan bool),
		aggregationSpec: spec,
	}

	for i := range spec.Events {
		spec.Events[i].F.state = processingFuncBuilder[spec.Events[i].F.Id](aggregator, i)
		spec.Events[i].O.state = outputFuncBuilder[spec.Events[i].O.Metrics](aggregator, i)
	}

	go func() {
		for {
			select {
			case <-aggregator.stop:
				return
			case event, ok := <-incoming:
				if !ok {
					return
				}
				aggregator.add(event)
			}
		}
	}()

	return aggregator, nil
}

func passesRule(event *tracer.EventData, rule string) bool {
	// TODO: don't hardcode parameter #0
	arg, err := event.Event.GetArgN(0, event.Common.Ret)
	if err != nil {
		return false
	}
	// TODO: don't hardcode filename
	if strings.Contains(arg, "/tmp/a.txt") {
		return true
	}
	return false
}

func considerEvent(event *tracer.EventData, spec AggregationSpec) (*EventSpec, bool) {
	for _, e := range spec.Events {
		if event.Common.Name == e.Name && passesRule(event, e.Rule) {
			return &e, true
		}
	}

	return nil, false
}

func (a *Aggregator) add(event *tracer.EventData) {
	eventSpec, ok := considerEvent(event, a.aggregationSpec)
	if !ok {
		return
	}

	processedEvent := eventSpec.F.state.process(event, eventSpec.F.Parameters)
	if processedEvent == nil {
		return
	}

	se := &SendEvent{
		data: processedEvent,
		spec: eventSpec,
	}

	eventSpec.O.state.channel() <- se
}

func writeEventToFile(w io.Writer, event *SendEvent, tracerCtx tracer.Context) error {
	evString := fmt.Sprintf("%s", event.String(tracerCtx))

	outString := fmt.Sprintf("COUNT: %d\nEVENT: %s\n\n", event.counter, evString)

	if _, err := io.WriteString(w, outString); err != nil {
		return fmt.Errorf("error writing to output file: %v", err)
	}

	return nil
}

func (a *Aggregator) send(se *SendEvent) error {
	log.Printf("sending event %v...\n", se.String(a.tracerCtx))

	event := se.data
	var ch aggregationChannel
	// TODO refactor
	for _, v := range a.channels {
		if se.spec.ChannelId == v.Id {
			ch = v
			break
		}
	}

	c, ok := a.channels[ch.Id]
	if !ok {
		return fmt.Errorf("channel %q not found", "2")
	}
	h := c.Handler

	switch ch.Kind {
	case File:
		if err := writeEventToFile(h.(io.Writer), se, a.tracerCtx); err != nil {
			return err
		}
	case Grpc:
		grpcHandler := h.(GrpcHandler)
		stream, err := grpcHandler.Client.Process(context.Background())
		if err != nil {
			return err
		}
		metric := event.Event.Metric()
		metric.Count++
		metric.CommonEvent = event.Common.Proto()

		if err := stream.Send(metric); err != nil {
			return err
		}

		_, err = stream.CloseAndRecv()
		if err != nil {
			return err
		}
	}

	log.Printf("sending event ... finished\n")

	return nil
}

func (a *Aggregator) Stop() {
	a.stop <- true
	for _, c := range a.channels {
		switch c.Kind {
		case File:
			c.Handler.(*os.File).Close()
		case Grpc:
			grpcHandler := c.Handler.(GrpcHandler)
			grpcHandler.Conn.Close()
		}
	}
}
