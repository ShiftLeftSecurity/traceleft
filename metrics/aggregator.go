package metrics

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

type Aggregator struct {
	sync.Mutex

	stop chan bool

	conn   *grpc.ClientConn
	client tracer.MetricCollectorClient

	collection []*tracer.Metric

	eventHashes map[uint64]*tracer.Metric

	intervalMilliseconds time.Duration
}

type AggregatorOptions struct {
	CollectorAddr string
	DialInsecure  bool
}

func NewAggregator(opts AggregatorOptions, incoming <-chan *tracer.EventData, intervalMilliseconds time.Duration) (*Aggregator, error) {
	var dialOptions []grpc.DialOption
	if opts.DialInsecure {
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		serverName := strings.Split(opts.CollectorAddr, ":")[0]
		creds := credentials.NewClientTLSFromCert(nil, serverName)
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(creds))
	}
	conn, err := grpc.Dial(opts.CollectorAddr, dialOptions...)
	if err != nil {
		return nil, err
	}

	aggregator := &Aggregator{
		conn:                 conn,
		client:               tracer.NewMetricCollectorClient(conn),
		stop:                 make(chan bool),
		eventHashes:          make(map[uint64]*tracer.Metric),
		intervalMilliseconds: intervalMilliseconds,
	}

	ticker := time.NewTicker(intervalMilliseconds * time.Millisecond).C

	go func() {
		for {
			select {
			case <-aggregator.stop:
				return
			case <-ticker:
				err := aggregator.send()
				if err != nil {
					log.Printf("failed to send event collection: %s\n", err)
				}
			case event, ok := <-incoming:
				if !ok {
					return
				}
				aggregator.add(event)
				if len(aggregator.eventHashes) > 1000 {
					err := aggregator.send()
					if err != nil {
						log.Printf("failed to send event collection: %s\n", err)
					}
				}
			}
		}
	}()

	return aggregator, nil
}

func (a *Aggregator) add(event *tracer.EventData) {
	a.Lock()
	defer a.Unlock()

	var metric *tracer.Metric
	if metric, seen := a.eventHashes[event.Common.Hash]; seen {
		metric.Count++
		return
	}

	metric = event.Event.Metric()
	metric.Count++
	metric.CommonEvent = event.Common.Proto()

	a.eventHashes[event.Common.Hash] = metric

	a.collection = append(a.collection, metric)
}

func (a *Aggregator) send() error {
	a.Lock()
	defer a.Unlock()

	log.Printf("sending %d events ...\n", len(a.collection))

	stream, err := a.client.Process(context.Background())
	if err != nil {
		return err
	}

	for _, metric := range a.collection {
		if err := stream.Send(metric); err != nil {
			return err
		}
	}

	log.Printf("sending %d events ... finished\n", len(a.collection))

	_, err = stream.CloseAndRecv()
	if err != nil {
		return err
	}

	a.collection = nil
	a.eventHashes = make(map[uint64]*tracer.Metric)
	return nil
}

func (a *Aggregator) Stop() {
	a.stop <- true
	a.conn.Close()
}
