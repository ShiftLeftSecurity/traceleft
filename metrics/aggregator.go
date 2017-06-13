package metrics

import (
	"context"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

type Aggregator struct {
	sync.Mutex

	stop chan bool

	conn *grpc.ClientConn

	collector  tracer.MetricCollectorClient
	collection *tracer.MetricCollection

	eventHashes map[string]*tracer.Metric

	intervalMilliseconds time.Duration
}

func NewAggregator(incoming <-chan *tracer.EventData, intervalMilliseconds time.Duration) (*Aggregator, error) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	aggregator := &Aggregator{
		conn:                 conn,
		stop:                 make(chan bool),
		collector:            tracer.NewMetricCollectorClient(conn),
		collection:           &tracer.MetricCollection{},
		eventHashes:          make(map[string]*tracer.Metric),
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
			}
		}
	}()

	return aggregator, nil
}

func (a *Aggregator) add(event *tracer.EventData) {
	a.Lock()
	defer a.Unlock()

	hashCommonPart, err := event.Common.Hash()
	if err != nil {
		log.Printf("failed to generate hash\n")
		return
	}

	hashEventPart, err := event.Event.Hash()
	if err != nil {
		log.Printf("failed to generate hash\n")
		return
	}

	hash := hashCommonPart + hashEventPart

	var metric *tracer.Metric
	if metric, seen := a.eventHashes[hash]; seen {
		metric.Count++
		return
	}

	metric = event.Event.Metric()
	metric.Count++
	metric.CommonEvent = event.Common.Proto()

	a.eventHashes[hash] = metric

	a.collection.Metrics = append(a.collection.Metrics, metric)
}

func (a *Aggregator) send() error {
	a.Lock()
	defer a.Unlock()

	log.Printf("sending %d events\n", len(a.collection.Metrics))

	_, err := a.collector.Process(context.Background(), a.collection)
	if err != nil {
		return err
	}

	a.collection.Metrics = nil
	a.eventHashes = make(map[string]*tracer.Metric)
	return nil
}

func (a *Aggregator) Stop() {
	a.stop <- true
	a.conn.Close()
}
