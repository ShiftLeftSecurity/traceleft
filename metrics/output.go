// functions and output functions

package metrics

import (
	"time"
)

type outputFunc interface {
	channel() chan *SendEvent
	process(d time.Duration, aggregator *Aggregator)
}

/* alerts_per_sec */

func init() {
	outputFuncBuilder["alerts_per_sec"] = func(a *Aggregator, i int) outputFunc {
		o := &eventsPerS{
			ch:      make(chan *SendEvent),
			counter: 0,
		}
		go o.process(time.Second, a)
		return o
	}
}

type eventsPerS struct {
	ch      chan *SendEvent
	counter int
}

func (e eventsPerS) process(d time.Duration, aggregator *Aggregator) {
	ticker := time.NewTicker(d).C
	var savedEv *SendEvent
	for {
		select {
		case event, ok := <-e.ch:
			if !ok {
				continue
			}
			savedEv = event
			e.counter++
		case <-ticker:
			if savedEv != nil {
				savedEv.counter = e.counter
				aggregator.send(savedEv)
				savedEv = nil
			}
			e.counter = 0
		}
	}
}

func (e eventsPerS) channel() chan *SendEvent {
	return e.ch
}
