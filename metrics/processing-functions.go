// functions and output functions

package metrics

import (
	"strconv"
	"strings"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

type processingFunc interface {
	process(*tracer.EventData, string) *tracer.EventData
}

/* sigma */

func init() {
	processingFuncBuilder["sigma"] = func(a *Aggregator, i int) processingFunc {
		return &sigma{
			counter: make(map[uint64]int),
		}
	}
}

type sigma struct {
	counter map[uint64]int
}

func (s sigma) process(ev *tracer.EventData, params string) *tracer.EventData {
	if s.counter == nil {
		s.counter = make(map[uint64]int)
	}
	c, _ := s.counter[ev.Common.Hash]

	p := parseParams(params)

	if c > p["frequency"] {
		s.counter[ev.Common.Hash] = 0
		return ev
	}

	s.counter[ev.Common.Hash]++

	return nil
}

func parseParams(params string) map[string]int {
	ret := make(map[string]int)
	parts := strings.Split(params, ";")

	for _, pt := range parts {
		param := strings.Split(pt, "=")
		if len(param) != 2 {
			continue
		}

		val, err := strconv.Atoi(param[1])
		if err != nil {
			continue
		}

		ret[param[0]] = val
	}

	return ret
}
