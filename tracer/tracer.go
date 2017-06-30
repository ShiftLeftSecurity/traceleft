package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	elflib "github.com/iovisor/gobpf/elf"

	"github.com/ShiftLeftSecurity/traceleft/probe"
)

// this has to match the struct in trace_syscalls.c and handlers.
type CommonEvent struct {
	Timestamp uint64
	Pid       int64
	Ret       int64
	Syscall   [64]byte
}

type Tracer struct {
	Probe    *probe.Probe
	perfMap  *elflib.PerfMap
	stopChan chan struct{}
}

func timestamp(data *[]byte) uint64 {
	var event CommonEvent
	err := binary.Read(bytes.NewBuffer(*data), binary.LittleEndian, &event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "timestamp() failed to decode received data: %v\n", err)
		return 0
	}

	return uint64(event.Timestamp)
}

func New(callback func(*[]byte), cacheSize int) (*Tracer, error) {
	p, err := probe.New(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("error loading probe: %v", err)
	}

	channel := make(chan []byte)
	perfMap, err := elflib.InitPerfMap(p.BPFModule(), "events", channel, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf map: %v", err)
	}

	perfMap.SetTimestampFunc(timestamp)

	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			case data := <-channel:
				go callback(&data)
			}
		}
	}()

	perfMap.PollStart()

	return &Tracer{
		Probe:    p,
		perfMap:  perfMap,
		stopChan: stopChan,
	}, nil
}

func (t *Tracer) Stop() {
	t.perfMap.PollStop()
	close(t.stopChan)

	t.Probe.Close()
}
