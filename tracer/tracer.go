package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	elflib "github.com/iovisor/gobpf/elf"

	"github.com/ShiftLeftSecurity/traceleft/probe"
)
import "C"

// this has to match the struct in trace_syscalls.c and handlers.
type CommonEvent struct {
	Timestamp uint64
	Pid       int64
	Ret       int64
	Syscall   string
}

func CommonEventFromBuffer(buf *bytes.Buffer) (*CommonEvent, error) {
	if buf.Len() < 88 { // sizeof(event_t) = 88. See bpf/trace_syscalls.c.
		return nil, fmt.Errorf("expected buf.Len() >= 88, but go %d", buf.Len())
	}
	e := &CommonEvent{}
	e.Timestamp = binary.LittleEndian.Uint64(buf.Next(8))
	e.Pid = int64(binary.LittleEndian.Uint64(buf.Next(8)))
	e.Ret = int64(binary.LittleEndian.Uint64(buf.Next(8)))
	syscallBytes := buf.Next(64)
	syscallCstr := (*C.char)(unsafe.Pointer(&syscallBytes[0]))
	e.Syscall = C.GoString(syscallCstr)
	return e, nil
}

type Tracer struct {
	Probe    *probe.Probe
	perfMap  *elflib.PerfMap
	stopChan chan struct{}
}

func timestamp(data *[]byte) uint64 {
	return binary.LittleEndian.Uint64(*data)
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
