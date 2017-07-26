package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	elflib "github.com/iovisor/gobpf/elf"

	"github.com/ShiftLeftSecurity/traceleft/probe"
)

// #include <inttypes.h>
// #include "../bpf/events-struct.h"
import "C"

// this has to match the struct in cStructTemplate defined by metagenerator.go
type CommonEvent struct {
	Timestamp uint64
	ProgramID uint64
	Pid       int64
	Ret       int64
	Name      string
	Hash      uint64
}

func CommonEventFromBuffer(buf *bytes.Buffer) (*CommonEvent, error) {
	if buf.Len() < C.sizeof_common_event_t {
		return nil, fmt.Errorf("expected buf.Len() >= %d, but got %d", C.sizeof_common_event_t, buf.Len())
	}
	e := &CommonEvent{}
	e.Timestamp = binary.LittleEndian.Uint64(buf.Next(8))
	e.ProgramID = binary.LittleEndian.Uint64(buf.Next(8))
	e.Pid = int64(binary.LittleEndian.Uint64(buf.Next(8)))
	e.Ret = int64(binary.LittleEndian.Uint64(buf.Next(8)))
	nameBytes := buf.Next(64)
	nameCstr := (*C.char)(unsafe.Pointer(&nameBytes[0]))
	e.Name = C.GoString(nameCstr)
	e.Hash = binary.LittleEndian.Uint64(buf.Next(8))
	return e, nil
}

type EventData struct {
	Common CommonEvent
	Event  Event
}

type Tracer struct {
	Probe    *probe.Probe
	perfMap  *elflib.PerfMap
	stopChan chan struct{}
}

func (e *CommonEvent) Proto() *ProtobufCommonEvent {
	return &ProtobufCommonEvent{
		Timestamp: e.Timestamp,
		Pid:       e.Pid,
		Ret:       e.Ret,
		Name:      e.Name,
		Hash:      e.Hash,
	}
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
		return nil, fmt.Errorf("failed to init events perf map: %v", err)
	}

	perfMap.SetTimestampFunc(timestamp)

	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			case data := <-channel:
				callback(&data)
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
