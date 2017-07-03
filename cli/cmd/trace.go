package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"unsafe"

	"github.com/spf13/cobra"

	"github.com/ShiftLeftSecurity/traceleft/probe"
	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

import "C"

type Event struct {
	Pids    []int
	ELFPath string
}

var (
	traceCmd = &cobra.Command{
		Use:   "trace [<pid>:]<path elf object> ...",
		Short: "Trace processes",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must pass at least one comma-separated [<pid>:]<path elf object> pair")
			}
			return nil
		},
		Run: cmdTrace,
	}

	handlerCacheSize int
)

func init() {
	traceCmd.Flags().IntVar(&handlerCacheSize, "handler-cache-size", 4, "size of the eBPF handler cache")
}

func cmdTrace(cmd *cobra.Command, args []string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	tracer, err := tracer.New(handleEvent, handlerCacheSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	events, err := parseEventMap(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse events to trace: %v\n", err)
		os.Exit(1)
	}

	if err := registerEvents(tracer.Probe, events); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register events to trace: %v\n", err)
		os.Exit(1)
	}

	<-sig
	tracer.Stop()
}

func init() {
	RootCmd.AddCommand(traceCmd)
}

func dispatchToLog(syscall *C.char, buf *bytes.Buffer, ret int64) error {
	event, err := tracer.GetStruct(C.GoString(syscall), buf)
	if err != nil {
		return err
	}
	fmt.Println(event.String(ret))
	return nil
}

func handleEvent(data *[]byte) {
	var cev tracer.CommonEvent
	buf := bytes.NewBuffer(*data)
	err := binary.Read(buf, binary.LittleEndian, &cev)
	if err != nil {
		fmt.Printf("failed to decode received data: %v\n", err)
		return
	}
	syscall := (*C.char)(unsafe.Pointer(&cev.Syscall))
	fmt.Printf("syscall %s pid %d return value %d ",
		C.GoString(syscall), cev.Pid, cev.Ret)
	err = dispatchToLog(syscall, buf, cev.Ret)
	if err != nil {
		fmt.Printf("failed to dispatch event for log: %v\n", err)
		return
	}

}

func registerEvents(p *probe.Probe, events []Event) error {
	for _, event := range events {
		elfBPFBytes, err := ioutil.ReadFile(event.ELFPath)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", event.ELFPath, err)
		}

		for _, pid := range event.Pids {
			if err := p.RegisterHandler(pid, elfBPFBytes); err != nil {
				return fmt.Errorf("error registering handler: %v", err)
			}
		}
	}

	return nil
}

func parseEventMap(eventMaps []string) ([]Event, error) {
	var events []Event
	for _, eventMap := range eventMaps {
		evParts := strings.Split(eventMap, ":")
		if len(evParts) > 2 {
			return nil, fmt.Errorf("malformed event-map %q", eventMap)
		}
		if len(evParts) == 1 {
			ebpfFile := evParts[0]
			event := Event{
				Pids:    []int{0},
				ELFPath: ebpfFile,
			}
			events = append(events, event)
			continue
		}
		pidsStr := evParts[0]
		pidParts := strings.Split(pidsStr, ",")
		var pids []int
		for _, pidStr := range pidParts {
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				return nil, fmt.Errorf("malformed pid %q in event-map", pidStr)
			}
			pids = append(pids, pid)
		}

		ebpfFile := evParts[1]

		event := Event{
			Pids:    pids,
			ELFPath: ebpfFile,
		}
		events = append(events, event)
	}
	return events, nil
}
