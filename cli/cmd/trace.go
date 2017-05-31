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

	elflib "github.com/iovisor/gobpf/elf"
	"github.com/spf13/cobra"

	"github.com/ShiftLeftSecurity/traceleft/probe"
	"github.com/ShiftLeftSecurity/traceleft/tracer"
	"reflect"
)

import "C"

type Event struct {
	Pids    []int
	ELFPath string
}

var traceCmd = &cobra.Command{
	Use:   "trace <pid>:<path elf object> ...",
	Short: "Trace processes",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("must pass at least one comma-separated <pid>:<path elf object> pair")
		}
		return nil
	},
	Run: cmdTrace,
}

func cmdTrace(cmd *cobra.Command, args []string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	tracer, err := tracer.New(handleEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	events, err := parseEventMap(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse events to trace: %v\n", err)
		os.Exit(1)
	}

	if err := registerEvents(tracer.BPFModule(), events); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to register events to trace: %v\n", err)
		os.Exit(1)
	}

	<-sig
	tracer.Stop()
}

func init() {
	RootCmd.AddCommand(traceCmd)
}

var SyscallEventMap = map[string]interface{}{
	"open":     tracer.OpenEvent{},
	"close":    tracer.CloseEvent{},
	"read":     tracer.ReadEvent{},
	"write":    tracer.WriteEvent{},
	"mkdir":    tracer.MkdirEvent{},
	"mkdirat":  tracer.MkdiratEvent{},
	"chmod":    tracer.ChmodEvent{},
	"fchmod":   tracer.FchmodEvent{},
	"fchmodat": tracer.FchmodatEvent{},
	"chown":    tracer.ChownEvent{},
	"fchown":   tracer.FchownEvent{},
	"fchownat": tracer.FchownatEvent{},
}

// Assume buffer truncates at 0
func bufLen(buf []byte) int {
	for idx := 0; idx < len(buf); idx++ {
		if buf[idx] == 0 {
			return idx
		}
	}
	return len(buf)
}

func dispatchToLog(syscall *C.char, buf *bytes.Buffer) error {
	event := SyscallEventMap[C.GoString(syscall)]
	ev := reflect.New(reflect.TypeOf(event)).Interface()
	err := binary.Read(buf, binary.LittleEndian, ev)
	if err != nil {
		return err
	}

	// Get all structure elements, their types and values and print them
	// TODO : use decent logging later on
	elem := reflect.ValueOf(ev).Elem()
	for i := 0; i < elem.NumField(); i++ {
		eType := elem.Type().Field(i).Type.Kind()
		eName := elem.Type().Field(i).Name
		eVal := elem.Field(i)
		switch eType.String() {
		case "array":
			s := fmt.Sprintf("%s", eVal)
			strVal := s[:bufLen([]byte(s))]
			fmt.Print(eName, ": ", string(strVal), " ")
		default:
			fmt.Print(eName, ": ", eVal, " ")
		}
	}
	fmt.Println("")
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
	err = dispatchToLog(syscall, buf)
	if err != nil {
		fmt.Printf("failed to dispatch event for log: %v\n", err)
		return
	}

}

func registerEvents(bpfModule *elflib.Module, events []Event) error {
	for _, event := range events {
		elfBPFBytes, err := ioutil.ReadFile(event.ELFPath)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", event.ELFPath, err)
		}

		if err := probe.RegisterHandler(bpfModule, event.Pids, elfBPFBytes); err != nil {
			return fmt.Errorf("error registering handler: %v", err)
		}
	}

	return nil
}

func parseEventMap(eventMaps []string) ([]Event, error) {
	var events []Event
	for _, eventMap := range eventMaps {
		evParts := strings.Split(eventMap, ":")
		if len(evParts) != 2 {
			return nil, fmt.Errorf("malformed event-map %q", eventMap)
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
