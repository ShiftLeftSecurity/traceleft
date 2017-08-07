package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ShiftLeftSecurity/traceleft/metrics"
	"github.com/ShiftLeftSecurity/traceleft/probe"
	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

// #include <inttypes.h>
// #include "../../bpf/events-struct.h"
import "C"

type Event struct {
	ProgramID uint64
	Pids      []int
	ELFPath   string
}

var (
	traceCmd = &cobra.Command{
		Use:   "trace [[program_id:]<pid>:]<path elf object> ...",
		Short: "Trace processes",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("must pass at least one comma-separated [<pid>:]<path elf object> pair")
			}
			return nil
		},
		Run: cmdTrace,
	}
	ctx tracer.Context

	handlerCacheSize      int
	collectorWithInsecure bool
	aggregationSpecPath   string
)

func init() {
	traceCmd.Flags().IntVar(&handlerCacheSize, "handler-cache-size", 4, "size of the eBPF handler cache")
	traceCmd.Flags().BoolVar(&collectorWithInsecure, "collector-insecure", false, "disable transport security for collector connection")
	ctx.Fds = tracer.NewFdMap()
	traceCmd.Flags().StringVar(&aggregationSpecPath, "aggregation-spec", "", "path to the aggregation spec in json format")
}

var eventChan chan *tracer.EventData

func cmdTrace(cmd *cobra.Command, args []string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	eventChan = make(chan *tracer.EventData)

	var spec metrics.AggregationSpec

	if aggregationSpecPath != "" {
		b, err := ioutil.ReadFile(aggregationSpecPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read aggregation spec: %v\n", err)
			os.Exit(1)
		}

		err = json.Unmarshal(b, &spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal aggregation spec: %v\n", err)
			os.Exit(1)
		}

		aggregator, err := metrics.NewAggregator(metrics.AggregatorOptions{
			collectorWithInsecure,
		}, eventChan, spec, ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get aggregator: %v\n", err)
			os.Exit(1)
		}
		defer aggregator.Stop()
	} else {
		go func() {
			for event := range eventChan {
				if event.Common.Name == "fd_install" {
					continue
				}

				containerStr := ""
				if isContainer(event.Common.Pid) {
					containerStr = "[container]"
				}

				errorStr := ""
				if event.Common.Flags == C.COMMON_EVENT_FLAG_INCOMPLETE_PROBE_READ {
					errorStr = "[incomplete]"
				}

				evString := event.Event.String(event.Common.Ret)
				fmt.Printf("name %s pid %d program id %d return value %d hash %d %s%s%s\n",
					event.Common.Name, event.Common.Pid, event.Common.ProgramID, event.Common.Ret, event.Common.Hash, evString, containerStr, errorStr)
			}
		}()
	}

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

	go func() {
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			fmt.Fprintf(os.Stderr, "http server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	<-sig
	tracer.Stop()
	ctx.Fds.Clear()
}

func init() {
	RootCmd.AddCommand(traceCmd)
}

func isContainer(pid int64) bool {
	mntNs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return false
	}
	hostMntNs, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return false
	}

	return mntNs != hostMntNs
}

func handleEvent(data *[]byte) {
	buf := bytes.NewBuffer(*data)
	commonEvent, err := tracer.CommonEventFromBuffer(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode received data: %v\n", err)
		return
	}
	event, err := tracer.GetStruct(commonEvent, ctx, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get event struct: %v\n", err)
		return
	}
	eventChan <- &tracer.EventData{
		*commonEvent,
		event,
	}
}

func registerEvents(p *probe.Probe, events []Event) error {
	for _, event := range events {
		elfBPFBytes, err := ioutil.ReadFile(event.ELFPath)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", event.ELFPath, err)
		}

		for _, pid := range event.Pids {
			if err := p.RegisterHandler(event.ProgramID, pid, elfBPFBytes); err != nil {
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
		if len(evParts) > 3 {
			return nil, fmt.Errorf("malformed event-map %q", eventMap)
		}

		// parse program_id
		var programID uint64 = 0
		if len(evParts) > 2 {
			var err error
			programIDStr := evParts[len(evParts)-3]
			programID, err = strconv.ParseUint(programIDStr, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("malformed program id %q in event-map", programIDStr)
			}
		}

		// parse pids
		var pids []int
		if len(evParts) > 1 {
			pidsStr := evParts[len(evParts)-2]
			pidParts := strings.Split(pidsStr, ",")
			for _, pidStr := range pidParts {
				pid, err := strconv.Atoi(pidStr)
				if err != nil {
					return nil, fmt.Errorf("malformed pid %q in event-map", pidStr)
				}
				pids = append(pids, pid)
			}
		} else {
			pids = []int{0}
		}

		// parse ebpf file
		ebpfFile := evParts[len(evParts)-1]

		event := Event{
			ProgramID: programID,
			Pids:      pids,
			ELFPath:   ebpfFile,
		}
		events = append(events, event)
	}
	return events, nil
}
