package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/peterh/liner"

	elflib "github.com/iovisor/gobpf/elf"

	"github.com/ShiftLeftSecurity/traceleft/probe"
	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

import "C"

var (
	historyFn = filepath.Join(os.TempDir(), ".liner_example_history")
	commands  = []string{"trace", "stop", "sleep"}

	outfile     string
	outfileLock sync.Mutex
)

func init() {
	flag.StringVar(&outfile, "outfile", "", "where to write output to (defaults to stdout)")
}

type Event struct {
	Add     bool
	Pids    []int
	ELFPath string
}

func parsePids(pidsStr string) ([]int, error) {
	pidParts := strings.Split(pidsStr, ",")
	var pids []int
	for _, pidStr := range pidParts {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return nil, fmt.Errorf("malformed pid %q", pidStr)
		}
		pids = append(pids, pid)
	}

	return pids, nil
}

func parseEvent(line string) (*Event, error) {
	lineParts := strings.Split(line, " ")

	if lineParts[0] == "sleep" {
		if len(lineParts) != 2 {
			return nil, fmt.Errorf("malformed command %q", line)
		}
		t, err := strconv.Atoi(lineParts[1])
		if err != nil {
			return nil, err
		}
		time.Sleep(time.Duration(t) * time.Second)
		return nil, nil
	}

	if len(lineParts) != 3 {
		return nil, fmt.Errorf("malformed command %q", line)
	}

	var add bool
	switch lineParts[0] {
	case "trace":
		add = true
	case "stop":
		add = false
	default:
		return nil, fmt.Errorf("command not found %q", lineParts[0])
	}

	pids, err := parsePids(lineParts[1])
	if err != nil {
		return nil, err
	}
	ebpfFile := lineParts[2]

	return &Event{
		Add:     add,
		Pids:    pids,
		ELFPath: ebpfFile,
	}, nil
}

func registerEvent(bpfModule *elflib.Module, event Event) error {
	elfBPFBytes, err := ioutil.ReadFile(event.ELFPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %v", event.ELFPath, err)
	}

	if event.Add {
		if err := probe.RegisterHandler(bpfModule, event.Pids, elfBPFBytes); err != nil {
			return fmt.Errorf("error registering handler: %v", err)
		}
	} else {
		return fmt.Errorf("stop not implemented yet")
	}

	return nil
}

func writeToOutfile(msg string) {
	outfileLock.Lock()
	defer outfileLock.Unlock()

	err := ioutil.WriteFile(outfile, []byte(msg), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %q to %q: %v\n", msg, outfile, err)
	}
}

func handleEvent(data *[]byte) {
	var cev tracer.CommonEvent
	buf := bytes.NewBuffer(*data)
	err := binary.Read(buf, binary.LittleEndian, &cev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode received data: %v\n", err)
		return
	}
	syscallCstr := (*C.char)(unsafe.Pointer(&cev.Syscall))
	syscallName := C.GoString(syscallCstr)
	msg := fmt.Sprintf("syscall %s pid %d return value %d\n", syscallName, cev.Pid, cev.Ret)
	event, err := tracer.GetStruct(syscallName, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get %q struct: %v\n", syscallName, err)
		return
	}
	if outfile != "" {
		go writeToOutfile(msg + event.String(cev.Ret))
	} else {
		fmt.Print(msg + event.String(cev.Ret))
	}
}

func main() {
	flag.Parse()

	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(false)

	line.SetCompleter(func(line string) (c []string) {
		for _, n := range commands {
			if strings.HasPrefix(n, strings.ToLower(line)) {
				c = append(c, n)
			}
		}
		return
	})

	if f, err := os.Open(historyFn); err == nil {
		line.ReadHistory(f)
		f.Close()
	}

	tracer, err := tracer.New(handleEvent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get tracer: %v\n", err)
		os.Exit(1)
	}
	defer tracer.Stop()

	for {
		if l, err := line.Prompt("$ "); err == nil {
			if l == "" {
				continue
			}
			line.AppendHistory(l)
			ev, err := parseEvent(l)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
				continue
			}
			if ev == nil {
				continue
			}

			if err := registerEvent(tracer.BPFModule(), *ev); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to register event: %v\n", err)
				continue
			}
		} else {
			break
		}
	}

	if f, err := os.Create(historyFn); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing history file: %v\n", err)
	} else {
		line.WriteHistory(f)
		f.Close()
	}
}
