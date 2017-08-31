package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peterh/liner"

	"github.com/ShiftLeftSecurity/traceleft/probe"
	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

import "C"

var (
	historyFn = filepath.Join(os.TempDir(), ".liner_example_history")

	commandsUsage = map[string]string{
		"trace":      "trace <program_id> <pid>[,<pid>...] <path elf object>",
		"stop":       "stop <program_id> <pid>[,<pid>...]",
		"sleep":      "sleep <sec>",
		"write-file": "write-file <file> <string>",
		"help":       "help [<cmd>]",
	}

	outfile     string
	outfileLock sync.Mutex

	ctx              tracer.Context
	handlerCacheSize int

	quiet bool
)

func init() {
	flag.StringVar(&outfile, "outfile", "", "where to write output to (defaults to stdout)")
	flag.IntVar(&handlerCacheSize, "handler-cache-size", 4, "size of the eBPF handler cache")
	flag.BoolVar(&quiet, "quiet", false, "be quiet")
	ctx.Fds = tracer.NewFdMap()
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

func cmdTrace(args []string, p *probe.Probe) error {
	if len(args) != 3 {
		return fmt.Errorf("invalid args (usage: %s): %v", commandsUsage["trace"], args)
	}
	programID, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return fmt.Errorf("malformed program id %q", args[0])
	}
	pids, err := parsePids(args[1])
	if err != nil {
		return err
	}
	eBPFFile := args[2]
	elfBPFBytes, err := ioutil.ReadFile(eBPFFile)
	if err != nil {
		return fmt.Errorf("error reading %q: %v", eBPFFile, err)
	}
	for _, pid := range pids {
		if err := p.RegisterHandler(programID, pid, elfBPFBytes); err != nil {
			return fmt.Errorf("error registering handler: %v", err)
		}
	}
	return nil
}

func cmdStop(args []string, p *probe.Probe) error {
	if len(args) != 2 {
		return fmt.Errorf("invalid args (usage: %s): %v", commandsUsage["stop"], args)
	}
	programID, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return fmt.Errorf("malformed program id %q", args[0])
	}
	pids, err := parsePids(args[1])
	if err != nil {
		return err
	}
	for _, pid := range pids {
		if err := p.UnregisterHandler(programID, pid); err != nil {
			return fmt.Errorf("error unregistering handler: %v", err)
		}
	}
	return nil
}

func cmdSleep(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("invalid args (usage: %s): %v", commandsUsage["sleep"], args)
	}
	t, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(t) * time.Second)
	return nil
}

func cmdWriteFile(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("invalid args (usage: %s): %v", commandsUsage["write-file"], args)
	}
	file := args[0]
	toWrite := strings.Join(args[1:], " ")
	return ioutil.WriteFile(file, []byte(toWrite), 0644)
}

func cmdHelp(args []string) error {
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "%s\n", commandsUsage["help"])
	} else if len(args) == 1 {
		fmt.Fprintf(os.Stderr, "%s\n", commandsUsage[args[0]])
	} else {
		for _, usageStr := range commandsUsage {
			fmt.Fprintf(os.Stderr, "%s\n", usageStr)
		}
	}
	return nil
}

func writeToOutfile(msg string) {
	outfileLock.Lock()
	defer outfileLock.Unlock()

	f, err := os.OpenFile(outfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %q: %v\n", outfile, err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(msg + "\n"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %q to %q: %v\n", msg, outfile, err)
	}
}

func handleEvent(data *[]byte) {
	buf := bytes.NewBuffer(*data)
	commonEvent, err := tracer.CommonEventFromBuffer(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode common event data: %v\n", err)
		return
	}
	msg := fmt.Sprintf("event %s pid %d return value %d ", commonEvent.Name, commonEvent.Pid, commonEvent.Ret)
	event, err := tracer.GetStruct(commonEvent, ctx, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get %q struct: %v\n", commonEvent.Name, err)
		return
	}

	eventStr := event.String(commonEvent.Ret)
	if commonEvent.Name == "fd_install" {
		return
	}

	if outfile != "" {
		go writeToOutfile(msg + eventStr)
	} else {
		fmt.Println(msg + eventStr)
	}
}

func main() {
	flag.Parse()

	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(false)

	line.SetCompleter(func(line string) (c []string) {
		for n := range commandsUsage {
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

	tracer, err := tracer.New(handleEvent, handlerCacheSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get tracer: %v\n", err)
		os.Exit(1)
	}
	defer tracer.Stop()

	if !quiet {
		fmt.Printf("Press ^D to write history file and exit\n")
	}
	for {
		l, err := line.Prompt("$ ")
		if err != nil {
			break
		}
		if l == "" {
			continue
		}
		line.AppendHistory(l)
		lineParts := strings.Split(l, " ")

		command := lineParts[0]
		args := lineParts[1:]

		switch command {
		case "sleep":
			err = cmdSleep(args)
		case "trace":
			err = cmdTrace(args, tracer.Probe)
		case "stop":
			err = cmdStop(args, tracer.Probe)
		case "write-file":
			err = cmdWriteFile(args)
		case "help":
			cmdHelp(args)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Command failed: %v\n", err)
		}
	}

	if !quiet {
		fmt.Printf("\nStopping ...\n")
	}
	if f, err := os.Create(historyFn); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing history file: %v\n", err)
	} else {
		line.WriteHistory(f)
		f.Close()
	}
}
