// +build linux

// Copyright 2016 Cilium Project
// Copyright 2016 Sylvain Afchain
// Copyright 2016 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elf

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
)

/*
#include <unistd.h>
#include <strings.h>
#include "include/bpf.h"
#include <linux/perf_event.h>
#include <linux/unistd.h>

static int perf_event_open_tracepoint(int tracepoint_id, int pid, int cpu,
                           int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = tracepoint_id;

	return syscall(__NR_perf_event_open, &attr, pid, cpu,
                      group_fd, flags);
}

int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.target_fd	   = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type   = type;

	// BPF_PROG_ATTACH = 8
	return syscall(__NR_bpf, 8, &attr, sizeof(attr));
}
*/
import "C"

type Module struct {
	fileName   string
	fileReader io.ReaderAt
	file       *elf.File

	log            []byte
	maps           map[string]*Map
	probes         map[string]*Kprobe
	cgroupPrograms map[string]*CgroupProgram
}

// Kprobe represents a kprobe or kretprobe and has to be declared
// in the C file,
type Kprobe struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
	efd   int
}

type AttachType int

const (
	IngressType AttachType = iota
	EgressType
	SockCreateType
)

// CgroupProgram represents a cgroup skb/sock program
type CgroupProgram struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
}

func NewModule(fileName string) *Module {
	return &Module{
		fileName:       fileName,
		probes:         make(map[string]*Kprobe),
		cgroupPrograms: make(map[string]*CgroupProgram),
		log:            make([]byte, 65536),
	}
}

func NewModuleFromReader(fileReader io.ReaderAt) *Module {
	return &Module{
		fileReader: fileReader,
		probes:     make(map[string]*Kprobe),
		log:        make([]byte, 65536),
	}
}

var kprobeIDNotExist error = errors.New("kprobe id file doesn't exist")

func writeKprobeEvent(probeType, eventName, funcName, maxactiveStr string) (int, error) {
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, fmt.Errorf("cannot open kprobe_events: %v\n", err)
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	_, err = f.WriteString(cmd)
	if err != nil {
		return -1, fmt.Errorf("cannot write %q to kprobe_events: %v\n", cmd, err)
	}

	kprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIdBytes, err := ioutil.ReadFile(kprobeIdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, kprobeIDNotExist
		}
		return -1, fmt.Errorf("cannot read kprobe id: %v\n", err)
	}

	kprobeId, err := strconv.Atoi(strings.TrimSpace(string(kprobeIdBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid kprobe id: %v\n", err)
	}

	return kprobeId, nil
}

// EnableKprobe enables a kprobe/kretprobe identified by secName.
// For kretprobes, you can configure the maximum number of instances
// of the function that can be probed simultaneously with maxactive.
// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
// For kprobes, maxactive is ignored.
func (b *Module) EnableKprobe(secName string, maxactive int) error {
	var probeType, funcName string
	isKretprobe := strings.HasPrefix(secName, "kretprobe/")
	probe, ok := b.probes[secName]
	if !ok {
		return fmt.Errorf("no such kprobe %q", secName)
	}
	progFd := probe.fd
	var maxactiveStr string
	if isKretprobe {
		probeType = "r"
		funcName = strings.TrimPrefix(secName, "kretprobe/")
		if maxactive > 0 {
			maxactiveStr = fmt.Sprintf("%d", maxactive)
		}
	} else {
		probeType = "p"
		funcName = strings.TrimPrefix(secName, "kprobe/")
	}
	eventName := probeType + funcName

	kprobeId, err := writeKprobeEvent(probeType, eventName, funcName, maxactiveStr)
	// fallback without maxactive
	if err == kprobeIDNotExist {
		kprobeId, err = writeKprobeEvent(probeType, eventName, funcName, "")
	}
	if err != nil {
		return err
	}

	efd := C.perf_event_open_tracepoint(C.int(kprobeId), -1 /* pid */, 0 /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return fmt.Errorf("perf_event_open for kprobe error")
	}

	_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_ENABLE, 0)
	if err2 != 0 {
		return fmt.Errorf("error enabling perf event: %v", err2)
	}

	_, _, err2 = syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_SET_BPF, uintptr(progFd))
	if err2 != 0 {
		return fmt.Errorf("error enabling perf event: %v", err2)
	}
	probe.efd = int(efd)
	return nil
}

// IterKprobes returns a channel that emits the kprobes that included in the
// module.
func (b *Module) IterKprobes() <-chan *Kprobe {
	ch := make(chan *Kprobe)
	go func() {
		for name := range b.probes {
			ch <- b.probes[name]
		}
		close(ch)
	}()
	return ch
}

// EnableKprobes enables all kprobes/kretprobes included in the module. The
// value in maxactive will be applied to all the kretprobes.
func (b *Module) EnableKprobes(maxactive int) error {
	var err error
	for _, kprobe := range b.probes {
		err = b.EnableKprobe(kprobe.Name, maxactive)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *Module) IterCgroupProgram() <-chan *CgroupProgram {
	ch := make(chan *CgroupProgram)
	go func() {
		for name := range b.cgroupPrograms {
			ch <- b.cgroupPrograms[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) CgroupProgram(name string) *CgroupProgram {
	return b.cgroupPrograms[name]
}

func (b *Module) AttachCgroupProgram(cgroupProg *CgroupProgram, cgroupPath string, attachType AttachType) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("error opening cgroup %q: %v", cgroupPath, err)
	}
	defer f.Close()

	progFd := C.int(cgroupProg.fd)
	cgroupFd := C.int(f.Fd())
	ret, err := C.bpf_prog_attach(progFd, cgroupFd, uint32(attachType))
	if ret < 0 {
		return fmt.Errorf("failed to attach prog to cgroup %q: %v\n", cgroupPath, err)
	}

	return nil
}
