package probe

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/iovisor/gobpf/bpffs"
	elflib "github.com/iovisor/gobpf/elf"
)

type Probe struct {
	sync.Mutex

	module *elflib.Module

	handler         map[string]*Handler
	handlerRefcount map[*Handler]int
	pidToHandlers   map[int][]*Handler
}

type Handler struct {
	module *elflib.Module

	id string

	name    string
	nameRet string

	fd    int
	fdRet int
}

func sha256hex(d []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(d))
}

func newHandler(elfBPF []byte) (*Handler, error) {
	rd := bytes.NewReader(elfBPF)
	handlerBPF := elflib.NewModuleFromReader(rd)

	// perf map is initialized and polled from global object
	elfSectionParams := map[string]elflib.SectionParams{
		"maps/events": elflib.SectionParams{
			SkipPerfMapInitialization: true,
		},
	}

	if err := handlerBPF.Load(elfSectionParams); err != nil {
		return nil, fmt.Errorf("error loading handler: %v", err)
	}

	var fd, fdRet int
	var name, nameRet string
	for kp := range handlerBPF.IterKprobes() {
		if strings.HasPrefix(kp.Name, "kprobe/") {
			fd = kp.Fd()
			name = fmt.Sprintf("%s_progs", strings.TrimPrefix(kp.Name, "kprobe/"))
		} else if strings.HasPrefix(kp.Name, "kretprobe/") {
			fdRet = kp.Fd()
			nameRet = fmt.Sprintf("%s_progs_ret", strings.TrimPrefix(kp.Name, "kretprobe/"))
		}
	}

	if name == "" || nameRet == "" {
		return nil, fmt.Errorf("malformed ELF file, it should contain both a kprobe and a kretprobe")
	}

	return &Handler{
		module:  handlerBPF,
		name:    name,
		nameRet: nameRet,
		fd:      fd,
		fdRet:   fdRet,
	}, nil
}

func (probe *Probe) registerHandler(pids []int, handler *Handler) error {
	progTable := probe.module.Map(handler.name)
	if progTable == nil {
		return fmt.Errorf("%q doesn't exist", handler.name)
	}
	progTableRet := probe.module.Map(handler.nameRet)
	if progTableRet == nil {
		return fmt.Errorf("%q doesn't exist", handler.nameRet)
	}

	var fd, fdRet int = handler.fd, handler.fdRet
	for _, pid := range pids {
		if err := probe.module.UpdateElement(progTable, unsafe.Pointer(&pid), unsafe.Pointer(&fd), 0); err != nil {
			return fmt.Errorf("error updating %q: %v", progTable.Name, err)
		}
		if err := probe.module.UpdateElement(progTableRet, unsafe.Pointer(&pid), unsafe.Pointer(&fdRet), 0); err != nil {
			return fmt.Errorf("error updating %q: %v", progTableRet.Name, err)
		}
	}

	for _, pid := range pids {
		probe.handlerRefcount[handler] += 1
		probe.pidToHandlers[pid] = append(probe.pidToHandlers[pid], handler)
	}
	return nil
}

func (probe *Probe) RegisterHandlerById(pids []int, hash string) error {
	return fmt.Errorf("not implemented yet")
}

func (probe *Probe) RegisterHandler(pids []int, elfBPF []byte) error {
	probe.Lock()
	defer probe.Unlock()

	id := sha256hex(elfBPF)

	_, ok := probe.handler[id]
	if !ok {
		handler, err := newHandler(elfBPF)
		if err != nil {
			return err
		}
		handler.id = id
		probe.handler[id] = handler
	}

	return probe.registerHandler(pids, probe.handler[id])
}

func (probe *Probe) UnregisterHandler(pids []int) error {
	probe.Lock()
	defer probe.Unlock()

	for _, pid := range pids {
		for _, handler := range probe.pidToHandlers[pid] {
			progTable := probe.module.Map(handler.name)
			if progTable == nil {
				return fmt.Errorf("%q doesn't exist", handler.name)
			}
			progTableRet := probe.module.Map(handler.nameRet)
			if progTableRet == nil {
				return fmt.Errorf("%q doesn't exist", handler.nameRet)
			}

			if err := probe.module.DeleteElement(progTable, unsafe.Pointer(&pid)); err != nil {
				return fmt.Errorf("error deleting %q: %v", progTable.Name, err)
			}
			if err := probe.module.DeleteElement(progTableRet, unsafe.Pointer(&pid)); err != nil {
				return fmt.Errorf("error deleting %q: %v", progTableRet.Name, err)
			}
			probe.handlerRefcount[handler] -= 1
			if probe.handlerRefcount[handler] == 0 {
				// TODO(schu): close unused handlers
			}
		}
		delete(probe.pidToHandlers, pid)
	}
	return nil
}

func (probe *Probe) Close() error {
	return probe.module.Close()
}

func (probe *Probe) BPFModule() *elflib.Module {
	return probe.module
}

func (handler *Handler) Id() string {
	return handler.id
}

func (handler *Handler) Close() error {
	return handler.module.Close()
}

func New() (*Probe, error) {
	if err := bpffs.Mount(); err != nil {
		return nil, err
	}
	// FIXME move this to go-bindata?
	globalBPF := elflib.NewModule("./bpf/out/trace_syscalls.bpf")

	if err := globalBPF.Load(nil); err != nil {
		return nil, fmt.Errorf("error loading global BPF: %v", err)
	}

	// TODO choose something here
	if err := globalBPF.EnableKprobes(16); err != nil {
		return nil, err
	}

	return &Probe{
		module:          globalBPF,
		handler:         make(map[string]*Handler),
		handlerRefcount: make(map[*Handler]int),
		pidToHandlers:   make(map[int][]*Handler),
	}, nil
}
