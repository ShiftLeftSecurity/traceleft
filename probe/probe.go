package probe

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"unsafe"

	"github.com/hashicorp/golang-lru"
	"github.com/iovisor/gobpf/bpffs"
	elflib "github.com/iovisor/gobpf/elf"
)

type Probe struct {
	module        *elflib.Module
	handlerCache  *lru.Cache
	pidToHandlers map[int][]*Handler
}

func evictHandler(key interface{}, value interface{}) {
	if h, ok := value.(*Handler); ok {
		h.Close()
	}
}

type Handler struct {
	module *elflib.Module

	id string

	// TODO find a better name for these
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
		"maps/events": {
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

func (probe *Probe) isHandling(pid int, h *Handler) bool {
	handlers, ok := probe.pidToHandlers[pid]
	if !ok {
		return false
	}
	for _, handler := range handlers {
		if handler.name == h.name && handler.nameRet == h.nameRet {
			return true
		}
	}
	return false
}

func (probe *Probe) registerHandler(pid int, handler *Handler) error {
	progTable := probe.module.Map(handler.name)
	if progTable == nil {
		return fmt.Errorf("%q doesn't exist", handler.name)
	}
	progTableRet := probe.module.Map(handler.nameRet)
	if progTableRet == nil {
		return fmt.Errorf("%q doesn't exist", handler.nameRet)
	}

	var fd, fdRet int = handler.fd, handler.fdRet
	if err := probe.module.UpdateElement(progTable, unsafe.Pointer(&pid), unsafe.Pointer(&fd), 0); err != nil {
		return fmt.Errorf("error updating %q: %v", progTable.Name, err)
	}
	if err := probe.module.UpdateElement(progTableRet, unsafe.Pointer(&pid), unsafe.Pointer(&fdRet), 0); err != nil {
		return fmt.Errorf("error updating %q: %v", progTableRet.Name, err)
	}

	if !probe.isHandling(pid, handler) {
		probe.pidToHandlers[pid] = append(probe.pidToHandlers[pid], handler)
	}

	return nil
}

func (probe *Probe) RegisterHandlerById(pid int, hash string) error {
	return fmt.Errorf("not implemented yet")
}

func (probe *Probe) getHandler(elfBPF []byte) (handler *Handler, err error) {
	id := sha256hex(elfBPF)
	val, ok := probe.handlerCache.Get(id)
	if !ok {
		handler, err = newHandler(elfBPF)
		if err != nil {
			return
		}

		probe.handlerCache.Add(id, handler)

		return
	}

	handler, ok = val.(*Handler)
	if !ok {
		return nil, fmt.Errorf("invalid type")
	}

	return
}

func (probe *Probe) RegisterHandler(pid int, elfBPF []byte) error {
	handler, err := probe.getHandler(elfBPF)
	if err != nil {
		return err
	}

	if err := probe.registerHandler(pid, handler); err != nil {
		return err
	}

	return nil
}

func (probe *Probe) unregisterHandler(pid int, handler *Handler) error {
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
	delete(probe.pidToHandlers, pid)

	return nil
}

func (probe *Probe) UnregisterHandler(pid int) error {
	for _, handler := range probe.pidToHandlers[pid] {
		if err := probe.unregisterHandler(pid, handler); err != nil {
			return err
		}
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

	cache, err := lru.NewWithEvict(4, evictHandler)
	if err != nil {
		return nil, err
	}

	return &Probe{
		module:        globalBPF,
		handlerCache:  cache,
		pidToHandlers: make(map[int][]*Handler),
	}, nil
}
