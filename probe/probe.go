package probe

import (
	"bytes"
	"fmt"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/bpffs"
	elflib "github.com/iovisor/gobpf/elf"
)

func RegisterHandler(globalBPF *elflib.Module, pids []int, elfBPF []byte) error {
	rd := bytes.NewReader(elfBPF)
	handlerBPF := elflib.NewModuleFromReader(rd)
	// perf map is initialized and polled from global object
	elfSectionParams := map[string]elflib.SectionParams{
		"maps/events": elflib.SectionParams{
			SkipPerfMapInitialization: true,
		},
	}
	if err := handlerBPF.Load(elfSectionParams); err != nil {
		return fmt.Errorf("error loading handler: %v", err)
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
		return fmt.Errorf("malformed ELF file, it should contain both a kprobe and a kretprobe")
	}

	progTable := globalBPF.Map(name)
	if progTable == nil {
		return fmt.Errorf("%q doesn't exist", name)
	}
	progTableRet := globalBPF.Map(nameRet)
	if progTableRet == nil {
		return fmt.Errorf("%q doesn't exist", nameRet)
	}

	for _, pid := range pids {
		if err := globalBPF.UpdateElement(progTable, unsafe.Pointer(&pid), unsafe.Pointer(&fd), 0); err != nil {
			return fmt.Errorf("error updating %q: %v", progTable.Name, err)
		}
		if err := globalBPF.UpdateElement(progTableRet, unsafe.Pointer(&pid), unsafe.Pointer(&fdRet), 0); err != nil {
			return fmt.Errorf("error updating %q: %v", progTableRet.Name, err)
		}
	}

	return nil
}

func Load() (*elflib.Module, error) {
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

	return globalBPF, nil
}
