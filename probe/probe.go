package probe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	elflib "github.com/iovisor/gobpf/elf"
)

/*
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/bpf_common.h>


static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

// TODO move this to gobpf
int bpf_pin_object(int fd, const char *pathname)
{
	union bpf_attr attr = {};

	attr.pathname = ptr_to_u64((void *)pathname);
	attr.bpf_fd = fd;

	return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}
*/
import "C"

const (
	bpfFSPath    = "/sys/fs/bpf"
	bpfNamespace = "traceleft"
)

const (
	// https://github.com/coreutils/coreutils/blob/v8.27/src/stat.c#L275
	FsMagicBPFFS = 0xCAFE4A11
)

func isBPFFSMounted() (bool, error) {
	var data syscall.Statfs_t
	if err := syscall.Statfs(bpfFSPath, &data); err != nil {
		return false, fmt.Errorf("cannot statfs %q: %v", bpfFSPath, err)
	}

	return data.Type == FsMagicBPFFS, nil
}

func maybeMountBPFFS() error {
	mounted, err := isBPFFSMounted()
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}

	if err := syscall.Mount(bpfFSPath, bpfFSPath, "bpf", 0, ""); err != nil && err != syscall.EBUSY {
		return fmt.Errorf("error mounting %q: %v", bpfFSPath, err)
	}

	return nil
}

func pinPerfMap(mapFD int) error {
	mapPath := filepath.Join(bpfFSPath, bpfNamespace, "global")
	os.MkdirAll(filepath.Dir(mapPath), 0644)
	_ = os.RemoveAll(mapPath)

	pathp := C.CString("/sys/fs/bpf/traceleft/global")
	defer C.free(unsafe.Pointer(pathp))

	ret, err := C.bpf_pin_object(C.int(mapFD), pathp)
	if ret != 0 {
		return fmt.Errorf("error pinning object to %q: %v", mapPath, err)
	}

	return nil
}

func RegisterHandler(globalBPF *elflib.Module, pids []int, elfBPF []byte) error {
	rd := bytes.NewReader(elfBPF)
	handlerBPF := elflib.NewModuleFromReader(rd)
	if err := handlerBPF.Load(nil); err != nil {
		return fmt.Errorf("error loading handler: %v", err)
	}

	var fd, fdRet int
	var name, nameRet string
	for kp := range handlerBPF.IterKprobes() {
		if strings.HasPrefix(kp.Name, "kprobe/") {
			fd = kp.Fd
			name = fmt.Sprintf("%s_progs", strings.TrimPrefix(kp.Name, "kprobe/"))
		} else if strings.HasPrefix(kp.Name, "kretprobe/") {
			fdRet = kp.Fd
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
	if err := maybeMountBPFFS(); err != nil {
		return nil, err
	}

	// FIXME move this to go-bindata?
	globalBPF := elflib.NewModule("../bpf/out/trace_syscalls.o")

	if err := globalBPF.Load(nil); err != nil {
		return nil, fmt.Errorf("error loading global BPF: %v", err)
	}

	// TODO choose something here
	if err := globalBPF.EnableKprobes(16); err != nil {
		return nil, err
	}

	eventsMap := globalBPF.Map("events")
	if err := pinPerfMap(eventsMap.FD()); err != nil {
		return nil, err
	}

	return globalBPF, nil
}
