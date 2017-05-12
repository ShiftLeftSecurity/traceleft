// +build linux

// Copyright 2017 Kinvolk
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
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

/*
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <unistd.h>

extern __u64 ptr_to_u64(void *);

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
	BPFDirGlobals = "globals" // as in iproute2's BPF_DIR_GLOBALS
	BPFFSPath     = "/sys/fs/bpf/"
)

func pinObject(fd int, namespace, object, name string) error {
	mapPath := filepath.Join(BPFFSPath, namespace, object, name)
	os.MkdirAll(filepath.Dir(mapPath), 0755)
	err := os.RemoveAll(mapPath)
	if err != nil {
		return fmt.Errorf("error removing old map file %q: %v", mapPath, err)
	}

	mapPathC := C.CString(mapPath)
	defer C.free(unsafe.Pointer(mapPathC))

	ret, err := C.bpf_pin_object(C.int(fd), mapPathC)
	if ret != 0 {
		return fmt.Errorf("error pinning object to %q: %v", mapPath, err)
	}
	return nil
}

func PinObjectGlobal(fd int, namespace, name string) error {
	return pinObject(fd, namespace, BPFDirGlobals, name)
}
