package bpf

import (
	"fmt"
	"syscall"
)

const (
	BPFFSPath = "/sys/fs/bpf"
	// https://github.com/coreutils/coreutils/blob/v8.27/src/stat.c#L275
	FsMagicBPFFS = 0xCAFE4A11
)

// IsBPFFSMounted checks if the BPF fs is mounted already
func IsBPFFSMounted() (bool, error) {
	var data syscall.Statfs_t
	if err := syscall.Statfs(BPFFSPath, &data); err != nil {
		return false, fmt.Errorf("cannot statfs %q: %v", BPFFSPath, err)
	}
	return data.Type == FsMagicBPFFS, nil
}

// MountBPFFS mounts the BPF fs if not already mounted
func MountBPFFS() error {
	mounted, err := IsBPFFSMounted()
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	if err := syscall.Mount(BPFFSPath, BPFFSPath, "bpf", 0, ""); err != nil {
		return fmt.Errorf("error mounting %q: %v", BPFFSPath, err)
	}
	return nil
}
