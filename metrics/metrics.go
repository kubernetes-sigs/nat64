package metrics

import (
	"fmt"
	"os"
	"syscall"

	"github.com/moby/sys/mountinfo"
	"k8s.io/klog/v2"
)

const (
	bpfMountPoint = "/sys/fs/bpf"
	bpfFSType     = "bpf"
)

// EnsureBpfFsMounted checks if the BPF filesystem is mounted at the standard location.
// If not, it attempts to mount it.
func EnsureBpfFsMounted() error {
	mounted, err := isBpfFsMounted()
	if err != nil {
		return fmt.Errorf("could not check if BPF filesystem is mounted: %w", err)
	}

	if mounted {
		klog.Infoln("BPF filesystem already mounted at", bpfMountPoint)
		return nil
	}

	klog.Infoln("BPF filesystem not mounted, attempting to mount it.")
	return mountBpfFs()
}

// isBpfFsMounted returns true if the bpf filesystem is mounted at /sys/fs/bpf.
func isBpfFsMounted() (bool, error) {
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return false, err
	}

	for _, m := range mounts {
		if m.Mountpoint == bpfMountPoint && m.FSType == bpfFSType {
			return true, nil
		}
	}

	return false, nil
}

// mountBpfFs mounts the BPF filesystem.
func mountBpfFs() error {
	// Create the directory if it doesn't exist.
	if err := os.MkdirAll(bpfMountPoint, 0755); err != nil {
		return fmt.Errorf("could not create BPF mount point directory %s: %w", bpfMountPoint, err)
	}

	// Mount the BPF filesystem.
	// The source and data arguments are typically "bpf" and empty respectively for BPF filesystems.
	if err := syscall.Mount("bpf", bpfMountPoint, "bpf", 0, ""); err != nil {
		return fmt.Errorf("failed to mount BPF filesystem at %s: %w", bpfMountPoint, err)
	}

	return nil
}
