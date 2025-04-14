package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/moby/sys/mountinfo"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/klog/v2"
)

const (
	bpfMountPoint = "/sys/fs/bpf"
	bpfFSType     = "bpf"
)

type Nat64KeyType struct {
	Status   int32
	Protocol uint8
}
type Nat64ValueType uint32

func LoadMap(name string) *ebpf.Map {
	spec, err := ebpf.LoadCollectionSpec(bpfProgram)
	if err != nil {
		klog.Infof("error loading collection spec: %v", err)
		return nil
	}
	obj, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: "/sys/fs/bpf",
			}})
	if err != nil {
		klog.Infof("error loading collection: %v", err)
		return nil
	}

	return obj.Maps[name]
}

func ReadAndUpdatePacketCount(m *ebpf.Map, c *prometheus.CounterVec) {
	aggregatedCounters := make(map[Nat64KeyType]uint32)
	iter := m.Iterate()

	if iter == nil {
		klog.Infof("failed to get map iterator")
		return
	}

	var key Nat64KeyType
	var values []uint32

	var total uint32

	for iter.Next(&key, &values) {
		for _, value := range values {
			total += value
		}
		aggregatedCounters[key] = total
	}
	if err := iter.Err(); err != nil {
		klog.Infof("error during map iteration: %v", err)
	}

	for key, total := range aggregatedCounters {
		labels := prometheus.Labels{"status": GetStatus(key.Status), "protocol": GetProtocolName(int(key.Protocol))}
		counterValue, err := GetCounterValue(c, labels)
		if err != nil {
			continue
		}
		c.With(labels).Add(float64(total) - counterValue)
	}
}

func GetCounterValue(metric *prometheus.CounterVec, labels prometheus.Labels) (float64, error) {
	var m = &dto.Metric{}
	if err := metric.With(labels).Write(m); err != nil {
		return 0, err
	}
	return m.Counter.GetValue(), nil
}

func GetProtocolName(nextHeader int) string {
	protocolNames := map[int]string{
		0x01: "ICMP",
		0x06: "TCP",
		0x11: "UDP",
		0x3a: "ICMPv6",
	}
	name, ok := protocolNames[nextHeader]
	if !ok {
		return "Unknown"
	}
	return name
}

func GetStatus(st int32) string {
	statuses := map[int32]string{
		0:  "success",
		-1: "unsupported",
		-2: "error",
		-3: "undefined",
	}
	name, ok := statuses[st]
	if !ok {
		return "Unknown"
	}
	return name
}

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
