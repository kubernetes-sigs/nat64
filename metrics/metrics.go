package metrics

import (
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/moby/sys/mountinfo"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const (
	bpfMountPoint = "/sys/fs/bpf"
	bpfFSType     = "bpf"
	bpfProgram    = "bpf/nat64.o"
)

type Nat64KeyType struct {
	Reason   int
	Protocol int
}
type Nat64MetricObj struct {
	*Nat64KeyType
	Count int
}

type Nat64ValueType []uint64

var (
	Ip64PacketCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_count",
			Help: "Packet count for each reason and protocol",
		},
		[]string{"reason", "protocol"},
	)
	Ip46PacketCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packets_count",
			Help: "Packet count for each reason and protocol",
		},
		[]string{"reason", "protocol"},
	)

	Ip64map = LoadMap("ip64_metrics")
	Ip46map = LoadMap("ip46_metrics")
)

func LoadMap(name string) *ebpf.Map {
	spec, err := ebpf.LoadCollectionSpec(bpfProgram)
	if err != nil {
		klog.Fatalf("error loading collection spec: %v", err)
	}
	obj, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: "/sys/fs/bpf",
			}})
	if err != nil {
		klog.Fatalf("error loading collection: %v", err)
	}
	defer obj.Close()

	return obj.Maps[name]
}

func ReadAndUpdatePacketCount(m *ebpf.Map, c *prometheus.CounterVec) {
	aggregatedCounters := make(map[Nat64KeyType]int)

	iter := m.Iterate()

	var key Nat64KeyType
	var values []Nat64MetricObj

	for iter.Next(&key, &values) {
		var total int
		for _, value := range values {
			total += value.Count
		}
		aggregatedCounters[key] = total
	}

	for key, total := range aggregatedCounters {
		c.With(prometheus.Labels{"reason": GetReason(key.Reason), "protocol": GetProtocolName(key.Protocol)}).Add(float64(total))
	}
}
func init() {
	prometheus.MustRegister(Ip64PacketCount)
	prometheus.MustRegister(Ip46PacketCount)
}

type Nat64ObjectCollector struct {
	mapName    string
	objects    map[string]*Nat64MetricObj
	metricDesc *prometheus.Desc
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

func GetReason(res int) string {
	reasons := map[int]string{
		0:  "success",
		-1: "unsupported",
		-2: "error",
		-3: "undefined",
	}
	name, ok := reasons[res]
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
