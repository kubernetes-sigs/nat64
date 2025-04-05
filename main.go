/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	toolswatch "k8s.io/client-go/tools/watch"
	"k8s.io/klog/v2"
)

// Stateful implementation of NAT64 based in two stages using a dummy interface.
// It creates a dummy netdevice with both defined IPv4 and IPv6 CIDRs used for NAT64
// 1. uses eBPF to implement stateless NAT64: IPv6 traffic directed to the NAT64 IPV6 CIDR is translated to the IPv4 CIDR
// 2. the translated traffic is IPv4 and can use netfilter masquerade to use the VM global IPv4 address
// This simplifies the implementation since there is no need to rewrite the whole linux conntrack logic in eBPF
// it also avoids the problem caused by collisions with ports on the host (in case you implement two conntrack systems)
// xref: https://github.com/cilium/cilium/issues/23604

const (
	originalMTU     = 1500
	bpfProgram      = "bpf/nat64.o"
	reconcilePeriod = 1 * time.Minute
	tableName       = "kube-nat64"
)

var (
	metricsBindAddress string
	natV4Range         string
	natV6Range         string
	nat64If            string
	podCIDR            string
	hostname           string
)

func init() {
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", "0.0.0.0:8881", "The IP address and port for the metrics server to serve on, default 0.0.0.0:8881")
	flag.StringVar(&natV4Range, "nat-v4-cidr", "169.254.64.0/24", "The IPv4 CIDR used to source NAT the NAT64 addresses")
	flag.StringVar(&natV6Range, "nat-v6-cidr", "64:ff9b::/96", "The IPv6 CIDR used for IPv4-Embedded IPv6 Address Prefix, default 64:ff9b::/96 (rfc6052)")
	flag.StringVar(&nat64If, "iface", "nat64", "The name of the interfaces created in the system to implement NAT64")
	flag.StringVar(&podCIDR, "source-cidr", "", "The subnet used to set the source range to NAT64, by default all traffic using the nat64 prefix is allowed")
	flag.StringVar(&hostname, "hostname", "", "Node hostname")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: nat64 [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	printVersion()
	flag.VisitAll(func(f *flag.Flag) {
		klog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	_, _, err := net.SplitHostPort(metricsBindAddress)
	if err != nil {
		klog.Fatalf("Wrong metrics-bind-address %s : %v", metricsBindAddress, err)
	}

	v4ip, v4net, err := net.ParseCIDR(natV4Range)
	if err != nil {
		klog.Fatalf("Wrong nat-v4-cidr %s: %v", natV4Range, err)
	}
	v4netMaskSize, v4netSize := v4net.Mask.Size()
	if v4netSize > 32 {
		klog.Fatalf("nat-v4-cidr is required to be IPv4 CIDR: %s", natV4Range)
	}

	routes, err := netlink.RouteGet(v4ip)
	if err != nil {
		klog.Fatalf("Can not get route to %s: %v", v4ip.String(), err)
	}
	// TODO: do not consider the default route
	if len(routes) > 1 {
		klog.Infof("Overalapping routes %v with the range %s", routes, natV4Range)
	}

	v6ip, v6net, err := net.ParseCIDR(natV6Range)
	if err != nil {
		klog.Fatalf("Wrong nat-v6-cidr %s: %v", natV6Range, err)
	}
	if v6net.IP.To4() != nil {
		klog.Fatalf("nat-v6-cidr is required to be IPv6 CIDR: %s", natV6Range)
	}

	v6netMaskSize, _ := v6net.Mask.Size()
	if v6netMaskSize > 96 {
		klog.Fatalf("nat-v6-cidr must be /96 or wider, need at least 4 variable bytes to embed IPv4 address")
	}

	routes, err = netlink.RouteGet(v6ip)
	if err != nil {
		klog.Fatalf("Can not get route to %s: %v", v6ip.String(), err)
	}
	// TODO: do not consider the default route
	if len(routes) > 1 {
		klog.Infof("Overlapping routes %v with the range %s", routes, natV4Range)
	}

	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			klog.Fatalf("Cannot fetch os.Hostname: %v", err)
		}
		klog.Infof("No hostname specified, using os.Hostname: %s", hostname)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("Cannot fetch cluster config: %v", err)
	}
	k8sClient, err := clientset.NewForConfig(config)

	if len(podCIDR) == 0 {
		klog.Infof("Watching for node, awaiting podCIDR allocation")
		ctx := context.Background()
		node, err := waitForPodCIDR(ctx, k8sClient, hostname)
		if err != nil {
			klog.Fatalf("waitForPodCIDR: %v", err)
		}
		// take podCIDR from primary IP family configured for the cluster
		podCIDR = node.Spec.PodCIDRs[0]
		klog.Infof("podCIDR: %s", podCIDR)
	}

	_, podIPNet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		klog.Fatalf("net.ParseCIDR: %v", err)
	}
	if podIPNet.IP.To4() != nil {
		klog.Fatalf("podCIDR is required to be IPv6 CIDR: %s", podCIDR)
	}

	podIPNetMaskSize, _ := podIPNet.Mask.Size()
	// In stateless NAT algorithm, variable bits from pod CIDR are retained
	// (for /120 pod CIDR, 1 byte is variable, for /112, 2 bytes, etc.).
	// Those last bytes of IPv6 pod address are saved in IPv4 source address after IPv6 -> IPv4 NAT
	// (for /120 pod CIDR, 198.18.0.0/16 IPv4 nat range and fd00:10:244:1::c5ff pod,
	// bytes 0xc5 (197) and 0xff (255) will be saved, resulting in 198.18.197.255 source address).
	// The wider IPv4 nat range is provided, the more pods we can handle without collissions, resulting
	// in wider supported pod CIDR.
	widestPodCIDRRangeAllowed := 128 - v4netMaskSize
	if podIPNetMaskSize < widestPodCIDRRangeAllowed {
		klog.Fatalf("Mask for pod CIDR must be of size %d or narrower to avoid source address collision for NAT64: %s", widestPodCIDRRangeAllowed, podCIDR)
	}

	// Obtain the interface with the default route for IPv4 so we can masquerade the traffic
	gwIface, err := getDefaultGwIf()
	if err != nil {
		klog.Fatalf("can not obtain default IPv4 gateway interface: %v", err)
	}
	klog.Infof("detected %s as default gateway interface", gwIface)

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	// run metrics server
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		klog.Infof("starting metrics server listening in %s", metricsBindAddress)
		http.ListenAndServe(metricsBindAddress, nil) // nolint:errcheck
	}()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.Fatal("Removing memlock:", err)
	}

	// sync nat64
	klog.Infof("create NAT64 interface %s with networks %s and %s", nat64If, v4net.String(), v6net.String())
	err = sync(v4net, v6net, podIPNet)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			klog.Fatalf("BPF verifier error: %+v\n", verr)
		} else {
			klog.Fatalf("Could not sync nat64: %v", err)
		}
	}

	ticker := time.NewTicker(reconcilePeriod)
	defer ticker.Stop()

	// sync nftables rules
	go func() {
		for {
			klog.Infoln("syncing nftables rules to masquerade v4 traffic...")
			err = syncRules(v4net, gwIface)
			if err != nil {
				klog.Infof("error syncing nftables rules: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	defer func() {
		// Clean up:
		// - NAT64 interface
		// - nftables rules
		klog.Infoln("NAT64 cleaning up")
		cleanup()
	}()

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

}

// sync creates the nat64 interface with the corresponding addresses
// installs the ebpf program on the interface
// installes corresponding nftables rules
func sync(v4net, v6net, podIPNet *net.IPNet) error {
	// Create the NAT64 interface if it does not exist
	link, err := netlink.LinkByName(nat64If)
	if link == nil || err != nil {
		klog.Infof("NAT64 interface with name %s not found, creating it", nat64If)
		link = &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: nat64If,
				MTU:  originalMTU,
			},
		}
		if err := netlink.LinkAdd(link); err != nil {
			return err
		}
	}

	// set the interface up if necessary
	if link.Attrs().Flags&net.FlagUp == 0 {
		klog.Infof("NAT64 interface with name %s down, setting it up", nat64If)
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}

	// Configure IP addresses on the NAT64 interface if necessary
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}

	klog.Infof("replacing addresses %v on interface %s with %s", addresses, nat64If, v4net.String())
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: v4net}); err != nil {
		return err
	}

	addresses, err = netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return err
	}

	klog.Infof("replacing addresses %v on interface %s with %s", addresses, nat64If, v6net.String())
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: v6net}); err != nil {
		return err
	}

	// Create qdisc on nat64 interface
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("failed to replace qdisc: %w", err)
	}

	// Add eBPF code to the TC of the nat64 interface
	spec, err := ebpf.LoadCollectionSpec(bpfProgram)
	if err != nil {
		return err
	}

	for _, prog := range spec.Programs {
		klog.Infof("eBPF program spec section %s name %s", prog.SectionName, prog.Name)
	}

	err = spec.RewriteConstants(map[string]interface{}{
		//		"NAT64_PREFIX": uint32(transportProtocolNumber),
		//		"NAT46_PREFIX": uint32(family),

		"IPV4_NAT_PREFIX": binary.BigEndian.Uint32(v4net.IP),
		"IPV4_NAT_MASK":   binary.BigEndian.Uint32(v4net.Mask),

		// no need to hold IPV6_NAT_PREFIX_3 and IPV6_NAT_MASK_3
		// last 4 bytes are reserved for embedding IPv4 address
		"IPV6_NAT_PREFIX_0": binary.BigEndian.Uint32(v6net.IP[0:4]),
		"IPV6_NAT_PREFIX_1": binary.BigEndian.Uint32(v6net.IP[4:8]),
		"IPV6_NAT_PREFIX_2": binary.BigEndian.Uint32(v6net.IP[8:12]),

		"IPV6_NAT_MASK_0": binary.BigEndian.Uint32(v6net.Mask[0:4]),
		"IPV6_NAT_MASK_1": binary.BigEndian.Uint32(v6net.Mask[4:8]),
		"IPV6_NAT_MASK_2": binary.BigEndian.Uint32(v6net.Mask[8:12]),

		"POD_PREFIX_0": binary.BigEndian.Uint32(podIPNet.IP[0:4]),
		"POD_PREFIX_1": binary.BigEndian.Uint32(podIPNet.IP[4:8]),
		"POD_PREFIX_2": binary.BigEndian.Uint32(podIPNet.IP[8:12]),
		"POD_PREFIX_3": binary.BigEndian.Uint32(podIPNet.IP[12:16]),

		"POD_MASK_0": binary.BigEndian.Uint32(podIPNet.Mask[0:4]),
		"POD_MASK_1": binary.BigEndian.Uint32(podIPNet.Mask[4:8]),
		"POD_MASK_2": binary.BigEndian.Uint32(podIPNet.Mask[8:12]),
		"POD_MASK_3": binary.BigEndian.Uint32(podIPNet.Mask[12:16]),
	})
	if err != nil {
		return fmt.Errorf("unexpected error rewriting eBPF program: %w", err)
	}

	// Instantiate a Collection from a CollectionSpec.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	nat64, ok := coll.Programs["nat64"]
	if !ok {
		return fmt.Errorf("could not find tc/nat64 program on %s", bpfProgram)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_IPV6,
			Priority:  1,
		},
		Fd:           nat64.FD(),
		Name:         "nat64",
		DirectAction: true,
	}

	klog.Infof("adding eBPF nat64 prog to the interface %s", nat64If)
	if err := netlink.FilterAdd(filter); err != nil {
		klog.Infof("filter %s already exist on interface %s, replacing it ...", filter.Name, nat64If)
		// it may already exist, try to replace it
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter for interface %s: %w", link.Attrs().Name, err)
		}
	}

	nat46, ok := coll.Programs["nat46"]
	if !ok {
		return fmt.Errorf("could not find tc/nat46 program on %s", bpfProgram)
	}

	filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_IP,
			Priority:  2,
		},
		Fd:           nat46.FD(),
		Name:         "nat46",
		DirectAction: true,
	}

	klog.Infof("adding eBPF nat46 prog to the interface %s", nat64If)
	if err := netlink.FilterAdd(filter); err != nil {
		klog.Infof("filter %s already exist on interface %s, replacing it ...", filter.Name, nat64If)
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter for interface %s: %w", link.Attrs().Name, err)
		}
	}

	return nil
}

func syncRules(natV4Range *net.IPNet, gwIface string) error {
	klog.V(2).Info("Syncing nat64 nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nat64 failure, can not start nftables: %v", err)
	}
	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 10),
	})

	/*
			nft --debug=netlink add rule inet kindnet-ipmasq postrouting ip saddr 10.0.0.0/18 meta oifname eth0 masquerade
		inet kindnet-ipmasq postrouting
		[ meta load nfproto => reg 1 ]
		[ cmp eq reg 1 0x00000002 ]
		[ payload load 4b @ network header + 12 => reg 1 ]
		[ bitwise reg 1 = ( reg 1 & 0x00c0ffff ) ^ 0x00000000 ]
		[ cmp eq reg 1 0x0000000a ]
		[ meta load oifname => reg 1 ]
		[ cmp eq reg 1 0x30687465 0x00000000 0x00000000 0x00000000 ]
		[ masq ]
	*/

	// masquerade IPv4 traffic that was NAT64 "masquerade traffic"
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 4, Mask: natV4Range.Mask, Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: natV4Range.IP.To4()},
			&expr.Meta{Key: expr.MetaKeyOIFNAME, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: ifname(gwIface)},
			&expr.Masq{Random: false, FullyRandom: false, Persistent: false, ToPorts: false, RegProtoMin: 0x0, RegProtoMax: 0x0},
			&expr.Counter{},
		},
	})

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("error deleting nftables rules %v", err)
	}
	return nil
}

// cleanup is best effort and deletes the NAT64 interface and the corresponding inftables rules
func cleanup() {
	// Create the NAT64 interface if it does not exist
	link, err := netlink.LinkByName(nat64If)
	if err != nil {
		klog.Infof("could not find nat64 interface %s: %v", nat64If, err)
	}

	if link != nil {
		if err := netlink.LinkDel(link); err != nil {
			klog.Infof("could not delete nat64 interface %s: %v", nat64If, err)
		}
	}

	nft, err := nftables.New()
	if err != nil {
		klog.Infof("ipmasq cleanup failure, can not start nftables:%v", err)
		return
	}
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.DelTable(table)
	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

func getDefaultGwIf() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}

	for _, r := range routes {
		// no multipath
		if len(r.MultiPath) == 0 {
			if r.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				klog.Infof("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}

		// multipath, use the first valid entry
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			if nh.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				klog.Infof("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("not routes found")
}

func waitForPodCIDR(ctx context.Context, client clientset.Interface, nodeName string) (*v1.Node, error) {
	// since allocators can assign the podCIDR after the node registers, we do a watch here to wait
	// for podCIDR to be assigned, instead of assuming that the Get() on startup will have it.
	ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Minute)
	defer cancelFunc()

	fieldSelector := fields.OneTermEqualSelector("metadata.name", nodeName).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (object runtime.Object, e error) {
			options.FieldSelector = fieldSelector
			return client.CoreV1().Nodes().List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (i watch.Interface, e error) {
			options.FieldSelector = fieldSelector
			return client.CoreV1().Nodes().Watch(ctx, options)
		},
	}
	condition := func(event watch.Event) (bool, error) {
		// don't process delete events
		if event.Type != watch.Modified && event.Type != watch.Added {
			return false, nil
		}

		n, ok := event.Object.(*v1.Node)
		if !ok {
			return false, fmt.Errorf("event object not of type Node")
		}
		// don't consider the node if is going to be deleted and keep waiting
		if !n.DeletionTimestamp.IsZero() {
			return false, nil
		}
		return n.Spec.PodCIDR != "" && len(n.Spec.PodCIDRs) > 0, nil
	}

	evt, err := toolswatch.UntilWithSync(ctx, lw, &v1.Node{}, nil, condition)
	if err != nil {
		return nil, fmt.Errorf("timeout waiting for PodCIDR allocation: %v", err)
	}
	if n, ok := evt.Object.(*v1.Node); ok {
		return n, nil
	}
	return nil, fmt.Errorf("event object not of type node")
}

func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var vcsRevision, vcsTime string
	for _, f := range info.Settings {
		switch f.Key {
		case "vcs.revision":
			vcsRevision = f.Value
		case "vcs.time":
			vcsTime = f.Value
		}
	}
	klog.Infof("dranet go %s build: %s time: %s", info.GoVersion, vcsRevision, vcsTime)
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
