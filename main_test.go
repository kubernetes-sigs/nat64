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
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type testSetup struct {
	v4net   *net.IPNet
	v6net   *net.IPNet
	podnet  *net.IPNet
	gwIface string
}

func setupTest(t *testing.T) (setup testSetup, cleanup func()) {
	t.Helper()

	var origns, newns *netns.NsHandle

	runtime.LockOSThread()
	cleanup = func() {
		if newns != nil {
			newns.Close() // nolint:errcheck
		}
		if origns != nil {
			_ = netns.Set(*origns)
			origns.Close() // nolint:errcheck
		}
		runtime.UnlockOSThread()
	}

	if os.Getuid() != 0 {
		cleanup()
		t.Skip("Test requires root privileges.")
	}

	_, v4net, err := net.ParseCIDR("192.168.0.0/18")
	if err != nil {
		cleanup()
		t.Fatalf("unexpected error %v", err)
	}

	_, v6net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		cleanup()
		t.Fatalf("unexpected error %v", err)
	}

	_, podnet, err := net.ParseCIDR("fd00:10:244::/112")
	if err != nil {
		cleanup()
		t.Fatalf("unexpected error %v", err)
	}

	setup.v4net = v4net
	setup.v6net = v6net
	setup.podnet = podnet
	setup.gwIface = "eth0"

	// Save the current network namespace
	ns1, err := netns.Get()
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	origns = &ns1

	// Create a new network namespace
	ns2, err := netns.New()
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	newns = &ns2

	// add a fake rule to masquerade all the traffic
	//  ip6tables -t nat -A POSTROUTING -o lo -j MASQUERADE
	cmd := exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE")
	_, err = cmd.CombinedOutput()
	if err != nil {
		cleanup()
		t.Fatalf("ip6tables error error = %v", err)
	}

	return setup, cleanup
}

func setupWithNat64IfUp(t *testing.T) (setup testSetup, link netlink.Link, cleanup func()) {
	t.Helper()

	setup, cleanup = setupTest(t)

	link = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: nat64If,
			MTU:  originalMTU,
		},
	}
	if err := netlink.LinkAdd(link); err != nil {
		cleanup()
		t.Errorf("unexpected error: %v", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		cleanup()
		t.Errorf("unexpected error: %v", err)
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(link); err != nil {
			cleanup()
			t.Errorf("unexpected error: %v", err)
		}
	}

	return setup, link, cleanup
}

func setupWithLoadedBpf(t *testing.T) (setup testSetup, link netlink.Link, coll *ebpf.Collection, cleanup func()) {
	t.Helper()

	if _, err := os.Stat(bpfProgram); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s does not exist, run make build first", bpfProgram)
	}

	setup, link, cleanup = setupWithNat64IfUp(t)

	spec, err := ebpf.LoadCollectionSpec(bpfProgram)
	if err != nil {
		cleanup()
		t.Errorf("unexpected error: %v", err)
	}

	err = spec.RewriteConstants(map[string]interface{}{
		// This is the range that is used to replace the original
		// IPv6 address, so it can be masquerade later with the
		// external IPv4 address.
		"IPV4_SNAT_PREFIX": binary.BigEndian.Uint32(setup.v4net.IP),
		"IPV4_SNAT_MASK":   binary.BigEndian.Uint32(setup.v4net.Mask),

		// NAT64 prefix, typically the well known prefix 64:ff9b::/96
		// no need to hold IPV6_NAT_PREFIX_3 and IPV6_NAT_MASK_3
		// last 4 bytes are reserved for embedding IPv4 address
		"IPV6_NAT64_PREFIX_0": binary.BigEndian.Uint32(setup.v6net.IP[0:4]),
		"IPV6_NAT64_PREFIX_1": binary.BigEndian.Uint32(setup.v6net.IP[4:8]),
		"IPV6_NAT64_PREFIX_2": binary.BigEndian.Uint32(setup.v6net.IP[8:12]),

		"IPV6_NAT64_MASK_0": binary.BigEndian.Uint32(setup.v6net.Mask[0:4]),
		"IPV6_NAT64_MASK_1": binary.BigEndian.Uint32(setup.v6net.Mask[4:8]),
		"IPV6_NAT64_MASK_2": binary.BigEndian.Uint32(setup.v6net.Mask[8:12]),

		// IPv6 prefix used by Pods
		"POD_PREFIX_0": binary.BigEndian.Uint32(setup.podnet.IP[0:4]),
		"POD_PREFIX_1": binary.BigEndian.Uint32(setup.podnet.IP[4:8]),
		"POD_PREFIX_2": binary.BigEndian.Uint32(setup.podnet.IP[8:12]),
		"POD_PREFIX_3": binary.BigEndian.Uint32(setup.podnet.IP[12:16]),

		"POD_MASK_0": binary.BigEndian.Uint32(setup.podnet.Mask[0:4]),
		"POD_MASK_1": binary.BigEndian.Uint32(setup.podnet.Mask[4:8]),
		"POD_MASK_2": binary.BigEndian.Uint32(setup.podnet.Mask[8:12]),
		"POD_MASK_3": binary.BigEndian.Uint32(setup.podnet.Mask[12:16]),
	})
	if err != nil {
		cleanup()
		t.Errorf("unexpected error: %v", err)
	}

	// Instantiate a Collection from a CollectionSpec.
	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		cleanup()
		t.Errorf("unexpected error: %v", err)
	}

	return setup, link, coll, cleanup
}

func Test_syncRules(t *testing.T) {
	setup, clean := setupTest(t)
	defer clean()

	expectedNftables := `# Warning: table ip6 nat is managed by iptables-nft, do not touch!
table ip6 nat {
       chain POSTROUTING {
               type nat hook postrouting priority srcnat; policy accept;
               ip6 daddr 64:ff9b::/96 counter packets 0 bytes 0 return comment "kube-nat64-rule"
               oifname "lo" counter packets 0 bytes 0 masquerade
       }
}
table inet kube-nat64 {
       chain postrouting {
               type nat hook postrouting priority srcnat - 10; policy accept;
               ip saddr 192.168.0.0/18 oifname "eth0" masquerade counter packets 0 bytes 0
       }
}
`

	err := syncRules(setup.v4net, setup.v6net, setup.gwIface)
	if err != nil {
		t.Fatalf("error syncing nftables rules: %v", err)
	}

	cmd := exec.Command("nft", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table error = %v", err)
	}
	got := string(out)
	if !compareMultilineStringsIgnoreIndentation(got, expectedNftables) {
		t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, expectedNftables, cmp.Diff(got, expectedNftables))
	}
	cleanup()
	cmd = exec.Command("nft", "list", "table", "inet", tableName)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("nft list ruleset unexpected success")
	}
	if !strings.Contains(string(out), "No such file or directory") {
		t.Errorf("unexpected error %v %s", err, string(out))
	}
	cmd = exec.Command("nft", "list", "table", "ip6", "nat")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset unexpected error")
	}
	if strings.Contains(string(out), setup.v6net.String()) {
		t.Errorf("unexpected rule on default table %s %s", setup.v6net.String(), string(out))
	}
}

func compareMultilineStringsIgnoreIndentation(str1, str2 string) bool {
	// Remove all indentation from both strings
	re := regexp.MustCompile(`(?m)^\s+`)
	str1 = re.ReplaceAllString(str1, "")
	str2 = re.ReplaceAllString(str2, "")

	return str1 == str2
}

func Test_checkHealth_ValidAfterSyncs(t *testing.T) {
	setup, clean := setupTest(t)
	defer clean()

	err := sync(setup.v4net, setup.v6net, setup.podnet)
	if err != nil {
		t.Errorf("sync failed: %v", err)
	}
	err = syncRules(setup.v4net, setup.v6net, setup.gwIface)
	if err != nil {
		t.Errorf("syncRules failed: %v", err)
	}

	err = checkHealth()
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func Test_checkHealth_InvalidWithLinkUp(t *testing.T) {
	_, _, clean := setupWithNat64IfUp(t)
	defer clean()

	expectedErrStr := `expected at least 2 bpf filters for nat64 interface, got 0
no nat64 filter defined for nat64 interface
no nat46 filter defined for nat64 interface`

	err := checkHealth()
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("invalid error, expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkHealth_InvalidEmptyNs(t *testing.T) {
	_, clean := setupTest(t)
	defer clean()

	expectedErrStr := `cannot fetch nat64 interface: Link not found`

	err := checkHealth()
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("invalid error, expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkBpfFiltersCount_Valid(t *testing.T) {
	_, link, coll, clean := setupWithLoadedBpf(t)
	defer clean()

	nat64, ok := coll.Programs["nat64"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat64 program on %s", bpfProgram)
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	nat46, ok := coll.Programs["nat46"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat46 program on %s", bpfProgram)
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	err = checkBpfFiltersCount(filters)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func Test_checkBpfFiltersCount_InvalidOneFilter(t *testing.T) {
	_, link, coll, clean := setupWithLoadedBpf(t)
	defer clean()

	nat64, ok := coll.Programs["nat64"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat64 program on %s", bpfProgram)
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	expectedErrStr := "expected at least 2 bpf filters for nat64 interface, got 1"
	err = checkBpfFiltersCount(filters)
	if err.Error() != expectedErrStr {
		t.Errorf("expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkBpfFiltersCount_InvalidNoFilters(t *testing.T) {
	_, _, _, clean := setupWithLoadedBpf(t)
	defer clean()

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	expectedErrStr := "expected at least 2 bpf filters for nat64 interface, got 0"
	err = checkBpfFiltersCount(filters)
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkBpfFilterNat64Present_Valid(t *testing.T) {
	_, link, coll, clean := setupWithLoadedBpf(t)
	defer clean()

	nat64, ok := coll.Programs["nat64"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat64 program on %s", bpfProgram)
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	err = checkBpfFilterNat64Present(filters)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func Test_checkBpfFilterNat64Present_InvalidNoFilter(t *testing.T) {
	_, _, _, clean := setupWithLoadedBpf(t)
	defer clean()

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	expectedErrStr := "no nat64 filter defined for nat64 interface"
	err = checkBpfFilterNat64Present(filters)
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkBpfFilterNat46Present_Valid(t *testing.T) {
	_, link, coll, clean := setupWithLoadedBpf(t)
	defer clean()

	nat46, ok := coll.Programs["nat46"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat46 program on %s", bpfProgram)
	}

	filter := &netlink.BpfFilter{
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	err = checkBpfFilterNat46Present(filters)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

}

func Test_checkBpfFilterNat46Present_InvalidWrongFilter(t *testing.T) {
	_, link, coll, clean := setupWithLoadedBpf(t)
	defer clean()

	nat64, ok := coll.Programs["nat64"]
	if !ok {
		t.Errorf("unexpected error: could not find tc/nat64 program on %s", bpfProgram)
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

	if err := netlink.FilterAdd(filter); err != nil {
		if err := netlink.FilterReplace(filter); err != nil {
			t.Errorf("unexpected error: replacing tc filter for interface %s: %v", link.Attrs().Name, err)
		}
	}

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	expectedErrStr := "no nat46 filter defined for nat64 interface"
	err = checkBpfFilterNat46Present(filters)
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_checkBpfFilterNat46Present_InvalidNoFilter(t *testing.T) {
	_, _, _, clean := setupWithLoadedBpf(t)
	defer clean()

	filters, err := checkAndGetFilters()
	if err != nil {
		t.Errorf("unexpected checkAndGetFilters error: %v", err)
	}

	expectedErrStr := "no nat46 filter defined for nat64 interface"
	err = checkBpfFilterNat46Present(filters)
	if err == nil || err.Error() != expectedErrStr {
		t.Errorf("expected: %s, got: %v", expectedErrStr, err)
	}
}

func Test_validateNetworks(t *testing.T) {
	tests := []struct {
		name     string
		v4nat64  string
		v6nat64  string
		podRange string
		wantErr  bool
	}{
		{
			name:     "valid networks",
			v4nat64:  "192.168.0.0/24",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/120",
			wantErr:  false,
		},
		{
			name:     "valid networks 2",
			v4nat64:  "192.168.0.0/18",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/120",
			wantErr:  false,
		},
		{
			name:     "valid networks 3",
			v4nat64:  "192.168.0.0/18",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/124",
			wantErr:  false,
		},
		{
			name:     "invalid pod CIDR",
			v4nat64:  "192.168.0.0/18",
			v6nat64:  "64:ff9b::/96",
			podRange: "192.168.0.0/18",
			wantErr:  true,
		},
		{
			name:     "invalid v6 CIDR",
			v4nat64:  "192.168.0.0/18",
			v6nat64:  "64:ff9b::/120",
			podRange: "fd00:10:244::/112",
			wantErr:  true,
		},
		{
			name:     "invalid pod CIDR mask",
			v4nat64:  "192.168.0.0/24",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/112",
			wantErr:  true,
		},
		{
			name:     "invalid pod CIDR mask 2",
			v4nat64:  "192.168.0.0/28",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/120",
			wantErr:  true,
		},
		{
			name:     "valid pod CIDR mask 3",
			v4nat64:  "192.168.0.0/8",
			v6nat64:  "64:ff9b::/96",
			podRange: "fd00:10:244::/104",
			wantErr:  false,
		},
		{
			name:     "invalid v6 CIDR mask",
			v4nat64:  "192.168.0.0/18",
			v6nat64:  "64:ff9b::/104",
			podRange: "fd00:10:244::/112",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, v4net, err := net.ParseCIDR(tt.v4nat64)
			if err != nil {
				t.Fatalf("unexpected error parsing v4net %s: %v", tt.v4nat64, err)
			}
			_, v6net, err := net.ParseCIDR(tt.v6nat64)
			if err != nil {
				t.Fatalf("unexpected error parsing v6net %s: %v", tt.v6nat64, err)
			}
			_, podNet, err := net.ParseCIDR(tt.podRange)
			if err != nil {
				t.Fatalf("unexpected error parsing podNet %s: %v", tt.podRange, err)
			}
			if err := validateNetworks(v4net, v6net, podNet); (err != nil) != tt.wantErr {
				t.Errorf("validateNetworks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
