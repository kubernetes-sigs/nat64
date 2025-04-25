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
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

type testSetup struct {
	v4net   *net.IPNet
	v6net   *net.IPNet
	podnet  *net.IPNet
	gwIface string
	nftConn *nftables.Conn
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

	nftConn, err := nftables.New()
	if err != nil {
		cleanup()
		t.Fatalf("unexpected error %v", err)
	}

	setup.v4net = v4net
	setup.v6net = v6net
	setup.podnet = podnet
	setup.gwIface = "eth0"
	setup.nftConn = nftConn

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
