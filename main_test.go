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
	"github.com/vishvananda/netns"
)

func Test_syncRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	_, v4net, err := net.ParseCIDR("192.168.0.0/18")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	gwIf := "eth0"

	expectedNftables := `
table inet kube-nat64 {
				chain postrouting {
								type nat hook postrouting priority srcnat - 10; policy accept;
  							ip saddr 192.168.0.0/18 oifname "eth0" masquerade counter packets 0 bytes 0
				}
}
`

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origns.Close() // nolint:errcheck

	// Create a new network namespace
	newns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newns.Close() // nolint:errcheck

	err = syncRules(v4net, gwIf)
	if err != nil {
		t.Fatalf("error syncing nftables rules: %v", err)
	}

	cmd := exec.Command("nft", "list", "table", "inet", tableName)
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
	// Switch back to the original namespace
	_ = netns.Set(origns)
}

func compareMultilineStringsIgnoreIndentation(str1, str2 string) bool {
	// Remove all indentation from both strings
	re := regexp.MustCompile(`(?m)^\s+`)
	str1 = re.ReplaceAllString(str1, "")
	str2 = re.ReplaceAllString(str2, "")

	return str1 == str2
}
