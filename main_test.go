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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"
)

var (
	usernsEnabled bool
	checkUserns   sync.Once
)

// execInUserns calls the go test binary again for the same test inside a user namespace where the
// current user is the only one mapped, and it is mapped to root inside the userns. This gives us
// permissions to create network namespaces and iptables rules without running as root on the host.
// This must be only top-level statement in the test function. Do not nest this.
// It will slightly defect the test log output as the test is entered twice
func execInUserns(t *testing.T, f func(t *testing.T)) {
	const subprocessEnvKey = `GO_SUBPROCESS_KEY`
	if testIDString, ok := os.LookupEnv(subprocessEnvKey); ok && testIDString == "1" {
		t.Run(`subprocess`, f)
		return
	}

	cmd := exec.Command(os.Args[0])
	cmd.Args = []string{os.Args[0], "-test.run=" + t.Name() + "$", "-test.v=true"}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, `-test.testlogfile=`) {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(),
		subprocessEnvKey+"=1",
	)
	// Include sbin in PATH, as some commands are not found otherwise.
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/sbin::/sbin:"+os.Getenv("PATH"))
	cmd.Stdin = os.Stdin

	// Map ourselves to root inside the userns.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

func unpriviledUserns() bool {
	checkUserns.Do(func() {
		cmd := exec.Command("sleep", "1")

		// Map ourselves to root inside the userns.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		if err := cmd.Start(); err != nil {
			// TODO: we can think userns is not supported if the "sleep" binary is not
			// present. This is unlikely, we can do tricks like use /proc/self/exe as
			// the binary to execute and ptrace, so it is never executed, but this seems
			// good enough for the tests.
			return
		}
		defer func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		usernsEnabled = true
	})

	return usernsEnabled
}

func Test_syncRules(t *testing.T) {
	if unpriviledUserns() {
		execInUserns(t, test_syncRules)
		return
	}
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges or unprivileged user namespaces")
	}

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}
	test_syncRules(t)
}

func test_syncRules(t *testing.T) {

	_, v4net, err := net.ParseCIDR("192.168.0.0/18")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	_, v6net, err := net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	gwIf := "eth0"

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

	// add a fake rule to masquerade all the traffic
	//  ip6tables -t nat -A POSTROUTING -o lo -j MASQUERADE

	cmd := exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE")
	_, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip6tables error error = %v", err)
	}

	// It is idemptotent
	for i := 0; i < 5; i++ {
		err = syncRules(v4net, v6net, gwIf)
		if err != nil {
			t.Fatalf("error syncing nftables rules: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cmd = exec.Command("nft", "list", "ruleset")
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
		t.Fatalf("nft list ruleset unexpected eror")
	}
	if strings.Contains(string(out), v6net.String()) {
		t.Errorf("unexpected rule on default table %s %s", v6net.String(), string(out))
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
