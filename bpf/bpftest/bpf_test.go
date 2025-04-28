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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpftests

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var (
	testPath       = flag.String("bpf-test-path", "", "Path to the eBPF tests")
	testFilePrefix = flag.String("test", "", "Single test file to run (without file extension)")
)

func TestBPF(t *testing.T) {
	if testPath == nil || *testPath == "" {
		t.Skip("Set -bpf-test-path to run BPF tests")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	entries, err := os.ReadDir(*testPath)
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".o") {
			continue
		}

		if *testFilePrefix != "" && !strings.HasPrefix(entry.Name(), *testFilePrefix) {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			loadAndRunSpec(t, entry)
		})
	}
}

func loadAndRunSpec(t *testing.T, entry fs.DirEntry) {
	elfPath := path.Join(*testPath, entry.Name())
	spec, err := ebpf.LoadCollectionSpec(elfPath)

	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("verifier error: %+v", ve)
	}
	if err != nil {
		t.Fatalf("ebpf.LoadCollectionSpec: %v", err)
	}

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	coll, err := ebpf.NewCollection(spec)
	defer coll.Close()

	// TODO: probably no need to check for verifier error here since we check that above,
	// but dunno, just copy pasting for now
	if errors.As(err, &ve) {
		t.Fatalf("verifier error: %+v", ve)
	}
	if err != nil {
		t.Fatalf("ebpf.NewCollection: %v", err)
	}

	testNameToPrograms := make(map[string]programSet)

	for progName, spec := range spec.Programs {
		match := checkProgRegex.FindStringSubmatch(spec.SectionName)
		if len(match) == 0 {
			continue
		}

		progs := testNameToPrograms[match[1]]
		if match[2] == "pktgen" {
			progs.pktgenProg = coll.Programs[progName]
		}
		if match[2] == "check" {
			progs.checkProg = coll.Programs[progName]
		}
		testNameToPrograms[match[1]] = progs
	}

	for progName, set := range testNameToPrograms {
		if set.checkProg == nil {
			t.Fatalf(
				"File '%s' contains a pktgen program in section '%s' but no check program.",
				elfPath,
				spec.Programs[progName].SectionName,
			)
		}
	}

	// Make sure sub-tests are executed in alphabetic order, to make test results repeatable if programs rely on
	// the order of execution.
	testNames := make([]string, 0, len(testNameToPrograms))
	for name := range testNameToPrograms {
		testNames = append(testNames, name)
	}
	slices.Sort(testNames)

	for _, name := range testNames {
		t.Run(name, subTest(testNameToPrograms[name], coll.Maps[suiteResultMap]))
	}
}

type programSet struct {
	pktgenProg *ebpf.Program
	checkProg  *ebpf.Program
}

var checkProgRegex = regexp.MustCompile(`[^/]+/test/([^/]+)/((?:check)|(?:pktgen))`)

const (
	ResultSuccess = 1

	suiteResultMap = "suite_result_map"
)

type skbuff struct {
}

func subTest(progSet programSet, resultMap *ebpf.Map) func(t *testing.T) {
	return func(t *testing.T) {
		// create skb with the max allowed size(4k - head room - tailroom)
		data := make([]byte, 4096-256-320)

		// skb is only used for tc programs
		// non-empty skb passed to non-tc programs will cause error: invalid argument
		skb := make([]byte, 0)
		if progSet.checkProg.Type() == ebpf.SchedCLS {
			// sizeof(struct __sk_buff) < 256, let's make it 256
			skb = make([]byte, 256)
			//skb[17] = 0x86
			//skb[16] = 0xdd
		}

		var (
			statusCode uint32
			err        error
		)

		if progSet.pktgenProg != nil {
			if statusCode, data, skb, err = runBpfProgram(progSet.pktgenProg, data, skb); err != nil {
				t.Fatalf("error while running pktgen prog: %s", err)
			}
		}

		if statusCode, data, skb, err = runBpfProgram(progSet.checkProg, data, skb); err != nil {
			t.Fatal("error while running check program:", err)
		}

		// Clear map value after each test
		defer func() {
			if resultMap == nil {
				return
			}

			var key int32
			value := make([]byte, resultMap.ValueSize())
			resultMap.Lookup(&key, &value)
			for i := 0; i < len(value); i++ {
				value[i] = 0
			}
			resultMap.Update(&key, &value, ebpf.UpdateAny)
		}()

		var key int32
		value := make([]byte, resultMap.ValueSize())
		err = resultMap.Lookup(&key, &value)
		if err != nil {
			t.Fatal("error while getting suite result:", err)
		}

		// Detect the length of the result, since the proto.Unmarshal doesn't like trailing zeros.
		valueLen := 0
		valueC := value
		for {
			_, _, len := protowire.ConsumeField(valueC)
			if len <= 0 {
				break
			}
			valueLen += len
			valueC = valueC[len:]
		}

		result := &SuiteResult{}
		err = proto.Unmarshal(value[:valueLen], result)
		if err != nil {
			t.Fatal("error while unmarshalling suite result:", err)
		}

		for _, testResult := range result.Results {
			// Remove the C-string, null-terminator.
			name := strings.TrimSuffix(testResult.Name, "\x00")
			t.Run(name, func(tt *testing.T) {
				if len(testResult.TestLog) > 0 && testing.Verbose() || testResult.Status != SuiteResult_TestResult_PASS {
					for _, log := range testResult.TestLog {
						tt.Logf("%s", log.FmtString())
					}
				}

				switch testResult.Status {
				case SuiteResult_TestResult_ERROR:
					tt.Fatal("Test failed due to unknown error in test framework")
				case SuiteResult_TestResult_FAIL:
					tt.Fail()
				case SuiteResult_TestResult_SKIP:
					tt.Skip()
				}
			})
		}

		if len(result.SuiteLog) > 0 && testing.Verbose() ||
			SuiteResult_TestResult_TestStatus(statusCode) != SuiteResult_TestResult_PASS {
			for _, log := range result.SuiteLog {
				t.Logf("%s", log.FmtString())
			}
		}

		switch SuiteResult_TestResult_TestStatus(statusCode) {
		case SuiteResult_TestResult_ERROR:
			t.Fatal("Test failed due to unknown error in test framework")
		case SuiteResult_TestResult_FAIL:
			t.Fail()
		case SuiteResult_TestResult_SKIP:
			t.SkipNow()
		}
	}
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	if len(dataOut) > 0 {
		// See comments at https://github.com/cilium/ebpf/blob/20c4d8896bdde990ce6b80d59a4262aa3ccb891d/prog.go#L563-L567
		dataOut = make([]byte, len(data)+256+2)
	}
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     1,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}

// A simplified version of fmt.Printf logic, the meaning of % specifiers changed to match the kernels printk specifiers.
// In the eBPF code a user can for example call `test_log("expected 123, got %llu", some_val)` the %llu meaning
// long-long-unsigned translates into a uint64, the rendered out would for example be -> 'expected 123, got 234'.
// https://www.kernel.org/doc/Documentation/printk-formats.txt
// https://github.com/libbpf/libbpf/blob/4eb6485c08867edaa5a0a81c64ddb23580420340/src/bpf_helper_defs.h#L152
func (l *Log) FmtString() string {
	var sb strings.Builder

	end := len(l.Fmt)
	argNum := 0

	for i := 0; i < end; {
		lasti := i
		for i < end && l.Fmt[i] != '%' {
			i++
		}
		if i > lasti {
			sb.WriteString(strings.TrimSuffix(l.Fmt[lasti:i], "\x00"))
		}
		if i >= end {
			// done processing format string
			break
		}

		// Process one verb
		i++

		var spec []byte
	loop:
		for ; i < end; i++ {
			c := l.Fmt[i]
			switch c {
			case 'd', 'i', 'u', 'x', 's':
				spec = append(spec, c)
				break loop
			case 'l':
				spec = append(spec, c)
			default:
				break loop
			}
		}
		// Advance to to next char
		i++

		// No argument left over to print for the current verb.
		if argNum >= len(l.Args) {
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(MISSING)")
			continue
		}

		switch string(spec) {
		case "u":
			fmt.Fprint(&sb, uint16(l.Args[argNum]))
		case "d", "i", "s":
			fmt.Fprint(&sb, int16(l.Args[argNum]))
		case "x":
			hb := make([]byte, 2)
			binary.BigEndian.PutUint16(hb, uint16(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "lu":
			fmt.Fprint(&sb, uint32(l.Args[argNum]))
		case "ld", "li", "ls":
			fmt.Fprint(&sb, int32(l.Args[argNum]))
		case "lx":
			hb := make([]byte, 4)
			binary.BigEndian.PutUint32(hb, uint32(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "llu":
			fmt.Fprint(&sb, uint64(l.Args[argNum]))
		case "lld", "lli", "lls":
			fmt.Fprint(&sb, int64(l.Args[argNum]))
		case "llx":
			hb := make([]byte, 8)
			binary.BigEndian.PutUint64(hb, uint64(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		default:
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(INVALID)")
			continue
		}

		argNum++
	}

	return sb.String()
}
