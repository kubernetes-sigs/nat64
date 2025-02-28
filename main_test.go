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

// TODO: having main_test.go is arguably quite ugly and calls for transfer
//       of things being tested here to a separate package.
//       we could use small refactor and move config stuff to separate place and
//       command line parsing to separate place, but that will come in later PRs,

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parsePodCIDR(t *testing.T) {
	tests := []struct {
		name                 string
		podCIDR              string
		expectedPodNetBytes  []uint32
		expectedPodMaskBytes []uint32
		expectedPodMaskSize  uint32
		shouldFail           bool
	}{
		{
			name:                 "/66 podCIDR, bytes beyond /66 provided in address",
			podCIDR:              "2001:db8:a0b:12f0::1111/66",
			expectedPodNetBytes:  []uint32{0x20010db8, 0xa0b12f0, 0, 0},
			expectedPodMaskBytes: []uint32{0xffffffff, 0xffffffff, 0xc0000000, 0},
			expectedPodMaskSize:  66,
			shouldFail:           false,
		},
		{
			name:                 "/66 podCIDR, no bytes beyond /66 provided in address",
			podCIDR:              "2001:db8:a0b:12f0::/66",
			expectedPodNetBytes:  []uint32{0x20010db8, 0xa0b12f0, 0, 0},
			expectedPodMaskBytes: []uint32{0xffffffff, 0xffffffff, 0xc0000000, 0},
			expectedPodMaskSize:  66,
			shouldFail:           false,
		},
		{
			name:                 "/128 podCIDR",
			podCIDR:              "2001:db8:a0b:12f0:2001:db8:a0b:12f0/128",
			expectedPodNetBytes:  []uint32{0x20010db8, 0xa0b12f0, 0x20010db8, 0xa0b12f0},
			expectedPodMaskBytes: []uint32{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
			expectedPodMaskSize:  128,
			shouldFail:           false,
		},
		{
			name:       "IPv4 podCIDR",
			podCIDR:    "127.0.0.1/16",
			shouldFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			podNetBytes, podMaskBytes, podMaskSize, err := parsePodCIDR(tc.podCIDR)
			if tc.shouldFail {
				assert.Error(t, err, "encountered error, but expected not to")
			} else {
				assert.NoError(t, err, "expected error, but did not encounter any")
				assert.Equal(t, tc.expectedPodNetBytes, podNetBytes, "invalid pod net bytes")
				assert.Equal(t, tc.expectedPodMaskBytes, podMaskBytes, "invalid pod mask bytes")
				assert.Equal(t, tc.expectedPodMaskSize, podMaskSize, "invalid pod mask size")
			}
		})
	}
}
