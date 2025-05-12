#!/bin/bash

set -eu

function setup_suite {
  # Build the nat64 project
  docker run -v "$BATS_TEST_DIRNAME"/../../bpf:/bpf silkeh/clang:17-bookworm clang -target bpf -I /bpf/include -g -Wall -O2 -c bpf/nat64.c -o bpf/nat64.o
  export BPF_NAT64_PROG="$BATS_TEST_DIRNAME"/../../bpf/nat64.o
}

function teardown_suite {
  sudo rm "$BPF_NAT64_PROG"
}
