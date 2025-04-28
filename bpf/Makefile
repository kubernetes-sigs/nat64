# Copyright 2025 The Kubernetes Authors.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include ../Makefile.defs

BPF_OBJ = nat64.o
TEST = nat64_test
TEST_OBJ = $(TEST).o

include ./Makefile.bpf

.PHONY: all bpf_all build_all clean

all: bpf_all

bpf_all: $(BPF_OBJ)

build_all: force
	$(MAKE) bpf_all

BPF_TEST_FLAGS:=
ifneq ($(shell id -u), 0)
                BPF_TEST_FLAGS += -exec "sudo -E"
endif

test: $(TEST_OBJ)
	$(QUIET)$(GO) test ./bpftest -bpf-test-path $(ROOT_DIR)/bpf -test $(TEST) $(BPF_TEST_FLAGS)

clean:
	rm -f *.o *.ll *.i *.s
