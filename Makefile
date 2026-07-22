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

# List of subdirectories used for global "make build", "make clean", etc
SUBDIRS := bpf

# Filter out any directories where the parent directory is also present, to avoid
# building or cleaning a subdirectory twice.
# For example: The directory "tools" is transformed into a match pattern "tools/%",
# which is then used to filter out items such as "tools/mount" and "tools/sysctlfx"
SUBDIRS := $(filter-out $(foreach dir,$(SUBDIRS),$(dir)/%),$(SUBDIRS))


.PHONY: clean force

all: build

# Builds all the components for Cilium by executing make in the respective sub directories.
build: $(SUBDIRS)

# Execute default make target(make all) for the provided subdirectory.
$(SUBDIRS): force
	@ $(MAKE) -C $@ all

# Perform overall cleanup
clean:
	-$(QUIET) for i in $(SUBDIRS); do $(MAKE) $(SUBMAKEOPTS) -C $$i clean; done

force :;

test:
	go test -v -count 1 -race ./...

lint:
	hack/lint.sh

# get image name from directory we're building
IMAGE_NAME=nat64
# docker image registry, default to upstream
REGISTRY?=gcr.io/k8s-staging-networking
# tag based on date-sha
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
# the full image tag
NAT64_IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(TAG)
PLATFORMS?=linux/amd64,linux/arm64

.PHONY: ensure-buildx
ensure-buildx:
	./hack/init-buildx.sh

image-build:
	docker buildx build . \
		--tag="${NAT64_IMAGE}" \
		--load

image-push:
	docker buildx build . \
		--platform="${PLATFORMS}" \
		--tag="${NAT64_IMAGE}" \
		--push

.PHONY: release # Build a multi-arch docker image
release: ensure-buildx image-push
