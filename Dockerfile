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

ARG GOARCH="amd64"

FROM ubuntu:24.04 AS ebpf-builder
WORKDIR /go/src/app
RUN apt-get update && apt-get -y install clang llvm
COPY ./bpf ./bpf
# TODO: make it so that we only build this in Makefile and just copy object files here
RUN clang -target bpf -I ./bpf/include -g -Wall -O2 -c bpf/nat64.c -o bpf/nat64.o

FROM golang:1.24 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY ./main.go ./metrics.go ./go.mod ./go.sum ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/nat64 .

FROM gcr.io/distroless/static-debian12
COPY --from=ebpf-builder --chown=root:root /go/src/app/bpf/nat64.o /bpf/nat64.o
COPY --from=builder --chown=root:root /go/bin/nat64 /nat64
CMD ["/nat64"]
