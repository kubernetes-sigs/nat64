ARG GOARCH="amd64"

FROM ubuntu:22.04 AS ebpf-builder
WORKDIR /go/src/app
RUN apt-get update && apt-get -y install clang llvm
COPY ./bpf ./bpf
# TODO: make it so that we only build this in Makefile and just copy object files here
RUN clang -target bpf -I ./bpf/include -g -Wall -O2 -c bpf/nat64.c -o bpf/nat64.o

FROM golang:1.22 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY ./main.go ./go.mod ./go.sum ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/nat64 .

FROM registry.k8s.io/build-image/distroless-iptables:v0.5.1
COPY --from=ebpf-builder --chown=root:root /go/src/app/bpf/nat64.o /bpf/nat64.o
COPY --from=builder --chown=root:root /go/bin/nat64 /nat64
CMD ["/nat64"]
