#!/bin/bash

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

# network config
# TODO - this should be configurable, using hardcoded values now
IPV4_CIDR="169.254.64.0/24"
IPV6_CIDR="64:ff9b::/96"
NAT_IF="nat64"

# dev setup config
KIND_CLUSTER="ipv6"
CONTAINERD="docker"

# $1 - node
# rest - args
function exec_kind_node {
    ${CONTAINERD} exec -it "$@"
}


for kind_node in `kubectl get nodes | tail -n +2 | awk '{ print $1 }'`; do
    # fetch iface with default route
    GWIF="`exec_kind_node ${kind_node} ip route | grep default | awk '{ print $5 }'`"

    # clean iptables rules
    echo "Removing IPv4 iptables rules on ${kind_node} node"
    exec_kind_node ${kind_node} iptables -t nat -D POSTROUTING -s "${IPV4_CIDR}" -o ${GWIF} -j MASQUERADE

    echo "Removing IPv6 iptables rules ${kind_node} node"
    exec_kind_node ${kind_node} ip6tables -t nat -D POSTROUTING -d "${IPV6_CIDR}" -j RETURN

    # delete network interface
    # this also unloads bpf programs since kernel unloads a bpf program
    # once there are no more references to it and the network interface
    # deleted here is the only reference
    echo "Removing nat64 network interface from ${kind_node} node"
    exec_kind_node ${kind_node} ip link delete nat64
done
