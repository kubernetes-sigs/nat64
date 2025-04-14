#!/bin/bash

set -eu

function setup_suite {
# Create 2 network namespaces
sudo ip netns add NorthNS
sudo ip netns add SouthNS

# Connect the namespaces using a veth pair
sudo ip link add name vethSouth type veth peer name vethNorth
sudo ip link set netns NorthNS dev vethNorth
sudo ip link set netns SouthNS dev vethSouth

# Configure the namespaces network so they can reach each other
sudo ip netns exec NorthNS ip link set up dev lo
sudo ip netns exec NorthNS ip link set up dev vethNorth
sudo ip netns exec NorthNS ip addr add 1.1.1.1/24 dev vethNorth

sudo ip netns exec SouthNS ip link set up dev lo
sudo ip netns exec SouthNS ip link set up dev vethSouth
sudo ip netns exec SouthNS ip addr add 1.1.1.2/24 dev vethSouth
  # test depend on external connectivity that can be very flaky
  sleep 5
}

function teardown_suite {
    kind export logs "$BATS_TEST_DIRNAME"/../../_artifacts --name "$CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
}