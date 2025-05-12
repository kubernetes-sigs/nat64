#!/usr/bin/env bats


function setup() {
  # Create 3 network namespaces
  sudo ip netns add ns1
  sudo ip netns add nsnat
  sudo ip netns add ns2

  # Connect the namespaces using a veth pair ns0 -- nsnat -- ns1
  sudo ip link add name veth1 type veth peer name vethnat1
  sudo ip link set netns ns1 dev veth1
  sudo ip link set netns nsnat dev vethnat1

  sudo ip link add name veth2 type veth peer name vethnat2
  sudo ip link set netns ns2 dev veth2
  sudo ip link set netns nsnat dev vethnat2

  # Configure the namespaces network so they can reach each other
  sudo ip netns exec ns1 ip link set up dev lo
  sudo ip netns exec ns1 ip link set up dev veth1
  sudo ip netns exec ns1 ip -6 addr add 2001:1:2:3:4::1/112 dev veth1
  sudo ip netns exec ns1 ip -6 route add default via 2001:1:2:3:4::2

  sudo ip netns exec nsnat ip link set up dev lo
  sudo ip netns exec nsnat ip link set up dev vethnat1
  sudo ip netns exec nsnat ip -6 addr add 2001:1:2:3:4::2/112 dev vethnat1

  sudo ip netns exec nsnat ip link set up dev vethnat2
  sudo ip netns exec nsnat ip addr add 1.1.1.1/24 dev vethnat2

  sudo ip netns exec ns2 ip link set up dev lo
  sudo ip netns exec ns2 ip link set up dev veth2
  sudo ip netns exec ns2 ip addr add 1.1.1.2/24 dev veth2

  # Create the nat64 interface
  sudo ip netns exec nsnat ip link add nat64 type dummy
  sudo ip netns exec nsnat ip link set up dev nat64
  sudo ip netns exec nsnat ip -6 addr add 64:ff9b::/96 dev nat64
  sudo ip netns exec nsnat ip addr add 169.254.169.0/24 dev nat64

  # Add masquerading
  sudo ip netns exec nsnat nft add table ip nat64
  sudo ip netns exec nsnat nft add chain ip nat64 POSTROUTING { type nat hook postrouting priority 100 \; }
  sudo ip netns exec nsnat nft add rule ip nat64 POSTROUTING ip saddr 169.254.169.0/24 masquerade

  # Enable forwarding
  sudo ip netns exec nsnat sysctl -w net.ipv6.conf.all.forwarding=1
  sudo ip netns exec nsnat sysctl -w net.ipv4.ip_forward=1
  
  echo "Attaching eBPF program $BPF_NAT64_PROG to nat64 interface in nsnat..."
  sudo ip netns exec nsnat tc qdisc add dev nat64 clsact
  sudo ip netns exec nsnat tc filter add dev nat64 ingress bpf direct-action obj "$BPF_NAT64_PROG" sec tc/nat64
  sudo ip netns exec nsnat tc filter add dev nat64 egress bpf direct-action obj "$BPF_NAT64_PROG" sec tc/nat46
}

function teardown() {
  sudo ip netns del ns1
  sudo ip netns del ns2
  sudo ip netns del nsnat
}

@test "test curl works through nat64" {
  # setup a echo server
  sudo ip netns exec ns2 socat -v tcp-l:1234,fork exec:'/bin/cat' >/dev/null &
  PID=$!
  # connect from the other namespace through NAT64
  for i in $(seq 1 5) ; do
    echo "Test Connect $i"
    output=$(sudo ip netns exec ns1 bash -c "echo hola | socat -T3 stdio tcp:[64:ff9b::1.1.1.2]:1234")
    test "$output" = "hola"
  done
  kill $PID
}
