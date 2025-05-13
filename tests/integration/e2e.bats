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
  sudo ip netns exec ns1 ip -6 addr add 2001:db8::1/112 dev veth1
  sudo ip netns exec ns1 ip -6 route add default via 2001:db8::2

  sudo ip netns exec nsnat ip link set up dev lo
  sudo ip netns exec nsnat ip link set up dev vethnat1
  sudo ip netns exec nsnat ip -6 addr add 2001:db8::2/112 dev vethnat1

  sudo ip netns exec nsnat ip link set up dev vethnat2
  sudo ip netns exec nsnat ip addr add 1.1.1.1/24 dev vethnat2

  sudo ip netns exec ns2 ip link set up dev lo
  sudo ip netns exec ns2 ip link set up dev veth2
  sudo ip netns exec ns2 ip addr add 1.1.1.2/24 dev veth2

  # Create the nat64 interface
  sudo ip netns exec nsnat ip link add nat64 type dummy
  sudo ip netns exec nsnat ip link set up dev nat64
  sudo ip netns exec nsnat ip -6 addr add 64:ff9b::/96 dev nat64
  sudo ip netns exec nsnat ip addr add 169.254.64.0/24 dev nat64

  # Do not get dropped as martian
  sudo ip netns exec nsnat sysctl net.ipv4.conf.nat64.rp_filter=0
  
  # Add masquerading
  sudo ip netns exec nsnat nft -f /dev/stdin <<EOF
  table ip6 nat {
       chain POSTROUTING {
               type nat hook postrouting priority srcnat; policy accept;
               ip6 daddr 64:ff9b::/96 counter return comment "kube-nat64-rule"
               oifname "lo" counter masquerade
       }
}
table inet kube-nat64 {
       chain postrouting {
               type nat hook postrouting priority srcnat - 10; policy accept;
               ip saddr 169.254.64.0/24 masquerade
       }
}
EOF

  # Enable forwarding
  sudo ip netns exec nsnat sysctl -w net.ipv6.conf.all.forwarding=1
  sudo ip netns exec nsnat sysctl -w net.ipv4.ip_forward=1
  
  echo "Attaching eBPF program $BPF_NAT64_PROG to nat64 interface in nsnat..."
  sudo ip netns exec nsnat tc qdisc add dev nat64 clsact
  sudo ip netns exec nsnat tc filter add dev nat64 egress protocol ipv6 prio 1 bpf obj "$BPF_NAT64_PROG" sec tc/nat64 direct-action
  sudo ip netns exec nsnat tc filter add dev nat64 egress protocol ip prio 2 bpf obj "$BPF_NAT64_PROG" sec tc/nat46 direct-action
}

function teardown() {
  timeout 2 sudo cat /sys/kernel/debug/tracing/trace_pipe
  sudo ip netns del ns1
  sudo ip netns del ns2
  sudo ip netns del nsnat
}

@test "test TCP works through nat64" {
  skip "problem executing inside namespace"
  # setup a echo server
  sudo ip netns exec ns2 socat -v tcp-l:1234,fork exec:'/bin/cat' >/dev/null &
  trap kill $PID 2>/dev/null EXIT INT TERM

  # connect from the other namespace through NAT64
  for i in $(seq 1 5) ; do
    echo "Test TCP Connect $i"
    run sudo ip netns exec ns1 bash -c \'socat -T1 stdio tcp:[64:ff9b::1.1.1.2]:1234 <<< "hola"\'
    [ "$status" -eq 0 ]
    [ "$output" = "hola" ]
  done

  kill $PID 2>/dev/null
}

@test "test UDP works through nat64" {
  skip "problem executing inside namespace"
  # setup a echo server
  sudo ip netns exec ns2 socat -v udp-l:1234,fork exec:'/bin/cat' >/dev/null &
  PID=$!
  trap kill $PID 2>/dev/null EXIT INT TERM

  # connect from the other namespace through NAT64
  for i in $(seq 1 5) ; do
    echo "Test UDP Connect $i"
    run sudo ip netns exec ns1 bash -c \'socat -T1 stdio udp:[64:ff9b::1.1.1.2]:1234 <<< "hola"\'
    [ "$status" -eq 0 ]
    [ "$output" = "hola" ]
  done
}

@test "test ICMP works through nat64" {
  echo "Test Connect 5 times"
  sudo ip netns exec ns1 ping -q -c 5 64:ff9b::1.1.1.2 >/dev/null
}
