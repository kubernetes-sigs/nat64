#!/usr/bin/env bats

@test "test curl works through nat64" {
  # setup a echo server
  ip netns exec SouthNS socat -v tcp-l:1234,fork exec:'/bin/cat'
  # connect from the other namespace through NAT64
  for i in $(seq 1 5) ; do
    echo "Test Connect $i"
    output=$(ip netns exec NorthNS "curl -6 --silent --output /dev/null 64:ff9b::1.1.1.2 && echo ok || echo fail")
    test "$output" = "ok"
  done
}

