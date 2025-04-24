#!/usr/bin/env bats

@test "bpf metrics map works" {
   output=$(kubectl \
      run -i test-bpfmap \
      --privileged \
      --image gke.gcr.io/debian-base \
      --restart=Never \
      --command \
      -- sh -c "apt-get update > /dev/null && apt-get install xxd jq iputils-ping libcap2 bpftool -y --allow-change-held-packages > /dev/null; \
       ping -c 7 64:ff9b::8.8.8.8 > /dev/null; \
       bpftool map -j dump name ipv6_metrics | \
      jq \".[] | to_entries[] | select(.key | startswith(\\\"elements\\\")).value | .[].formatted | select(.key.reason==0 and (.key.protocol==1)).value.count\"")
  test "$output" = $'7'
}

@test "test curl works from Pods" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-curl$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail")
    test "$output" = "ok"
  done
}

@test "test ping works from Pods" {
  # GitHub runners are hosted on Azure VMs, which
  # don't allow inbound ICMP packets by default,
  # (see
  # https://docs.github.com/en/actions/using-github-hosted-runners/using-github-hosted-runners/about-github-hosted-runners#cloud-hosts-used-by-github-hosted-runners)
  # hence we will test ICMP against an IP assigned
  # to the default interface
  default_interface=$(ip route | grep default | awk '{print $5}')
  test ! -z $default_interface
  ip_address=$(ip addr show "$default_interface" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
  test ! -z $ip_address
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-ping$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "ping -6 -c 1 64:ff9b::$ip_address -q >/dev/null && echo ok || echo fail")
    test "$output" = "ok"
  done
}

@test "test dig works from Pods" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-dig$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "dig @64:ff9b::8.8.8.8 www.google.com >/dev/null && echo ok || echo fail")
    test "$output" = "ok"
  done
}

@test "test metric server is up and operating on host" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-metrics$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --restart=Never \
      --command \
      -- sh -c "curl --silent localhost:8881/metrics | grep process_start_time_seconds >/dev/null && echo ok || echo fail")
    test "$output" = "ok"
  done
}

@test "test curl works from host network Pods" {
  skip "Host Network Pods need to use as source one address from the Pod IP range"
  # TODO We can have a route that src from one of the IPs of the host in the Pod range
  # However, we need to think well how do we want to generalize this.
  # In this scenario, host network Pods run in the host namespace, so they already
  # have IPv4 access
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-curl-host$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail")
    test "$output" = "ok"
  done
}
