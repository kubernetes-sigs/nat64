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
      run -i test-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail")
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
      run -i test-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail")
    test "$output" = "ok"
  done
}
