#!/usr/bin/env bats

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
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    output=$(kubectl \
      run -i test-ping$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "ping -6 -c 10 64:ff9b::8.8.8.8")
    echo "$output"
    # have false assertion so that CI prints output in job
    test 1 = 0
    #test "$output" = "ok"
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
