#!/usr/bin/env bats

@test "test curl works from Pods" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    kubectl \
      run test-curl$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail"
    kubectl wait --for=jsonpath='{.status.containerStatuses[0].state.terminated}' pod/test-curl$i --timeout=30s
    output=$(kubectl logs test-curl$i)
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
    kubectl \
      run test-ping$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "ping -6 -c 1 64:ff9b::$ip_address -q >/dev/null && echo ok || echo fail"
    kubectl wait --for=jsonpath='{.status.containerStatuses[0].state.terminated}' pod/test-ping$i --timeout=30s
    output=$(kubectl logs test-ping$i)
    test "$output" = "ok"
  done
}

@test "test dig works from Pods" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    kubectl \
      run test-dig$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --restart=Never \
      --command \
      -- sh -c "dig @64:ff9b::8.8.8.8 www.google.com >/dev/null && echo ok || echo fail"
    kubectl wait --for=jsonpath='{.status.containerStatuses[0].state.terminated}' pod/test-dig$i --timeout=30s
    output=$(kubectl logs test-dig$i)
    test "$output" = "ok"
  done
}

@test "test metric server is up and operating on host" {
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    kubectl \
      run test-metrics$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --restart=Never \
      --command \
      -- sh -c "curl --silent localhost:8881/metrics | grep process_start_time_seconds >/dev/null && echo ok || echo fail"
    kubectl wait --for=jsonpath='{.status.containerStatuses[0].state.terminated}' pod/test-metrics$i
    output=$(kubectl logs test-metrics$i)
    test "$output" = "ok"
  done
}

@test "test missing nat64 interface restart the pod" {
  docker exec "$CLUSTER_NAME-worker" ip link del nat64
  nat64_pod_name=$(kubectl get pods -n kube-system -l app=nat64 --field-selector spec.nodeName="$CLUSTER_NAME-worker" -o jsonpath='{.items[0].metadata.name}')

  echo "Getting initial restart count for $nat64_pod_name..."
  local initial_restarts
  initial_restarts=$(kubectl get pod -n kube-system $nat64_pod_name \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null) || initial_restarts=0
  echo "Initial restart count for $nat64_pod_name: $initial_restarts"

  echo "Polling for restart of nat64 pod $nat64_pod_name (initial restarts: $initial_restarts)..."
  local final_restarts=$initial_restarts
  local attempts=30 # 30 attempts * 5 seconds = 150 seconds timeout
  for i in $(seq 1 $attempts); do
    current_restarts=$(kubectl get pod -n kube-system $nat64_pod_name -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null) || current_restarts=$initial_restarts
    if [ "$current_restarts" -gt "$initial_restarts" ]; then
      final_restarts=$current_restarts
      echo "nat64 pod $nat64_pod_name has restarted. New count: $final_restarts"
      break
    fi
    echo "Polling nat64 pod $nat64_pod_name (Attempt $i/$attempts). Current restarts: $current_restarts, Initial: $initial_restarts"
    kubectl get pod -n kube-system $nat64_pod_name -o wide || echo "Could not get status of $nat64_pod_name during poll"
    sleep 5
  done

  [ "$final_restarts" -gt "$initial_restarts" ]
  sleep 3
  # verify the interface is present
  docker exec "$CLUSTER_NAME-worker" ip link show nat64

}

@test "test nftables rules are restored" {
  docker exec "$CLUSTER_NAME-worker" nft delete table inet kube-nat64
  docker exec "$CLUSTER_NAME-worker" nft delete chain ip6 nat POSTROUTING

  echo "Polling for table and rule restoration..."
  for i in $(seq 1 20); do
    # Check if table 'inet kube-nat64' exists
    if docker exec "$CLUSTER_NAME-worker" nft list table inet kube-nat64 > /dev/null 2>&1; then
      table_restored=true
    else
      table_restored=false
    fi

    # Check if exactly one rule with comment "kube-nat64-rule" exists in ip6 nat POSTROUTING
    local rule_count
    rule_count=$(docker exec "$CLUSTER_NAME-worker" nft list chain ip6 nat POSTROUTING 2>/dev/null | grep -c 'comment "kube-nat64-rule"' || true )
    if [ "$rule_count" -eq 1 ]; then
      rule_restored_correctly=true
    else
      rule_restored_correctly=false # Reset if count changes during polling
    fi

    if [ "$table_restored" = true ] && [ "$rule_restored_correctly" = true ]; then
      echo "Table and rule restored correctly."
      break
    fi

    echo "Waiting... (Attempt $i/20) Table restored: $table_restored, Rule count correct: $rule_restored_correctly (count: $rule_count)"
    sleep 5
  done
  [ "$table_restored" = true ]
  [ "$rule_restored_correctly" = true ]
}


@test "test curl works from host network Pods" {
  skip "Host Network Pods need to use as source one address from the Pod IP range"
  # TODO We can have a route that src from one of the IPs of the host in the Pod range
  # However, we need to think well how do we want to generalize this.
  # In this scenario, host network Pods run in the host namespace, so they already
  # have IPv4 access
  for i in $(seq 1 5) ; do
    echo "Test Pod $i"
    kubectl \
      run test-curl-host$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --restart=Never \
      --command \
      -- sh -c "curl -6 --silent --output /dev/null www.google.com && echo ok || echo fail"
    kubectl wait --for=jsonpath='{.status.containerStatuses[0].state.terminated}' pod/test-curl-host$i --timeout=30s
    output=$(kubectl logs test-curl-host$i)
    test "$output" = "ok"
  done
}
