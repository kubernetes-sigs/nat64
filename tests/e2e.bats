#!/usr/bin/env bats

# setup is called at the beginning of every test.
function setup() {
  DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"



}

# teardown is called at the end of every test.
function teardown() {
  kind delete cluster --name "$CLUSTER_NAME"
}

@test "test curl works from Pods" {
  for i in $(seq 1 5) ; do
    run kubectl \
      run -i test-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --command \
      -- sh -c "curl -6 www.github.com"
    [ "$status" -eq 0 ]
  done
}

@test "test curl works from host network Pods" {
  for i in $(seq 1 5) ; do
      run kubectl \
      run -i test-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --command \
      -- sh -c "curl -6 www.github.com"
    [ "$status" -eq 0 ]
  done
}
