#!/usr/bin/env bats

@test "test curl works from Pods" {
  for i in $(seq 1 5) ; do
    run kubectl \
      run -i test-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --command \
      -- sh -c "curl -6 --silent www.github.com && echo ok || echo fail"
    [ "$status" -eq 0 ]
    [ "$output" = "ok" ]
  done
}

@test "test curl works from host network Pods" {
  for i in $(seq 1 5) ; do
      run kubectl \
      run -i test-hostnet-dns$i \
      --image registry.k8s.io/e2e-test-images/agnhost:2.39 \
      --overrides='{"spec": {"hostNetwork": true}}' \
      --command \
      -- sh -c "curl -6 --silent www.github.com && echo ok || echo fail"
    [ "$status" -eq 0 ]
    [ "$output" = "ok" ]
  done
}
