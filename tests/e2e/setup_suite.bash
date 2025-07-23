#!/bin/bash

set -eu

function setup_suite {
  # Build the nat64 project
  docker build -t registry.k8s.io/networking/nat64:test -f Dockerfile "$BATS_TEST_DIRNAME"/../.. --output=type=docker

  # Define the name of the kind cluster
  export CLUSTER_NAME="nat64-test-cluster"

  # Check if the kind cluster exists
  if kind get clusters | grep -q "$CLUSTER_NAME"; then
    return
  fi

  kind create cluster --wait 1m --retain --name "$CLUSTER_NAME" --config="$BATS_TEST_DIRNAME"/../../kind-ipv6.yaml
  # Install nat64
  kind load docker-image registry.k8s.io/networking/nat64:test --name "$CLUSTER_NAME"
  nat64_install=$(sed 's#registry.k8s.io/networking/nat64.*#registry.k8s.io/networking/nat64:test#' < "$BATS_TEST_DIRNAME"/../../install.yaml)
  printf '%s' "${nat64_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=nat64

  # Use Google Public DNS64 https://developers.google.com/speed/public-dns/docs/dns64
  original_coredns=$(kubectl get -oyaml -n=kube-system configmap/coredns)
  echo "Original CoreDNS config:"
  echo "${original_coredns}"
  # Patch it
  fixed_coredns=$(printf '%s' "${original_coredns}" | awk '{ print } /errors/ && !inserted { print "        dns64 {\n          translate_all\n        }"; inserted = 1 }' | sed 's/\/etc\/resolv.conf/[64:ff9b::8.8.8.8]:53/' )
  echo "Patched CoreDNS config with dns64:"
  echo "${fixed_coredns}"
  printf '%s' "${fixed_coredns}" | kubectl apply -f -
  kubectl -n kube-system rollout restart deployment coredns
  kubectl -n kube-system rollout status deployment coredns
  # test depend on external connectivity that can be very flaky
  sleep 5
}

function teardown_suite {
    kind export logs "$BATS_TEST_DIRNAME"/../../_artifacts --name "$CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
}
