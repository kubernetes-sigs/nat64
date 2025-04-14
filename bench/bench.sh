#!/bin/bash -x

NAT64_IMAGE="registry.k8s.io/networking/nat64:bench"
GW_IFACE="eth0"
RX_ADDR="1.2.3.4"
RX_PORT="1234"

function setup_kind {
  docker build . -t ${NAT64_IMAGE}
  kind delete clusters bench || true
  kind create cluster --name bench --config kind-ipv6.yaml
  kind load docker-image ${NAT64_IMAGE} --name bench
  kubectl create -f install.yaml
}

function setup_rx_host {
  sudo ip addr add "${RX_ADDR}/30" dev ${GW_IFACE}
  python3 -m http.server ${RX_PORT} --bind ${RX_ADDR} >/dev/null 2>/dev/null &
  echo $!
}

function cleanup {
  kind delete clusters bench
  sudo ip addr del "${RX_ADDR}/30" dev ${GW_IFACE}
  kill $1
}

setup_kind
RX_SERVER_PID=`setup_rx_host`
trap "cleanup $RX_SERVER_PID" EXIT

sleep 10

kubectl run bench --image ubuntu/apache2
sleep 10

echo "### BENCHMARK LOCAL (no NAT64, reference point) ###"
ab -n 50000 "http://${RX_ADDR}:${RX_PORT}/"

echo "### BENCHMARK WITH NAT64 ###"
kubectl exec -it bench -- ab -n 50000 "http://64:ff9b::${RX_ADDR}:${RX_PORT}/"
