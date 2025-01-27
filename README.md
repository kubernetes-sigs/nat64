# nat64

NAT64 implementation for Kubernetes deployments (mainly)

Despite you can use [IPv6 only in Kubernetes since 2019](https://github.com/kubernetes/enhancements/pull/1139) the Internet is still far of having parity between both IPv4 and
IPv6 worlds. DNS64 and NAT64 are commonly used to solve this problem and Kubernetes is not different, on the contrary, thanks to its "simple" network principlies this model is easy to implement.


            +---------------------+         +---------------+
             |IPv6 network         |         |    IPv4       |
             |           |  +-------------+  |  network      |
             |           |--| Name server |--|               |
             |           |  | with DNS64  |  |  +----+       |
             |  +----+   |  +-------------+  |  | H2 |       |
             |  | H1 |---|         |         |  +----+       |
             |  +----+   |      +-------+    |  192.0.2.1    |
             |2001:db8::1|------| NAT64 |----|               |
             |           |      +-------+    |               |
             |           |         |         |               |
             +---------------------+         +---------------+

              [rfc6146](https://datatracker.ietf.org/doc/html/rfc6146)

### DNS64

The main problem with DNS64 in Kubernetes is that the DNS service use to be implemented as
a Deployment, so the Pods only can communicate via IPv6 with the upstream DNS server. This is
one of the main problems why we need this solution, to be able to get rid from this [hack we
have to use in KIND](https://github.com/kubernetes-sigs/kind/blob/7c2f6c1dcd332c039ac3e7d3e3dc0dd1ec2e6a6d/hack/ci/e2e-k8s.sh#L213-L238) , since the Github runners are IPv4 only.

We can just forward requests to [a public DNS64 server](https://developers.google.com/speed/public-dns/docs/dns64), also CoreDNS has a [DNS64 plugin](https://coredns.io/plugins/dns64/)

### NAT64

This is more tricky, one of the common solutions is to use an external gateway to perform NAT64, but that requires additional infrastructure and probable more cost and complexity, and is hard to implement on CI systems with [KIND](https://kind.sigs.k8s.io/) that run
nested on VMs.

One of the nice things of Kubernetes, is that it is decoupled of the underlying infrastructure, in a Kubernetes IPv6-only cluster the family depends on the [addresses assigned to the different API objects](https://kubernetes.io/docs/concepts/cluster-administration/networking/#cluster-network-ipfamilies), so Pods, Services and Nodes only have IPv6 address and communicate using them, but the infrastructure can be dual-stack.
Using VMs with with dual stack addresses can allow use to implement NAT64 in the host.

There are [many implementations of Open Source NAT64](https://ripe85.ripe.net/presentations/78-ripe85-open-source-nat64.pdf) but I didn't find any of them that was able to fit my needs, in terms of simplicity, performance, dependencies, ...

Some time ago [I hacked a solution proxying IPv6 on IPv4](https://github.com/aojea/tproxy64/) but it was just that ... a hack. However, I've found out recently that [android
has a NAT64 implementation in eBPF](https://android.googlesource.com/platform//system/netd/+/c753c3d3735396a9686b3447bae6bdea85ebb1e2/bpf_progs/clatd.c) and started to think more about this ...

The main problem is that we need to implement [Stateful NAT64](https://datatracker.ietf.org/doc/html/rfc6146), and writing the NAT/conntrack logic is complex and hard to support, not mentioning that both NAT/conntrack systems are not synchronized so there can be [collisions and packet drops](https://github.com/cilium/cilium/issues/23604#issuecomment-1832040160) :/

I also wanted this solution simple to troubleshoot and hermetic, so I remember my old days configuring routers, and I liked the existing solutions using a NAT64 interface.

With all of these ideas I came up with this solution that basically goes as:

1. The program runs as Daemonset all nodes

1. It configures a dummy interface named `nat64` by default

```sh
5: nat64: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether ca:a6:ab:76:fb:7c brd ff:ff:ff:ff:ff:ff
    inet 169.254.64.0/24 scope global nat64
       valid_lft forever preferred_lft forever
    inet6 64:ff9b::/96 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::c8a6:abff:fe76:fb7c/64 scope link
       valid_lft forever preferred_lft forever
```

1. This interface has assigned two subnets

   1. The IPv6 one is the IPv4 in IPv6 prefx, the default is `64:ff9b::/96` per rfc6052

   1. The IPv4 one is `169.254.64.0/24`, link-local also alleviates the risk of leaking traffic or overlapping.

1. The packets with IPv6 prefix that are directed are NAT64 stateless

   1. Pod IPv6 saddr is replaced by one address in the IPv4 configured range

   1. Destination IPv6 has the destination IP4 embedded

1. After the static NAT is performed, the packet goes through the kernel again and is MASQUERADE to the Internet with the IPv4 of the host, replacing the IPv4 from the `nat64` interface range.

1. When the packet comes back, the MASQUERADE is reverted and the packet is destinted to the `nat64`interface where the static NAT64 is reverted.

   1. Source IPv6 address is the IPv4 in IPv6 address

   1. Destination IPv6 address is the one we used in the step 4.

## Install

Just do `kubectl apply -f https://raw.githubusercontent.com/aojea/nat64/main/install.yaml`


## Development

Assuming you have checked out the repo and you are already in the repo folder

1. Install kind cluster with IPv6 only

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
networking:
  ipFamily: ipv6
nodes:
- role: control-plane
- role: worker
```

```sh
kind create cluster --name ipv6 --config kind-ipv6.yaml
```

1. Build project (it already compiles the eBPF code too)

```sh
docker build . -t aojea/nat64:v0.1.0
```

1. Preload the image in the kind cluster we just created

```sh
kind load docker-image aojea/nat64:v0.1.0 --name ipv6
```

1. Install the nat64 daemonset

```sh
kubectl apply -f install.yaml
```

in case you already have it installed you can rollout restart the daemonset or just delete and create again

```sh
kubectl delete -f install.yaml  && kubectl apply -f install.yaml
```

1. Once it is installed you can test it by creating a pod and checking the connectivity to IPv4 sites using the NAT64 prefix:

```sh
$ kubectl run test --image k8s.gcr.io/e2e-test-images/agnhost:2.39 --command -- /agnhost netexec --http-port=8080
$ kubectl exec -it test bash
...
# UDP test
dig @64:ff9b::8.8.8.8 www.google.es
# TCP test
curl [64:ff9b::140.82.121.4]:80
```

## TODO

This is far to be complete, features and suggestions are welcome:

- [ ] metrics: number of NAT64 translations: connection, packets, protocol, ...
- [ ] Right now the algorithm to map 6 to 4 is very simple, use the latest digit from the Pod IPv6 address, this limits us to 254 connection, is that enough?
- [x] TCP and UDP checksum (fixed by @siwiutki)
- [ ] ICMP
- [ ] Testing, testing, ....

## Contributors

@siwiutki

## References

- https://datatracker.ietf.org/doc/html/rfc6052
- https://datatracker.ietf.org/doc/html/rfc6146
- https://datatracker.ietf.org/doc/html/rfc6145
- https://blog.dan.drown.org/clatd-on-android/
