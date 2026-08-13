# nat64

This repo contains a NAT64 implementation for Kubernetes deployments (mainly).

While you can use
[IPv6-only in Kubernetes since 2019](https://github.com/kubernetes/enhancements/pull/1139),
the Internet is still far from parity between IPv4 and IPv6 support. DNS64 and
NAT64 are a common solution to this problem and Kubernetes is no different. To
the contrary - thanks to its "simple" network principles, this model is easy to implement.


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

## Prerequisites

* This solution is intended for IPv6-only clusters that need IPv4 connectivity
* Nodes need to have operating IPv4 network interface
* NAT64 agent does NAT only for IPs coming from the Pod assigned range, that includes all Pods with `hostNetwork: false`, pods with
  `hostNetwork: true` can use node network interface directly

### DNS64

The main problem with DNS64 in Kubernetes is that the DNS service use to be implemented as
a Deployment, so the Pods can only communicate via IPv6 with the upstream DNS server. This is
one of the main problems why we need this solution, to be able to get rid of this [hack we
have to use in KIND](https://github.com/kubernetes-sigs/kind/blob/7c2f6c1dcd332c039ac3e7d3e3dc0dd1ec2e6a6d/hack/ci/e2e-k8s.sh#L213-L238), since the Github runners are IPv4 only.

We can just forward requests to [a public DNS64 server](https://developers.google.com/speed/public-dns/docs/dns64), also CoreDNS has a [DNS64 plugin](https://coredns.io/plugins/dns64/)

#### CoreDNS configuration

If you use [CoreDNS's `dns64` plugin](https://coredns.io/plugins/dns64/)
to provide DNS64 alongside the NAT64 translation this agent performs, some
`dns64` configurations produce surprising results when combined with the
in-cluster Kubernetes DNS.

##### Known issue: `translate_all` breaks in-cluster DNS

**Symptom:** with `dns64` enabled and its `translate_all` option set, external
DNS64 lookups work correctly, but in-cluster Service DNS stops resolving
entirely. This has been reported and confirmed upstream:
[coredns/coredns#7246](https://github.com/coredns/coredns/issues/7246).

**Reproducing it:**

1. Create an IPv6-only kind cluster:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv6
nodes:
- role: control-plane
- role: worker
```

2. Install nat64 (see [Install](#install) above) so CoreDNS pods have
   internet access.

3. Patch the `coredns` ConfigMap to add a `dns64` block with `translate_all`
   enabled, and point `forward` at a DNS64-capable resolver:

```corefile
.:53 {
    errors
    health
    dns64 {
        translate_all
    }
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    forward . [64:ff9b::8.8.8.8]:53
    cache 30
    loop
    reload
    loadbalance
}
```

4. Restart the `coredns` Deployment and query from a test pod:

```console
$ nslookup kubernetes
Server:         fd00:10:96::a
Address:        fd00:10:96::a#53

*** Can't find kubernetes.default.svc.cluster.local: No answer
```

   In-cluster names no longer resolve, even though external DNS64 lookups
   (e.g. `nslookup www.google.es`) succeed.

**Why this happens:** `translate_all` causes the `dns64` plugin to rewrite
*every* query result, including the `A`/`AAAA` records the `kubernetes`
plugin returns for in-cluster Services. Once those responses are rewritten,
the client no longer receives the addresses the `kubernetes` plugin actually
generated, and in-cluster resolution breaks.

##### Recommended configuration

Do not enable `translate_all` on a Corefile that also serves in-cluster
Kubernetes DNS. Instead, scope `dns64` translation to non-cluster domains
only, and let the `kubernetes` plugin handle `cluster.local` (and the reverse
zones) before `dns64` ever sees those queries:

```corefile
.:53 {
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    dns64 {
        prefix 64:ff9b::/96
    }
    forward . [64:ff9b::8.8.8.8]:53
    cache 30
    loop
    reload
    loadbalance
}
```

Key points:

- Keep the `kubernetes` plugin block **before** `dns64` in the plugin chain,
  so cluster Service lookups are answered first and never passed to `dns64`
  for rewriting.
- Omit `translate_all` unless you have confirmed it does not affect your
  in-cluster DNS. Without it, `dns64` only synthesizes `AAAA` records when no
  real `AAAA` exists — the normal, non-breaking DNS64 behavior — and leaves
  cluster-local answers untouched.
- If you do need `translate_all` for some external zones, split it into a
  separate server block scoped to only those zones, rather than the default
  `.:53` block that also serves `cluster.local`.

##### Verifying your configuration

After applying a Corefile, confirm both paths work from a test pod:

```console
# In-cluster DNS should resolve normally
$ nslookup kubernetes
...
Name:   kubernetes.default.svc.cluster.local
Address: fd00:10:96::1

# External DNS64 should still synthesize an address
$ nslookup www.google.es
...
Name:   www.google.es
Address: 64:ff9b::acd9:da5e
```

If the in-cluster lookup fails while the external one succeeds, revisit your
Corefile for a `translate_all` setting applied to the same server block that
handles `cluster.local`.

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

Just do `kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/nat64/refs/heads/main/install.yaml`


## Development

Assuming you have checked out the repo and you are already in the repo folder

1. Install kind cluster with IPv6 only using `kind-ipv6.yaml` located in the
   root directory of the repository

```sh
kind create cluster --name ipv6 --config kind-ipv6.yaml
```

1. Build project (it already compiles the eBPF code too)

```sh
make image-build
# save image tag
IMAGE_TAG=...
```

1. Preload the image in the kind cluster we just created

```sh
kind load docker-image ${IMAGE_TAG} --name ipv6
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
- [x] ICMP
- [ ] Testing, testing, ....

## Contributors

@siwiutki
@ampanasiuk

## References

- https://datatracker.ietf.org/doc/html/rfc6052
- https://datatracker.ietf.org/doc/html/rfc6146
- https://datatracker.ietf.org/doc/html/rfc6145
- https://blog.dan.drown.org/clatd-on-android/
