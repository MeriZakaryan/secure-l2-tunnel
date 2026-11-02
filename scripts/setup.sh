#!/usr/bin/env bash
# Build the 5-namespace topology:
#
#   pc1 [pc1-eth0]---[dev1-lan] dev1 [dev1-wan]---[mitm-left] mitm [mitm-right]---[dev2-wan] dev2 [dev2-lan]---[pc2-eth0] pc2
#   10.20.20.1                       10.30.30.1                                     10.30.30.2                     10.20.20.2
#
set -euo pipefail

NAMESPACES="pc1 dev1 mitm dev2 pc2"
PC_MTU=1400          # leaves room for 70 bytes of tunnel overhead inside 1500

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0"; exit 1
fi
command -v ethtool >/dev/null || { echo "ethtool missing: sudo apt install ethtool"; exit 1; }

# ---- 1. Fresh namespaces ----
for ns in $NAMESPACES; do
    ip netns del "$ns" 2>/dev/null || true
done
for ns in $NAMESPACES; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

# ---- 2. veth pairs: link <ifA> <nsA> <ifB> <nsB> ----
link() {
    ip link add "$1" type veth peer name "$3"
    ip link set "$1" netns "$2"
    ip link set "$3" netns "$4"
}
link pc1-eth0   pc1   dev1-lan   dev1
link dev1-wan   dev1  mitm-left  mitm
link mitm-right mitm  dev2-wan   dev2
link dev2-lan   dev2  pc2-eth0   pc2

# ---- 3. Bring up: disable IPv6 noise and NIC offloads ----
up() {
    local ns=$1 ifc=$2
    ip netns exec "$ns" sysctl -qw "net.ipv6.conf.${ifc}.disable_ipv6=1"
    # Offloads OFF: otherwise AF_PACKET sees merged 64 KB "frames" (GRO/GSO/TSO)
    # and frames with unfilled checksums (tx checksum offload)
    ip netns exec "$ns" ethtool -K "$ifc" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
    ip -n "$ns" link set "$ifc" up
}
up pc1  pc1-eth0
up dev1 dev1-lan
up dev1 dev1-wan
up mitm mitm-left
up mitm mitm-right
up dev2 dev2-wan
up dev2 dev2-lan
up pc2  pc2-eth0

# ---- 4. IP addresses ----
ip -n pc1  addr add 10.20.20.1/24 dev pc1-eth0
ip -n pc2  addr add 10.20.20.2/24 dev pc2-eth0
ip -n dev1 addr add 10.30.30.1/24 dev dev1-wan
ip -n dev2 addr add 10.30.30.2/24 dev dev2-wan

# ---- 5. Smaller MTU on the PCs (TCP MSS becomes 1400 - 40 = 1360) ----
ip -n pc1 link set pc1-eth0 mtu "$PC_MTU"
ip -n pc2 link set pc2-eth0 mtu "$PC_MTU"

# ---- 6. Promiscuous mode on raw-capture interfaces ----
ip -n dev1 link set dev1-lan   promisc on
ip -n mitm link set mitm-left  promisc on
ip -n mitm link set mitm-right promisc on
ip -n dev2 link set dev2-lan   promisc on

echo "Topology ready:"
for ns in $NAMESPACES; do
    echo "== $ns =="
    ip -n "$ns" -br addr show | grep -v '^lo'
done