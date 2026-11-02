#!/usr/bin/env bash
# Remove all namespaces (their veth interfaces are deleted automatically)
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }
for ns in pc1 dev1 mitm dev2 pc2; do
    ip netns del "$ns" 2>/dev/null || true
done
echo "Topology removed."