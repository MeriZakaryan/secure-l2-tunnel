# Secure Layer-2 Tunnel over UDP

Computer Networks course project (UFAR). Two transparent encryption devices protect
all traffic between PC1 and PC2 against a man-in-the-middle, using a signed
Diffie-Hellman handshake and AES-256-GCM.

## Topology

```
PC1 ── Device1 ══ MITM ══ Device2 ── PC2
10.20.20.1     10.30.30.1   10.30.30.2    10.20.20.2
```

## Setup

```bash
sudo ./scripts/setup.sh      # create namespaces
sudo ./scripts/teardown.sh   # remove them
```