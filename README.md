# Secure Inline Channel: AES-GCM Bump-in-the-Wire Devices

Computer Networks course project (UFAR). Two transparent inline devices protect the
traffic between PC1 and PC2 against a man-in-the-middle. They authenticate each other with
a signed Diffie–Hellman handshake, then protect data with AES-256-GCM.

## Topology

Five Linux network namespaces connected by veth pairs:

```
 PC1 ─────── Device1 ═══════ MITM ═══════ Device2 ─────── PC2
10.20.20.1   (LAN) (WAN)                 (WAN) (LAN)   10.20.20.2
                10.30.30.1                10.30.30.2
```

- **PC1 / PC2** run ordinary TCP programs (`sender`, `receiver`) and are unaware of the encryption.
- **Device1 / Device2** capture every frame with `AF_PACKET` raw sockets in promiscuous mode.
- **MITM** relays frames between the devices and can attack them (bit flip, replay, handshake tampering).

## Two protection modes

| | `inplace` (required task) | `udp` (real-world design, like a VPN) |
|---|---|---|
| What is encrypted | TCP payload of port-5000 packets | The **whole** Ethernet frame from the PC |
| Headers on the wire | Original IP/TCP headers (visible) | Outer IP/UDP between devices; inner headers hidden |
| Unprotected traffic | ARP, ICMP, SYN, pure ACK, FIN pass in clear | Nothing: everything goes through the tunnel |
| Overhead per packet | 24 B (8 B counter + 16 B tag) | 54 B (20 IP + 8 UDP + 10 header + 16 tag) |
| Checksums | IP and TCP checksums recomputed | Not needed: inner frame restored byte for byte |

### Packet formats

```
inplace:  [ Eth | IP | TCP | payload (ciphertext) | counter 8 B | tag 16 B ]
          AAD = src IP | dst IP | protocol | TCP header (checksum field zeroed)

udp:      [ Eth | IP 10.30.30.x | UDP :9000 | ver | type | counter 8 B | encrypted frame | tag 16 B ]
          AAD = ver | type | counter (10 B)
```

**Nonce** = 4-byte salt ‖ 8-byte counter. Each direction has its own key, salt and counter,
so a nonce is never reused within a session. The receiver accepts only counters greater
than the last accepted one (replay protection) and updates its counter only after the tag
has been verified.

## Handshake

Raw Ethernet frames, EtherType `0x88B5` (IEEE local experimental):

```
Device1 (initiator)                                         Device2 (responder)
   HELLO:  nonce1 | DH pub1                       ──────▶
                                                  ◀──────   REPLY:  nonce2 | DH pub2 | Sign_dev2("responder" | H)
   verify with dev2_pub.pem
   FINISH: Sign_dev1("initiator" | H)             ──────▶   verify with dev1_pub.pem

H    = SHA-256(label | nonce1 | pub1 | nonce2 | pub2)        (transcript hash)
s    = DH shared secret (ffdhe2048, 256 B, padded)
keys = HKDF-SHA256(s, salt = H) → key 1→2 | key 2→1 | salt 1→2 | salt 2→1
```

- **Ephemeral DH** (new private keys every session, erased after use) gives **forward secrecy**.
- **RSA-2048 PSS signatures** over the transcript authenticate both devices and stop a MITM
  from substituting its own DH values.
- **Nonces** make every handshake unique (no replay of old handshakes); **role labels**
  prevent a signature from being reflected back as the other role's.
- Received DH values are validated (`EVP_PKEY_public_check`), the shared secret has a fixed length.

## Security properties

| Threat | Defense | Demonstrated by |
|---|---|---|
| Eavesdropping | AES-256-GCM encryption | `tcpdump` on the MITM link |
| Modification of data | GCM tag over payload + AAD | `mitm -m flip`: `AUTH FAIL` on Device2 |
| Replay of valid packets | Strictly increasing counter | `mitm -m replay`: `REPLAY dropped` |
| MITM on key exchange | Signed transcript | `mitm -m hs-tamper`: `signature INVALID` |
| Stolen long-term keys | Forward secrecy (ephemeral DH) | New Session ID on every start |
| Nonce reuse | Per-direction keys/salts, counter, fresh keys per session | — |

Detected attacks become packet loss, which TCP recovers by retransmission, so the file
still arrives intact (identical SHA-256).

## Limitations

- **Availability is not protected**: a MITM can always drop traffic (`mitm -m flip -n 1` stalls the transfer).
- **inplace mode**: SYN, pure ACKs and FIN are neither encrypted nor authenticated (e.g. a forged
  RST can close the connection); IP addresses, ports and packet sizes are visible.
- **Strict replay check**: packets reordered on the path would be dropped (a sliding replay
  window, as in IPsec, would allow reordering).
- **No rekeying**: one key pair per session; a restart of Device2 alone requires restarting Device1.
- If the FINISH frame is lost, Device1 considers the session established while Device2 does not.
- Long-term keys are generated on one machine and trusted directly (no certificates/PKI).

## Modern alternatives

The project uses DH + RSA as taught in the course. Production systems usually choose:

- **X25519** (elliptic-curve DH): 32-byte keys instead of 256, faster, hard to misuse.
- **Ed25519** signatures: 64-byte signatures, deterministic, constant-time by design.
- **ChaCha20-Poly1305**: AEAD that is fast and constant-time without AES hardware.
- **Complete protocols**: WireGuard (Noise framework, UDP tunnel, like our `udp` mode),
  IPsec ESP, MACsec (802.1AE, layer-2 encryption like our inline devices), TLS 1.3.

## Requirements

Linux with root access, `gcc`, `make`, OpenSSL 3 headers, `iproute2`, `ethtool`, `tcpdump`:

```bash
sudo apt install build-essential libssl-dev iproute2 ethtool tcpdump
```

## Build and run

```bash
make                          # build sender, receiver, device, mitm
./scripts/genkeys.sh          # generate RSA-2048 key pairs in keys/ (never committed)
sudo ./scripts/setup.sh       # create the 5 namespaces
```

Manual run (one terminal each; start PC2's receiver before PC1's sender):

```bash
sudo ip netns exec mitm ./mitm [-m forward|flip|replay|hs-tamper] [-n N] mitm-left mitm-right
sudo ip netns exec dev2 ./device [-m inplace|udp] 2 dev2-lan dev2-wan
sudo ip netns exec dev1 ./device [-m inplace|udp] 1 dev1-lan dev1-wan
sudo ip netns exec pc2  ./receiver 5000 out.bin
sudo ip netns exec pc1  ./sender 10.20.20.2 5000 test.bin
sha256sum test.bin out.bin
```

Add `-v` to `device` or `mitm` to print every frame.

## Automated tests

```bash
sudo ./scripts/run_test.sh udp flip       # one scenario, with statistics
sudo ./scripts/run_test.sh all            # all 8 combinations
```

| Scenario | Expected result |
|---|---|
| `forward` | File identical |
| `flip` | Every flipped packet rejected (`auth_fail`), file identical |
| `replay` | Every replayed packet rejected (`replay`), file identical |
| `hs-tamper` | Signature check fails, no session established |

Logs are written to `logs/`.

## MTU

PC interfaces use MTU 1400 and the sender sets `TCP_MAXSEG` = 1360, so the largest packet
after protection fits into the 1500-byte link MTU:

- inplace: 1400 + 24 = 1424 bytes
- udp: 20 + 8 + 10 + (14 + 1400) + 16 = 1468 bytes

NIC offloads (GRO/GSO/TSO, checksum) are disabled with `ethtool`, otherwise raw sockets
would see merged oversized frames and frames with unfilled checksums.

## Project structure

```
scripts/setup.sh, teardown.sh   topology
scripts/genkeys.sh              long-term RSA keys
scripts/run_test.sh             automated end-to-end tests
src/sender.c, receiver.c        TCP programs on PC1 / PC2
src/device.c                    inline device: handshake + inplace/udp protection
src/handshake.c/.h              DH, RSA-PSS signatures, HKDF, handshake messages
src/crypto.c/.h                 AES-256-GCM (OpenSSL EVP), nonce construction
src/packet.c/.h                 packet parsing, AAD, checksums
src/netutil.c/.h                raw sockets, frame printing
src/mitm.c                      man-in-the-middle with attack modes
```