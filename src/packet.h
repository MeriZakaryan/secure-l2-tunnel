#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define ETH_HDR_LEN    14
#define PROTECTED_PORT 5000
#define CTR_LEN        8
#define TRAILER_LEN    (CTR_LEN + GCM_TAG_LEN)   // 24 bytes appended to each protected payload
#define WAN_MTU        1500
#define AAD_MAX        (4 + 4 + 1 + 60)          // src IP, dst IP, protocol, TCP header (max 60)

struct pkt_info {
    size_t ihl;      // IP header length
    size_t tot;      // IP total length (header + TCP header + payload)
    size_t tcp_off;  // offset of the TCP header in the frame
    size_t thl;      // TCP header length
    size_t pl_off;   // offset of the TCP payload in the frame
    size_t pl_len;   // TCP payload length
};

// Returns 1 = valid IPv4/TCP (pi filled), 0 = not IPv4/TCP (forward as is),
//        -1 = malformed or fragmented (drop)
int pkt_parse_tcp(const uint8_t *f, size_t len, struct pkt_info *pi);

// Is this a packet we encrypt? (port 5000, non-empty payload)
int pkt_is_protected(const uint8_t *f, const struct pkt_info *pi);

// Build AAD: src IP | dst IP | protocol | TCP header with checksum zeroed. Returns its length.
size_t pkt_build_aad(const uint8_t *f, const struct pkt_info *pi, uint8_t *aad);

void pkt_set_ip_len(uint8_t *f, size_t new_tot);
void pkt_fix_checksums(uint8_t *f);   // recompute IP header + TCP checksums

uint64_t get_be64(const uint8_t *p);
void     put_be64(uint8_t *p, uint64_t v);

#endif