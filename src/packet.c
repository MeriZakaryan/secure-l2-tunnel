#include "packet.h"
#include <string.h>

// Read/write big-endian (network order) values byte by byte: no alignment issues
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void     put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

int pkt_parse_tcp(const uint8_t *f, size_t len, struct pkt_info *pi) {
    if (len < ETH_HDR_LEN + 20) return 0;
    if (get16(f + 12) != 0x0800) return 0;             // EtherType not IPv4 (e.g. ARP)

    const uint8_t *ip = f + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return -1;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t tot = get16(ip + 2);
    if (ihl < 20 || tot < ihl || ETH_HDR_LEN + tot > len) return -1;   // lengths must be consistent
    if (ip[9] != 6) return 0;                          // not TCP (e.g. ICMP ping)
    if (get16(ip + 6) & 0x3fff) return -1;             // MF flag or fragment offset: not supported
    if (tot < ihl + 20) return -1;

    const uint8_t *tcp = ip + ihl;
    size_t thl = (size_t)(tcp[12] >> 4) * 4;           // data offset, in 4-byte units
    if (thl < 20 || tot < ihl + thl) return -1;

    pi->ihl = ihl;
    pi->tot = tot;
    pi->tcp_off = ETH_HDR_LEN + ihl;
    pi->thl = thl;
    pi->pl_off = pi->tcp_off + thl;
    pi->pl_len = tot - ihl - thl;
    return 1;
}

int pkt_is_protected(const uint8_t *f, const struct pkt_info *pi) {
    uint16_t sport = get16(f + pi->tcp_off);
    uint16_t dport = get16(f + pi->tcp_off + 2);
    return (sport == PROTECTED_PORT || dport == PROTECTED_PORT) && pi->pl_len > 0;
}

int pkt_parse_udp(const uint8_t *f, size_t len, uint16_t port, size_t *pl_off, size_t *pl_len) {
    if (len < ETH_HDR_LEN + 20 || get16(f + 12) != 0x0800) return 0;
    const uint8_t *ip = f + ETH_HDR_LEN;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t tot = get16(ip + 2);
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17) return 0;      // 17 = UDP
    if (tot < ihl + 8 || ETH_HDR_LEN + tot > len) return 0;
    if (get16(ip + 6) & 0x3fff) return 0;                             // fragment

    const uint8_t *udp = ip + ihl;
    if (get16(udp) != port && get16(udp + 2) != port) return 0;
    size_t ulen = get16(udp + 4);                                     // UDP header + payload
    if (ulen < 8 || ulen > tot - ihl) return 0;

    *pl_off = ETH_HDR_LEN + ihl + 8;
    *pl_len = ulen - 8;
    return 1;
}

size_t pkt_build_aad(const uint8_t *f, const struct pkt_info *pi, uint8_t *aad) {
    const uint8_t *ip = f + ETH_HDR_LEN;
    memcpy(aad, ip + 12, 8);                      // source IP + destination IP
    aad[8] = ip[9];                               // protocol (6 = TCP)
    memcpy(aad + 9, f + pi->tcp_off, pi->thl);    // whole TCP header incl. options
    aad[9 + 16] = 0;                              // zero the TCP checksum field: it is
    aad[9 + 17] = 0;                              // recomputed after encryption/decryption
    return 9 + pi->thl;
}

void pkt_set_ip_len(uint8_t *f, size_t new_tot) {
    put16(f + ETH_HDR_LEN + 2, (uint16_t)new_tot);
}

// Internet checksum: sum of 16-bit words, carries folded back, then inverted
static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len) {
    while (len > 1) { sum += get16(p); p += 2; len -= 2; }
    if (len) sum += (uint32_t)p[0] << 8;          // odd last byte: pad with a zero byte
    return sum;
}
static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void pkt_fix_checksums(uint8_t *f) {
    uint8_t *ip = f + ETH_HDR_LEN;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t tot = get16(ip + 2);

    // IP header checksum: covers the IP header only
    put16(ip + 10, 0);
    put16(ip + 10, csum_fold(csum_add(0, ip, ihl)));

    // TCP or UDP checksum: pseudo-header + whole segment/datagram
    size_t csum_off;
    if      (ip[9] == 6)  csum_off = 16;   // TCP checksum field offset
    else if (ip[9] == 17) csum_off = 6;    // UDP checksum field offset
    else return;

    uint8_t *l4 = ip + ihl;
    size_t l4_len = tot - ihl;
    uint8_t pseudo[12];
    memcpy(pseudo, ip + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = ip[9];
    put16(pseudo + 10, (uint16_t)l4_len);

    put16(l4 + csum_off, 0);
    uint32_t sum = csum_add(0, pseudo, sizeof(pseudo));
    sum = csum_add(sum, l4, l4_len);
    uint16_t c = csum_fold(sum);
    if (ip[9] == 17 && c == 0) c = 0xffff;  // in UDP, 0 means "no checksum"
    put16(l4 + csum_off, c);
}