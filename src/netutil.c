#include "netutil.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>             // if_nametoindex
#include <sys/ioctl.h>          // ioctl, SIOCGIFHWADDR
#include <arpa/inet.h>          // htons, ntohs, inet_ntop
#include <sys/socket.h>
#include <netpacket/packet.h>   // sockaddr_ll, packet_mreq, PACKET_OUTGOING
#include <net/ethernet.h>       // struct ether_header, ETHERTYPE_IP, ETHERTYPE_ARP
#include <linux/if_ether.h>     // ETH_P_ALL
#include <netinet/ip.h>         // struct iphdr
#include <netinet/tcp.h>        // struct tcphdr

int raw_open(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Unknown interface: %s\n", ifname);
        return -1;
    }

    // Protocol 0 = receive nothing until bind(). Opening with ETH_P_ALL directly
    // would capture frames from ALL interfaces in the short time before bind().
    int fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }

    // Bind to this one interface, all protocols
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)"); close(fd); return -1;
    }

    // Promiscuous mode: accept frames addressed to ANY MAC, not only ours
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = (int)ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("setsockopt(PACKET_MR_PROMISC)"); close(fd); return -1;
    }

    // Larger receive buffer: fewer frames dropped by the kernel during bursts
    int rcvbuf = 4 * 1024 * 1024;   // 4 MB
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
        perror("setsockopt(SO_RCVBUF) (continuing)");

    return fd;
}

ssize_t raw_recv(int fd, unsigned char *buf, size_t cap) {
    struct sockaddr_ll from;
    socklen_t from_len = sizeof(from);

    // MSG_TRUNC: return the REAL frame length even if it didn't fit in buf
    ssize_t n = recvfrom(fd, buf, cap, MSG_TRUNC, (struct sockaddr *)&from, &from_len);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return 0;
        perror("recvfrom");
        return -1;
    }
    // Frames leaving this interface (sent by us or by the local kernel): ignore
    if (from.sll_pkttype == PACKET_OUTGOING) return 0;

    if ((size_t)n > cap) {
        fprintf(stderr, "Dropped oversized frame (%zd bytes)\n", n);
        return 0;
    }
    return n;
}

int raw_send(int fd, const unsigned char *buf, size_t len) {
    ssize_t n = send(fd, buf, len, 0);
    if (n < 0) { perror("send(raw)"); return -1; }
    if ((size_t)n != len) {
        fprintf(stderr, "Partial raw send: %zd of %zu bytes\n", n, len);
        return -1;
    }
    return 0;
}

static void mac_str(const uint8_t *m, char *out, size_t cap) {
    snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void frame_print(const char *tag, const unsigned char *f, size_t len) {
    struct ether_header eth;
    if (len < sizeof(eth)) { printf("%s  short frame (%zu B)\n", tag, len); return; }
    memcpy(&eth, f, sizeof(eth));            // copy instead of casting: safe alignment

    char src[18], dst[18];
    mac_str(eth.ether_shost, src, sizeof(src));
    mac_str(eth.ether_dhost, dst, sizeof(dst));
    uint16_t type = ntohs(eth.ether_type);
    printf("%s  %4zu B  %s > %s  ", tag, len, src, dst);

    if (type == ETHERTYPE_ARP) { printf("ARP\n"); return; }
    if (type != ETHERTYPE_IP)  { printf("ethertype 0x%04x\n", type); return; }

    // ---- IPv4 header: validate every length before using it ----
    const unsigned char *ip = f + sizeof(eth);
    size_t ip_avail = len - sizeof(eth);
    struct iphdr iph;
    if (ip_avail < sizeof(iph)) { printf("IPv4 (truncated)\n"); return; }
    memcpy(&iph, ip, sizeof(iph));
    size_t ihl = (size_t)iph.ihl * 4;        // header length is in 4-byte units
    size_t tot = ntohs(iph.tot_len);
    if (iph.version != 4 || ihl < 20 || tot < ihl || tot > ip_avail) {
        printf("IPv4 (malformed)\n"); return;
    }

    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph.saddr, s, sizeof(s));
    inet_ntop(AF_INET, &iph.daddr, d, sizeof(d));
    if (iph.protocol != IPPROTO_TCP) {
        printf("IPv4 %s > %s  proto %u%s\n", s, d, iph.protocol,
               iph.protocol == IPPROTO_ICMP ? " (ICMP)" : "");
        return;
    }

    // ---- TCP header ----
    struct tcphdr th;
    if (tot < ihl + sizeof(th)) { printf("TCP (truncated)\n"); return; }
    memcpy(&th, ip + ihl, sizeof(th));
    size_t thl = (size_t)th.doff * 4;        // TCP header length, 4-byte units
    if (thl < 20 || tot < ihl + thl) { printf("TCP (malformed)\n"); return; }

    printf("TCP %s:%u > %s:%u  [%s%s%s%s%s]  payload %zu B\n",
           s, ntohs(th.source), d, ntohs(th.dest),
           th.syn ? "S" : "", th.ack ? "A" : "", th.psh ? "P" : "",
           th.fin ? "F" : "", th.rst ? "R" : "",
           tot - ihl - thl);
}

int if_get_mac(const char *ifname, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);     // any socket works for this ioctl
    if (fd < 0) { perror("socket"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)"); close(fd); return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}