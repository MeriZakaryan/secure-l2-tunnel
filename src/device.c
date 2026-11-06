// device: transparent inline encryption device ("bump in the wire").
// In-place mode: encrypts only the TCP payload of protected packets with AES-256-GCM,
// keeps the IP/TCP headers, appends counter (8 B) + tag (16 B), fixes checksums.
// Usage: ./device [-v] <1|2> <lan_if> <wan_if>
//   1 = Device1 (PC1 side), 2 = Device2 (PC2 side)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include "netutil.h"
#include "packet.h"
#include "crypto.h"

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static int lan_fd = -1, wan_fd = -1, verbose = 0;

// ---- Session state: one key + salt per direction ----
static struct {
    uint8_t  tx_key[AES_KEY_LEN], rx_key[AES_KEY_LEN];
    uint8_t  tx_salt[SALT_LEN],   rx_salt[SALT_LEN];
    uint64_t tx_ctr;    // last counter used for sending (next packet uses tx_ctr + 1)
    uint64_t rx_last;   // highest counter accepted from the peer (replay protection)
} sess;

static struct {
    unsigned long long passed, encrypted, decrypted, auth_fail, replay, dropped;
} st;

// TEMPORARY (commit 4 only): hardcoded test keys. Commit 5 replaces this with keys
// derived from the authenticated DH handshake. Hardcoded keys are a vulnerability:
// anyone can read them from the source or with `strings ./device`.
static void session_init_test_keys(int role) {
    uint8_t k12[AES_KEY_LEN], k21[AES_KEY_LEN], s12[SALT_LEN], s21[SALT_LEN];
    memset(k12, 0x11, sizeof(k12));   // key for direction Device1 -> Device2
    memset(k21, 0x22, sizeof(k21));   // key for direction Device2 -> Device1
    memset(s12, 0xA1, sizeof(s12));
    memset(s21, 0xB2, sizeof(s21));

    if (role == 1) {
        memcpy(sess.tx_key, k12, AES_KEY_LEN); memcpy(sess.tx_salt, s12, SALT_LEN);
        memcpy(sess.rx_key, k21, AES_KEY_LEN); memcpy(sess.rx_salt, s21, SALT_LEN);
    } else {
        memcpy(sess.tx_key, k21, AES_KEY_LEN); memcpy(sess.tx_salt, s21, SALT_LEN);
        memcpy(sess.rx_key, k12, AES_KEY_LEN); memcpy(sess.rx_salt, s12, SALT_LEN);
    }
    sess.tx_ctr = 0;
    sess.rx_last = 0;
}

// Forward a frame unchanged (ARP, ICMP, SYN, pure ACK, other ports)
static void pass(int out_fd, const char *tag, uint8_t *f, size_t len) {
    if (verbose) frame_print(tag, f, len);
    if (raw_send(out_fd, f, len) == 0) st.passed++;
}

// ===== PC -> network: encrypt =====
static void handle_from_lan(uint8_t *f, size_t len) {
    struct pkt_info pi;
    int r = pkt_parse_tcp(f, len, &pi);
    if (r < 0) { st.dropped++; return; }
    if (r == 0 || !pkt_is_protected(f, &pi)) { pass(wan_fd, "LAN->WAN pass", f, len); return; }

    size_t new_tot = pi.tot + TRAILER_LEN;
    if (new_tot > WAN_MTU || ETH_HDR_LEN + new_tot > FRAME_MAX) {
        fprintf(stderr, "Drop: %zu bytes after encryption > MTU %d (MSS too large?)\n",
                new_tot, WAN_MTU);
        st.dropped++; return;
    }
    if (sess.tx_ctr == UINT64_MAX) {            // never wrap around: that would reuse nonces
        fprintf(stderr, "Counter exhausted: new session required\n");
        st.dropped++; return;
    }
    uint64_t ctr = ++sess.tx_ctr;

    uint8_t aad[AAD_MAX], nonce[GCM_NONCE_LEN], tag[GCM_TAG_LEN], ct[FRAME_MAX];
    size_t aad_len = pkt_build_aad(f, &pi, aad);   // BEFORE changing the header
    make_nonce(nonce, sess.tx_salt, ctr);

    uint8_t *pl = f + pi.pl_off;
    if (aead_encrypt(sess.tx_key, nonce, aad, aad_len, pl, pi.pl_len, ct, tag) < 0) {
        fprintf(stderr, "Encryption error\n");
        st.dropped++; return;
    }

    // Rebuild in place: ciphertext | counter | tag
    memcpy(pl, ct, pi.pl_len);
    put_be64(pl + pi.pl_len, ctr);
    memcpy(pl + pi.pl_len + CTR_LEN, tag, GCM_TAG_LEN);
    pkt_set_ip_len(f, new_tot);
    pkt_fix_checksums(f);

    size_t out_len = ETH_HDR_LEN + new_tot;
    if (verbose) frame_print("LAN->WAN ENC ", f, out_len);
    if (raw_send(wan_fd, f, out_len) == 0) st.encrypted++;
}

// ===== network -> PC: verify + decrypt =====
static void handle_from_wan(uint8_t *f, size_t len) {
    struct pkt_info pi;
    int r = pkt_parse_tcp(f, len, &pi);
    if (r < 0) { st.dropped++; return; }
    if (r == 0 || !pkt_is_protected(f, &pi)) { pass(lan_fd, "WAN->LAN pass", f, len); return; }

    if (pi.pl_len <= TRAILER_LEN) {
        fprintf(stderr, "Drop: protected packet too short (%zu B)\n", pi.pl_len);
        st.auth_fail++; return;
    }
    size_t ct_len = pi.pl_len - TRAILER_LEN;
    uint8_t *pl = f + pi.pl_off;
    uint64_t ctr = get_be64(pl + ct_len);
    const uint8_t *tag = pl + ct_len + CTR_LEN;

    // Replay protection: counters must strictly increase
    if (ctr <= sess.rx_last) {
        fprintf(stderr, "REPLAY dropped: counter %llu <= last accepted %llu\n",
                (unsigned long long)ctr, (unsigned long long)sess.rx_last);
        st.replay++; return;
    }

    uint8_t aad[AAD_MAX], nonce[GCM_NONCE_LEN], pt[FRAME_MAX];
    size_t aad_len = pkt_build_aad(f, &pi, aad);
    make_nonce(nonce, sess.rx_salt, ctr);

    if (aead_decrypt(sess.rx_key, nonce, aad, aad_len, pl, ct_len, tag, pt) < 0) {
        fprintf(stderr, "AUTH FAIL: tag mismatch, packet dropped (counter %llu)\n",
                (unsigned long long)ctr);
        st.auth_fail++; return;
    }
    sess.rx_last = ctr;          // update only AFTER the tag was verified

    // Restore the original packet: plaintext, original length, valid checksums
    memcpy(pl, pt, ct_len);
    size_t new_tot = pi.tot - TRAILER_LEN;
    pkt_set_ip_len(f, new_tot);
    pkt_fix_checksums(f);

    size_t out_len = ETH_HDR_LEN + new_tot;
    if (verbose) frame_print("WAN->LAN DEC ", f, out_len);
    if (raw_send(lan_fd, f, out_len) == 0) st.decrypted++;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-v] <1|2> <lan_if> <wan_if>\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        if (opt == 'v') verbose = 1;
        else usage(argv[0]);
    }
    if (argc - optind != 3) usage(argv[0]);

    int role;
    if      (strcmp(argv[optind], "1") == 0) role = 1;
    else if (strcmp(argv[optind], "2") == 0) role = 2;
    else usage(argv[0]);
    const char *lan_if = argv[optind + 1], *wan_if = argv[optind + 2];

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    lan_fd = raw_open(lan_if);
    wan_fd = raw_open(wan_if);
    if (lan_fd < 0 || wan_fd < 0) return 1;

    session_init_test_keys(role);
    printf("Device%d running: %s (LAN) <-> %s (WAN), protecting TCP port %d. Ctrl+C to stop.\n",
           role, lan_if, wan_if, PROTECTED_PORT);

    struct pollfd pfd[2] = {
        { .fd = lan_fd, .events = POLLIN },
        { .fd = wan_fd, .events = POLLIN },
    };
    uint8_t buf[FRAME_MAX];

    while (running) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }
        if (pfd[0].revents & POLLIN) {
            ssize_t n = raw_recv(lan_fd, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) handle_from_lan(buf, (size_t)n);
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t n = raw_recv(wan_fd, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) handle_from_wan(buf, (size_t)n);
        }
    }

    printf("\nStopped. passed: %llu, encrypted: %llu, decrypted: %llu, "
           "auth_fail: %llu, replay: %llu, dropped: %llu\n",
           st.passed, st.encrypted, st.decrypted, st.auth_fail, st.replay, st.dropped);

    memset(&sess, 0, sizeof(sess));   // erase keys (commit 5: use OPENSSL_cleanse)
    close(lan_fd);
    close(wan_fd);
    return 0;
}