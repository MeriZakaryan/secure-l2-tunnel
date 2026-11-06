// device: transparent inline encryption device ("bump in the wire").
// 1. Handshake with the peer device over raw Ethernet (EtherType 0x88B5):
//    ephemeral Diffie-Hellman (ffdhe2048), signed with long-term RSA-2048 keys, HKDF-SHA256.
// 2. In-place mode: encrypts only the TCP payload of protected packets with AES-256-GCM,
//    keeps the IP/TCP headers, appends counter (8 B) + tag (16 B), fixes checksums.
// Usage: ./device [-v] [-k keydir] <1|2> <lan_if> <wan_if>
//   1 = Device1 (PC1 side, initiator), 2 = Device2 (PC2 side, responder)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include "netutil.h"
#include "packet.h"
#include "crypto.h"
#include "handshake.h"

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static int lan_fd = -1, wan_fd = -1, verbose = 0, role = 0;
static struct hs_state hs;

// ---- Session state: one key + salt per direction ----
static struct {
    int      ready;     // 1 after a successful handshake
    uint8_t  tx_key[AES_KEY_LEN], rx_key[AES_KEY_LEN];
    uint8_t  tx_salt[SALT_LEN],   rx_salt[SALT_LEN];
    uint64_t tx_ctr;    // last counter used for sending
    uint64_t rx_last;   // highest counter accepted from the peer
} sess;

static struct {
    unsigned long long passed, encrypted, decrypted, auth_fail, replay, dropped, no_session, hs_fail;
} st;

static int is_handshake(const uint8_t *f, size_t len) {
    return len >= ETH_HDR_LEN && f[12] == (HS_ETHERTYPE >> 8) && f[13] == (HS_ETHERTYPE & 0xff);
}

// Install fresh keys from the handshake. Counters restart at 0: safe, because the keys are new.
static void session_install(const struct hs_keys *k) {
    if (role == 1) {
        memcpy(sess.tx_key, k->k12, AES_KEY_LEN); memcpy(sess.tx_salt, k->s12, SALT_LEN);
        memcpy(sess.rx_key, k->k21, AES_KEY_LEN); memcpy(sess.rx_salt, k->s21, SALT_LEN);
    } else {
        memcpy(sess.tx_key, k->k21, AES_KEY_LEN); memcpy(sess.tx_salt, k->s21, SALT_LEN);
        memcpy(sess.rx_key, k->k12, AES_KEY_LEN); memcpy(sess.rx_salt, k->s12, SALT_LEN);
    }
    sess.tx_ctr = 0;
    sess.rx_last = 0;
    sess.ready = 1;

    printf("Secure session established. Session ID: ");
    for (int i = 0; i < 8; i++) printf("%02x", hs.th[i]);   // public: hash of public values
    printf("\n");
}

static void handle_handshake(const uint8_t *f, size_t len) {
    uint8_t out[HS_MAX_FRAME];
    size_t out_len;
    struct hs_keys keys;
    int r = hs_handle(&hs, f, len, out, &out_len, &keys);
    if (r < 0) { st.hs_fail++; return; }
    if (r & HS_SEND) raw_send(wan_fd, out, out_len);
    if (r & HS_READY) session_install(&keys);
    OPENSSL_cleanse(&keys, sizeof(keys));
}

static void pass(int out_fd, const char *tag, uint8_t *f, size_t len) {
    if (verbose) frame_print(tag, f, len);
    if (raw_send(out_fd, f, len) == 0) st.passed++;
}

// ===== PC -> network: encrypt =====
static void handle_from_lan(uint8_t *f, size_t len) {
    if (is_handshake(f, len)) { st.dropped++; return; }   // PCs must not inject handshake frames

    struct pkt_info pi;
    int r = pkt_parse_tcp(f, len, &pi);
    if (r < 0) { st.dropped++; return; }
    if (r == 0 || !pkt_is_protected(f, &pi)) { pass(wan_fd, "LAN->WAN pass", f, len); return; }
    if (!sess.ready) { st.no_session++; return; }          // no keys yet: TCP will retransmit

    size_t new_tot = pi.tot + TRAILER_LEN;
    if (new_tot > WAN_MTU || ETH_HDR_LEN + new_tot > FRAME_MAX) {
        fprintf(stderr, "Drop: %zu bytes after encryption > MTU %d (MSS too large?)\n",
                new_tot, WAN_MTU);
        st.dropped++; return;
    }
    if (sess.tx_ctr == UINT64_MAX) {
        fprintf(stderr, "Counter exhausted: new session required\n");
        st.dropped++; return;
    }
    uint64_t ctr = ++sess.tx_ctr;

    uint8_t aad[AAD_MAX], nonce[GCM_NONCE_LEN], tag[GCM_TAG_LEN], ct[FRAME_MAX];
    size_t aad_len = pkt_build_aad(f, &pi, aad);
    make_nonce(nonce, sess.tx_salt, ctr);

    uint8_t *pl = f + pi.pl_off;
    if (aead_encrypt(sess.tx_key, nonce, aad, aad_len, pl, pi.pl_len, ct, tag) < 0) {
        fprintf(stderr, "Encryption error\n");
        st.dropped++; return;
    }
    memcpy(pl, ct, pi.pl_len);
    put_be64(pl + pi.pl_len, ctr);
    memcpy(pl + pi.pl_len + CTR_LEN, tag, GCM_TAG_LEN);
    pkt_set_ip_len(f, new_tot);
    pkt_fix_checksums(f);

    size_t out_len = ETH_HDR_LEN + new_tot;
    if (verbose) frame_print("LAN->WAN ENC ", f, out_len);
    if (raw_send(wan_fd, f, out_len) == 0) st.encrypted++;
}

// ===== network -> PC: handshake, or verify + decrypt =====
static void handle_from_wan(uint8_t *f, size_t len) {
    if (is_handshake(f, len)) { handle_handshake(f, len); return; }

    struct pkt_info pi;
    int r = pkt_parse_tcp(f, len, &pi);
    if (r < 0) { st.dropped++; return; }
    if (r == 0 || !pkt_is_protected(f, &pi)) { pass(lan_fd, "WAN->LAN pass", f, len); return; }
    if (!sess.ready) { st.no_session++; return; }

    if (pi.pl_len <= TRAILER_LEN) {
        fprintf(stderr, "Drop: protected packet too short (%zu B)\n", pi.pl_len);
        st.auth_fail++; return;
    }
    size_t ct_len = pi.pl_len - TRAILER_LEN;
    uint8_t *pl = f + pi.pl_off;
    uint64_t ctr = get_be64(pl + ct_len);
    const uint8_t *tag = pl + ct_len + CTR_LEN;

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
    sess.rx_last = ctr;

    memcpy(pl, pt, ct_len);
    size_t new_tot = pi.tot - TRAILER_LEN;
    pkt_set_ip_len(f, new_tot);
    pkt_fix_checksums(f);

    size_t out_len = ETH_HDR_LEN + new_tot;
    if (verbose) frame_print("WAN->LAN DEC ", f, out_len);
    if (raw_send(lan_fd, f, out_len) == 0) st.decrypted++;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-v] [-k keydir] <1|2> <lan_if> <wan_if>\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *keydir = "keys";
    int opt;
    while ((opt = getopt(argc, argv, "vk:")) != -1) {
        if (opt == 'v') verbose = 1;
        else if (opt == 'k') keydir = optarg;
        else usage(argv[0]);
    }
    if (argc - optind != 3) usage(argv[0]);
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

    uint8_t mac[6];
    if (if_get_mac(wan_if, mac) < 0) return 1;

    // Own private key + peer's public key, e.g. Device1: keys/dev1_priv.pem + keys/dev2_pub.pem
    char my_priv[512], peer_pub[512];
    snprintf(my_priv, sizeof(my_priv), "%s/dev%d_priv.pem", keydir, role);
    snprintf(peer_pub, sizeof(peer_pub), "%s/dev%d_pub.pem", keydir, 3 - role);
    if (hs_init(&hs, role, my_priv, peer_pub, mac) < 0) return 1;

    printf("Device%d running: %s (LAN) <-> %s (WAN), protecting TCP port %d. Ctrl+C to stop.\n",
           role, lan_if, wan_if, PROTECTED_PORT);
    if (role == 2) printf("[HS] waiting for HELLO from Device1...\n");

    struct pollfd pfd[2] = {
        { .fd = lan_fd, .events = POLLIN },
        { .fd = wan_fd, .events = POLLIN },
    };
    uint8_t buf[FRAME_MAX];
    time_t last_hello = 0;

    while (running) {
        // Device1: (re)send HELLO once per second until the session is established
        if (role == 1 && !sess.ready && time(NULL) != last_hello) {
            last_hello = time(NULL);
            size_t n = hs_build_hello(&hs, buf);
            if (n > 0 && raw_send(wan_fd, buf, n) == 0)
                printf("[HS] HELLO sent, waiting for Device2...\n");
        }

        int pr = poll(pfd, 2, 500);   // wake up at least every 0.5 s for HELLO retransmission
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }
        if (pr == 0) continue;

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

    printf("\nStopped. passed: %llu, encrypted: %llu, decrypted: %llu, auth_fail: %llu, "
           "replay: %llu, dropped: %llu, no_session: %llu, hs_fail: %llu\n",
           st.passed, st.encrypted, st.decrypted, st.auth_fail, st.replay, st.dropped,
           st.no_session, st.hs_fail);

    OPENSSL_cleanse(&sess, sizeof(sess));   // erase session keys
    hs_free(&hs);
    close(lan_fd);
    close(wan_fd);
    return 0;
}