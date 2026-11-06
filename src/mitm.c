// mitm: man-in-the-middle between Device1 (left) and Device2 (right).
// Attacks target the data direction left -> right.
// Usage: ./mitm [-v] [-m forward|flip|replay] [-n N] <left_if> <right_if>
//   forward : relay unchanged (default)
//   flip    : flip 1 bit in every N-th protected packet, then FIX the checksums
//             (a smart attacker: the TCP checksum is not a security mechanism)
//   replay  : re-send the first protected packet again every N-th protected packet

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include "netutil.h"
#include "packet.h"

enum { MODE_FORWARD, MODE_FLIP, MODE_REPLAY, MODE_HSTAMPER };

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static int mode = MODE_FORWARD, verbose = 0;
static unsigned long every = 100;
static unsigned long long prot_seen = 0, attacks = 0;
static uint8_t saved[FRAME_MAX];
static size_t  saved_len = 0;

// Handshake attack: flip one bit inside every handshake frame (0x88B5).
// In HELLO/REPLY this hits the DH public value: exactly what a MITM must replace
// to run its own Diffie-Hellman with each side.
static void tamper_handshake(uint8_t *f, size_t len) {
    if (mode != MODE_HSTAMPER || len < 14 + 4 + 64) return;
    if (f[12] != 0x88 || f[13] != 0xB5) return;
    f[14 + 4 + 32 + 10] ^= 0x01;   // after Ethernet header, 4-byte header and 32-byte nonce
    attacks++;
    printf("[MITM] tampered with handshake message type %u\n", f[17]);
}

static void left_to_right(int out_fd, uint8_t *f, size_t len) {
    tamper_handshake(f, len);

    // Find the protected data: TCP payload (in-place mode) or UDP payload (tunnel mode)
    size_t off = 0, plen = 0;
    int target = 0;
    if (mode == MODE_FLIP || mode == MODE_REPLAY) {
        struct pkt_info pi;
        if (pkt_parse_tcp(f, len, &pi) == 1 && pkt_is_protected(f, &pi)) {
            off = pi.pl_off; plen = pi.pl_len; target = 1;
        } else if (pkt_parse_udp(f, len, TUN_PORT, &off, &plen) && plen > 0) {
            target = 1;
        }
    }

    if (target) {
        prot_seen++;

        if (mode == MODE_FLIP && prot_seen % every == 0) {
            f[off + plen / 2] ^= 0x01;          // flip the lowest bit of a middle byte
            pkt_fix_checksums(f);               // hide the change from IP/TCP/UDP checksums
            attacks++;
            printf("[MITM] flipped 1 bit in protected packet #%llu\n", prot_seen);
        }

        if (mode == MODE_REPLAY) {
            if (saved_len == 0) {               // remember the first protected packet
                memcpy(saved, f, len);
                saved_len = len;
            } else if (prot_seen % every == 0) {
                raw_send(out_fd, saved, saved_len);
                attacks++;
                printf("[MITM] replayed the first protected packet (at #%llu)\n", prot_seen);
            }
        }
    }
    if (verbose) frame_print("L->R", f, len);
    raw_send(out_fd, f, len);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-v] [-m forward|flip|replay|hs-tamper] [-n N] <left_if> <right_if>\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "vm:n:")) != -1) {
        switch (opt) {
        case 'v': verbose = 1; break;
        case 'm':
            if      (strcmp(optarg, "forward") == 0) mode = MODE_FORWARD;
            else if (strcmp(optarg, "flip") == 0)    mode = MODE_FLIP;
            else if (strcmp(optarg, "replay") == 0)  mode = MODE_REPLAY;
            else if (strcmp(optarg, "hs-tamper") == 0) mode = MODE_HSTAMPER;
            else usage(argv[0]);
            break;
        case 'n': {
            char *end;
            every = strtoul(optarg, &end, 10);
            if (*end != '\0' || every == 0) usage(argv[0]);
            break;
        }
        default: usage(argv[0]);
        }
    }
    if (argc - optind != 2) usage(argv[0]);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int left  = raw_open(argv[optind]);
    int right = raw_open(argv[optind + 1]);
    if (left < 0 || right < 0) return 1;

    const char *names[] = { "forward", "flip", "replay", "hs-tamper" };
    printf("MITM running: %s <-> %s, mode %s", argv[optind], argv[optind + 1], names[mode]);
    if (mode == MODE_FLIP || mode == MODE_REPLAY) printf(" (every %lu protected packets)", every);
    printf(". Ctrl+C to stop.\n");

    struct pollfd pfd[2] = {
        { .fd = left,  .events = POLLIN },
        { .fd = right, .events = POLLIN },
    };
    uint8_t buf[FRAME_MAX];

    while (running) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }
        if (pfd[0].revents & POLLIN) {
            ssize_t n = raw_recv(left, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) left_to_right(right, buf, (size_t)n);
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t n = raw_recv(right, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) {
                tamper_handshake(buf, (size_t)n);
                if (verbose) frame_print("R->L", buf, (size_t)n);
                raw_send(left, buf, (size_t)n);
            }
        }
    }

    printf("\nStopped. protected packets seen: %llu, attacks performed: %llu\n", prot_seen, attacks);
    close(left);
    close(right);
    return 0;
}