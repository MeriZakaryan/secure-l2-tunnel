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

enum { MODE_FORWARD, MODE_FLIP, MODE_REPLAY };

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static int mode = MODE_FORWARD, verbose = 0;
static unsigned long every = 100;
static unsigned long long prot_seen = 0, attacks = 0;
static uint8_t saved[FRAME_MAX];
static size_t  saved_len = 0;

static void left_to_right(int out_fd, uint8_t *f, size_t len) {
    struct pkt_info pi;
    if (mode != MODE_FORWARD && pkt_parse_tcp(f, len, &pi) == 1 && pkt_is_protected(f, &pi)) {
        prot_seen++;

        if (mode == MODE_FLIP && prot_seen % every == 0) {
            f[pi.pl_off + pi.pl_len / 2] ^= 0x01;   // flip the lowest bit of a middle byte
            pkt_fix_checksums(f);                    // hide the change from TCP/IP checksums
            attacks++;
            printf("[MITM] flipped 1 bit in protected packet #%llu\n", prot_seen);
        }

        if (mode == MODE_REPLAY) {
            if (saved_len == 0) {                    // remember the first protected packet
                memcpy(saved, f, len);
                saved_len = len;
            } else if (prot_seen % every == 0) {     // and inject it again later
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
    fprintf(stderr, "Usage: %s [-v] [-m forward|flip|replay] [-n N] <left_if> <right_if>\n", prog);
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

    const char *names[] = { "forward", "flip", "replay" };
    printf("MITM running: %s <-> %s, mode %s", argv[optind], argv[optind + 1], names[mode]);
    if (mode != MODE_FORWARD) printf(" (every %lu protected packets)", every);
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