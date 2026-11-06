// device: transparent inline device ("bump in the wire").
//   lan_if = interface towards the PC
//   wan_if = interface towards the MITM / the other device
// Commit 3: frames are forwarded unchanged in both directions (no crypto yet).
// Usage: ./device <lan_if> <wan_if> [-v]

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include "netutil.h"

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static int lan_fd = -1, wan_fd = -1, verbose = 0;
static unsigned long long cnt_out = 0, cnt_in = 0;

// PC -> network.  Commit 4: encrypt the TCP payload here.
static void handle_from_lan(unsigned char *f, size_t len) {
    if (verbose) frame_print("LAN->WAN", f, len);
    if (raw_send(wan_fd, f, len) == 0) cnt_out++;
}

// network -> PC.  Commit 4: verify the tag and decrypt here.
static void handle_from_wan(unsigned char *f, size_t len) {
    if (verbose) frame_print("WAN->LAN", f, len);
    if (raw_send(lan_fd, f, len) == 0) cnt_in++;
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "-v") != 0)) {
        fprintf(stderr, "Usage: %s <lan_if> <wan_if> [-v]\n", argv[0]);
        return 1;
    }
    verbose = (argc == 4);

    // Ctrl+C sets running = 0. No SA_RESTART, so poll() is interrupted (EINTR).
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    lan_fd = raw_open(argv[1]);
    wan_fd = raw_open(argv[2]);
    if (lan_fd < 0 || wan_fd < 0) return 1;

    printf("Device running: %s (LAN) <-> %s (WAN). Ctrl+C to stop.\n", argv[1], argv[2]);

    // Wait on both interfaces at once
    struct pollfd pfd[2] = {
        { .fd = lan_fd, .events = POLLIN },
        { .fd = wan_fd, .events = POLLIN },
    };
    unsigned char buf[FRAME_MAX];

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

    printf("\nStopped. LAN->WAN: %llu frames, WAN->LAN: %llu frames\n", cnt_out, cnt_in);
    close(lan_fd);
    close(wan_fd);
    return 0;
}