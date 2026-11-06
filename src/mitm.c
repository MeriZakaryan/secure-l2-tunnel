// mitm: man-in-the-middle between Device1 and Device2.
// Commit 3: forwards frames unchanged (attack modes come in commit 4).
// Usage: ./mitm <left_if> <right_if> [-v]

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include "netutil.h"

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "-v") != 0)) {
        fprintf(stderr, "Usage: %s <left_if> <right_if> [-v]\n", argv[0]);
        return 1;
    }
    int verbose = (argc == 4);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int left  = raw_open(argv[1]);
    int right = raw_open(argv[2]);
    if (left < 0 || right < 0) return 1;

    printf("MITM running: %s <-> %s (forward mode). Ctrl+C to stop.\n", argv[1], argv[2]);

    struct pollfd pfd[2] = {
        { .fd = left,  .events = POLLIN },
        { .fd = right, .events = POLLIN },
    };
    unsigned char buf[FRAME_MAX];
    unsigned long long l2r = 0, r2l = 0;

    while (running) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }
        if (pfd[0].revents & POLLIN) {
            ssize_t n = raw_recv(left, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) {
                if (verbose) frame_print("L->R", buf, (size_t)n);
                if (raw_send(right, buf, (size_t)n) == 0) l2r++;
            }
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t n = raw_recv(right, buf, sizeof(buf));
            if (n < 0) break;
            if (n > 0) {
                if (verbose) frame_print("R->L", buf, (size_t)n);
                if (raw_send(left, buf, (size_t)n) == 0) r2l++;
            }
        }
    }

    printf("\nStopped. L->R: %llu frames, R->L: %llu frames\n", l2r, r2l);
    close(left);
    close(right);
    return 0;
}