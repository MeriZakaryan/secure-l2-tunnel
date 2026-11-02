// receiver: runs on PC2. Waits for one TCP connection and saves everything to a file.
// Usage: ./receiver <port> <output_file>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <output_file>\n", argv[0]);
        return 1;
    }

    char *end;
    long port = strtol(argv[1], &end, 10);
    if (*end != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[1]);
        return 1;
    }

    // ---- 1. Create a TCP socket ----
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    // Allow restarting immediately on the same port (avoids "Address already in use")
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    // ---- 2. Bind to all local addresses on the given port ----
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);       // 0.0.0.0 = any interface
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv); return 1;
    }

    // ---- 3. Listen and accept one client ----
    if (listen(srv, 1) < 0) { perror("listen"); close(srv); return 1; }
    printf("Listening on port %ld...\n", port);

    struct sockaddr_in cli;
    socklen_t cli_len = sizeof(cli);
    int c = accept(srv, (struct sockaddr *)&cli, &cli_len);   // blocks until a client connects
    if (c < 0) { perror("accept"); close(srv); return 1; }

    char cli_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli.sin_addr, cli_ip, sizeof(cli_ip));
    printf("Connection from %s:%u\n", cli_ip, ntohs(cli.sin_port));

    FILE *out = fopen(argv[2], "wb");
    if (!out) { perror("fopen"); close(c); close(srv); return 1; }

    // ---- 4. Receive until the sender closes (recv returns 0) ----
    unsigned char buf[BUF_SIZE];
    unsigned long long total = 0;
    for (;;) {
        ssize_t n = recv(c, buf, sizeof(buf), 0);
        if (n > 0) {
            if (fwrite(buf, 1, (size_t)n, out) != (size_t)n) {
                perror("fwrite"); break;
            }
            total += (unsigned long long)n;
        } else if (n == 0) {
            break;                              // sender finished (FIN received)
        } else {
            if (errno == EINTR) continue;
            perror("recv"); break;
        }
    }

    if (fclose(out) != 0) perror("fclose");
    close(c);                                   // our close lets the sender finish
    close(srv);
    printf("Received %llu bytes into %s\n", total, argv[2]);
    return 0;
}