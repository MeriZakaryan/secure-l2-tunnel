// sender: runs on PC1. Connects to the receiver over TCP and sends a file.
// Usage: ./sender <dest_ip> <port> <file>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>      // htons, inet_pton
#include <netinet/in.h>     // sockaddr_in
#include <netinet/tcp.h>    // TCP_MAXSEG
#include <sys/socket.h>

#define BUF_SIZE 4096
#define TUNNEL_MSS 1360     // 1400 (PC MTU) - 20 (IP) - 20 (TCP)     

// send() may send fewer bytes than asked; loop until everything is sent
static int send_all(int fd, const unsigned char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;   // interrupted by a signal: retry
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <dest_ip> <port> <file>\n", argv[0]);
        return 1;
    }

    // ---- Parse and validate the port (never trust input) ----
    char *end;
    long port = strtol(argv[2], &end, 10);
    if (*end != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return 1;
    }

    FILE *f = fopen(argv[3], "rb");          // "rb" = read in binary mode
    if (!f) { perror("fopen"); return 1; }

    // ---- 1. Create a TCP socket ----
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); fclose(f); return 1; }

    // ---- 2. Limit segment size BEFORE connect (MSS is announced in the SYN) ----
    int mss = TUNNEL_MSS;
    if (setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
        perror("setsockopt TCP_MAXSEG (continuing)");

    // ---- 3. Fill in the destination address ----
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)port);  // host to network byte order (big-endian)
    if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", argv[1]);
        close(sock); fclose(f); return 1;
    }

    // ---- 4. Connect: the TCP 3-way handshake happens here ----
    if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("connect");
        close(sock); fclose(f); return 1;
    }
    printf("Connected to %s:%ld\n", argv[1], port);

    // ---- 5. Read the file in chunks and send each chunk ----
    unsigned char buf[BUF_SIZE];
    size_t n;
    unsigned long long total = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (send_all(sock, buf, n) < 0) {
            perror("send");
            close(sock); fclose(f); return 1;
        }
        total += n;
    }
    if (ferror(f)) {
        perror("fread");
        close(sock); fclose(f); return 1;
    }

    // ---- 6. Tell the receiver "no more data" (sends TCP FIN) ----
    shutdown(sock, SHUT_WR);

    // ---- 7. Wait until the receiver closes: guarantees it got everything ----
    char tmp;
    while (recv(sock, &tmp, 1, 0) > 0) { }

    printf("Sent %llu bytes\n", total);
    close(sock);
    fclose(f);
    return 0;
}