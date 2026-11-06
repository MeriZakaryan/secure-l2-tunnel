#ifndef NETUTIL_H
#define NETUTIL_H

#include <stddef.h>
#include <sys/types.h>

#define FRAME_MAX 2048   // larger than any frame we expect (1514 max with MTU 1500)

// Open a raw AF_PACKET socket bound to one interface, in promiscuous mode.
// Returns the socket fd, or -1 on error.
int raw_open(const char *ifname);

// Receive one frame.
// Returns: frame length (> 0), 0 = nothing usable (skip), -1 = fatal error.
ssize_t raw_recv(int fd, unsigned char *buf, size_t cap);

// Send one complete frame. Returns 0 on success, -1 on error.
int raw_send(int fd, const unsigned char *buf, size_t len);

// Print a one-line summary of a frame (MACs, IPs, ports, TCP flags, payload size).
void frame_print(const char *tag, const unsigned char *f, size_t len);

#endif