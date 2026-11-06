CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_DEFAULT_SOURCE
LDLIBS  = -lcrypto
BINS    = sender receiver device mitm

all: $(BINS)

sender: src/sender.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

receiver: src/receiver.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

device: src/device.c src/netutil.c src/packet.c src/crypto.c src/handshake.c src/netutil.h src/packet.h src/crypto.h src/handshake.h
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

mitm: src/mitm.c src/netutil.c src/packet.c src/netutil.h src/packet.h src/crypto.h
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

clean:
	rm -f $(BINS)

.PHONY: all clean