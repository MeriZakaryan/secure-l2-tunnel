CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_DEFAULT_SOURCE
BINS    = sender receiver device mitm

all: $(BINS)

sender: src/sender.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

receiver: src/receiver.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

device: src/device.c src/netutil.c src/netutil.h
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

mitm: src/mitm.c src/netutil.c src/netutil.h
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

clean:
	rm -f $(BINS)

.PHONY: all clean