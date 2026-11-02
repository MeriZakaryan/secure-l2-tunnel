CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_DEFAULT_SOURCE
BINS    = sender receiver

all: $(BINS)

sender: src/sender.c
	$(CC) $(CFLAGS) -o $@ $^

receiver: src/receiver.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(BINS)

.PHONY: all clean