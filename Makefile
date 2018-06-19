CC=gcc

CFLAGS=-O2 -g -std=c99 -Wall -Wextra -Werror -funsigned-char

all:
	$(CC) $(CFLAGS) -o psk-raw-tx-1 psk-raw-tx-1.c
	$(CC) $(CFLAGS) -o psk-raw-rx -pthread psk-raw-rx.c

clean:
	rm -rf psk-raw-tx-1
	rm -rf psk-raw-rx
