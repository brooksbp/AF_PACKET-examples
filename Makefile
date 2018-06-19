CC=gcc

CFLAGS=-O2 -g -std=c99 -Wall -Wextra -Werror -funsigned-char

all:
	$(CC) $(CFLAGS) -o psk-raw-tx psk-raw-tx.c
	$(CC) $(CFLAGS) -o psk-raw-rx -pthread psk-raw-rx.c

clean:
	rm -rf perf.data*
	rm -rf psk-raw-tx
	rm -rf psk-raw-rx
