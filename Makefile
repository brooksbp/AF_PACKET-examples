CC=gcc

CFLAGS=-O2 -g -std=c99 -Wall -Wextra -Werror -funsigned-char

all:
	$(CC) $(CFLAGS) -o rx-packet -pthread rx-packet.c
	$(CC) $(CFLAGS) -o tx-packet -pthread tx-packet.c

clean:
	rm -rf perf.data*
	rm -rf rx-packet
	rm -rf tx-packet
