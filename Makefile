CC=gcc

CFLAGS=-O2 -g -std=c99 -Wall -Wextra -Werror -funsigned-char

all:
	$(CC) $(CFLAGS) -o psk-raw-tx-1 psk-raw-tx-1.c
	sudo setcap cap_net_raw=ep psk-raw-tx-1
