#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const char *opt_if = "";
static int opt_ifindex;

static struct option longopts[] = {
	{"interface", required_argument, 0, 'i'},
	{0, 0, 0, 0}
};

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"Options:\n"
		" -i, --interface=DEVNAME\n"
		"\n",
		program);
	exit(EXIT_FAILURE);
}

static void parse_argv(int argc, char *argv[])
{
	int c, longindex;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:", longopts, &longindex);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opt_if = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	opt_ifindex = if_nametoindex(opt_if);
	if (opt_ifindex == 0) {
		perror("if_nametoindex");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	struct ifreq ifr;
	int psk;

	parse_argv(argc, argv);

	psk = socket(AF_PACKET, SOCK_RAW, 0);
	if (psk == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, opt_if, sizeof(ifr.ifr_name));

	if (ioctl(psk, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFHWADDR");
		close(psk);
		exit(EXIT_FAILURE);
	}

	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	int buffer_len = 0;

	struct ether_header *eh = (struct ether_header *)buffer;
	eh->ether_shost[0] = ifr.ifr_hwaddr.sa_data[0];
	eh->ether_shost[1] = ifr.ifr_hwaddr.sa_data[1];
	eh->ether_shost[2] = ifr.ifr_hwaddr.sa_data[2];
	eh->ether_shost[3] = ifr.ifr_hwaddr.sa_data[3];
	eh->ether_shost[4] = ifr.ifr_hwaddr.sa_data[4];
	eh->ether_shost[5] = ifr.ifr_hwaddr.sa_data[5];
	eh->ether_dhost[0] = 0x00;
	eh->ether_dhost[1] = 0x51;
	eh->ether_dhost[2] = 0x82;
	eh->ether_dhost[3] = 0x11;
	eh->ether_dhost[4] = 0x22;
	eh->ether_dhost[5] = 0x00;
	eh->ether_type = htons(ETH_P_IP);
	buffer_len += sizeof(struct ether_header);

	//struct iphdr *ih = (struct iphdr *)(buffer + sizeof(struct ether_header));
	buffer_len += sizeof(struct iphdr *);

	buffer[buffer_len++] = 0xaa;
	buffer[buffer_len++] = 0xaa;
	buffer[buffer_len++] = 0xaa;
	buffer[buffer_len++] = 0xaa;

	buffer_len = 64;

	struct sockaddr_ll sa;
	sa.sll_ifindex = opt_ifindex;
	sa.sll_halen = ETH_ALEN;
	sa.sll_addr[0] = 0x11;
	sa.sll_addr[1] = 0x12;
	sa.sll_addr[2] = 0x13;
	sa.sll_addr[3] = 0x14;
	sa.sll_addr[4] = 0x15;
	sa.sll_addr[5] = 0x16;

	if (sendto(psk, buffer, buffer_len, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0) {
		perror("sendto");
		close(psk);
		exit(EXIT_FAILURE);
	}

	close(psk);
	exit(EXIT_SUCCESS);
}
