#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

//#define DEBUG
//#define RX_SOCKADDR

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
		" -i, --interface=DEVNAME    Only recv packets from DEVNAME\n"
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

#ifdef DEBUG
#ifdef RX_SOCKADDR
static void print_sockaddr_ll(struct sockaddr_ll *sa)
{
	printf("sll_family=%u\n", sa->sll_family);
	printf("sll_protocol=%u\n", sa->sll_protocol);
	printf("sll_ifindex=%d\n", sa->sll_ifindex);
	printf("sll_hatype=%u\n", sa->sll_hatype);
	printf("sll_pkttype=%u\n", sa->sll_pkttype);
	printf("sll_halen=%u\n", sa->sll_halen);
	printf("sll_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       sa->sll_addr[0],
	       sa->sll_addr[1],
	       sa->sll_addr[2],
	       sa->sll_addr[3],
	       sa->sll_addr[4],
	       sa->sll_addr[5]);
}
#endif

static void print_packet(char *p, ssize_t len)
{
	int i;
	printf("len=%ld\n", len);
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("        0x%04x: ", i);
		if (i % 2 == 0)
			printf(" ");
		printf("%02x", p[i]);
		if ((i+1) % 16 == 0)
			printf("\n");
	}
	if (!(i % 16 == 0))
		printf("\n");
}
#endif

static unsigned long time_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static unsigned long stats_rx_packets;

static void *stats_thread(void *arg)
{
	(void)arg;
	unsigned long prev_time_now = time_now();
	unsigned long prev_stats_rx_packets = 0;

	for (;;) {
		usleep(1000000);
		unsigned long now = time_now();
		unsigned long rx_packets = stats_rx_packets;

		unsigned long ns = now - prev_time_now;
		unsigned long packets = rx_packets - prev_stats_rx_packets;

		printf("%'-11.0f pps\n", packets * 1000000000. / ns);

		prev_time_now = now;
		prev_stats_rx_packets = rx_packets;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, stats_thread, NULL);
	pthread_attr_destroy(&attr);


	struct ifreq ifr;
	int psk;

	parse_argv(argc, argv);

	psk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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

	struct sockaddr_ll sa_ll;
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = opt_ifindex;
	if (bind(psk, (struct sockaddr *)&sa_ll, sizeof(struct sockaddr_ll)) == -1) {
		perror("bind");
		close(psk);
		exit(EXIT_FAILURE);
	}

	char buffer[1024];
#ifdef RX_SOCKADDR
	struct sockaddr sa;
	socklen_t sl;
#endif
	ssize_t len;

	for (;;) {
#ifdef RX_SOCKADDR
		if ((len = recvfrom(psk, buffer, 1024, 0, &sa, &sl)) == -1) {
#else
		if ((len = recvfrom(psk, buffer, 1024, 0, NULL, NULL)) == -1) {
#endif
			perror("recvfrom");
			close(psk);
			exit(EXIT_FAILURE);
		}
		stats_rx_packets++;
#ifdef DEBUG
#ifdef RX_SOCKADDR
		print_sockaddr_ll((struct sockaddr_ll *)&sa);
#endif
		print_packet(buffer, len);
#endif
	}

	close(psk);
	exit(EXIT_SUCCESS);
}
