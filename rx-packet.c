#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

//#define DEBUG
//#define RX_SOCKADDR

#define SZ_1      (1 <<  0)
#define SZ_2      (1 <<  1)
#define SZ_4      (1 <<  2)
#define SZ_8      (1 <<  3)
#define SZ_16     (1 <<  4)
#define SZ_32     (1 <<  5)
#define SZ_64     (1 <<  6)
#define SZ_128    (1 <<  7)
#define SZ_256    (1 <<  8)
#define SZ_512    (1 <<  9)

#define SZ_1K     (1 << 10)
#define SZ_2K     (1 << 11)
#define SZ_4K     (1 << 12)
#define SZ_8K     (1 << 13)
#define SZ_16K    (1 << 14)
#define SZ_32K    (1 << 15)
#define SZ_64K    (1 << 16)
#define SZ_128K   (1 << 17)
#define SZ_256K   (1 << 18)
#define SZ_512K   (1 << 19)

#define SZ_1M     (1 << 20)
#define SZ_2M     (1 << 21)
#define SZ_4M     (1 << 22)
#define SZ_8M     (1 << 23)
#define SZ_16M    (1 << 24)
#define SZ_32M    (1 << 25)
#define SZ_64M    (1 << 26)
#define SZ_128M   (1 << 27)
#define SZ_256M   (1 << 28)
#define SZ_512M   (1 << 29)

#define SZ_1G     (1 << 30)
#define SZ_2G     (1 << 31)

static const char *opt_if = "";
static int opt_ifindex;
static bool opt_tpacket_v3 = false;

static struct option longopts[] = {
	{"interface", required_argument, 0, 'i'},
	{"tpacketv3", no_argument, 0, '3'},
	{0, 0, 0, 0}
};

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"Options:\n"
		" -i, --interface=DEVNAME    Only recv packets from DEVNAME\n"
		" -3, --tpacketv3            Use PACKET_MMAP with TPACKET_V3\n"
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
		case '3':
			opt_tpacket_v3 = true;
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

// Why isn't this part of the uapi?
struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req3 req;
};
static struct ring *ring;

int main(int argc, char *argv[])
{
	parse_argv(argc, argv);

	// Create stats thread
	pthread_t thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, stats_thread, NULL);
	pthread_attr_destroy(&attr);

	// Create packet socket
	int psk;
	psk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (psk == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (opt_tpacket_v3) {
		// Set TPACKET version
		int v = TPACKET_V3;
		if (setsockopt(psk, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)) == -1) {
			perror("PACKET_VERSION");
			close(psk);
			exit(EXIT_FAILURE);
		}
		// Register an RX ring
		ring = malloc(sizeof(*ring));
		unsigned int block_size = SZ_4M;
		unsigned int block_nr = 64;
		unsigned int frame_size = SZ_2K;
		memset(&ring->req, 0, sizeof(ring->req));
		ring->req.tp_block_size = block_size;
		ring->req.tp_block_nr = block_nr;
		ring->req.tp_frame_size = frame_size;
		ring->req.tp_frame_nr = (block_size * block_nr) / frame_size;
		ring->req.tp_retire_blk_tov = 60;
		ring->req.tp_sizeof_priv = 0;
		ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
		if (setsockopt(psk, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req)) == -1) {
			perror("PACKET_RX_RING");
			close(psk);
			exit(EXIT_FAILURE);
		}
		// Map the ring into this process
		if ((ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED | MAP_LOCKED, psk, 0)) == MAP_FAILED) {
			perror("mmap");
			close(psk);
			exit(EXIT_FAILURE);
		}
		// Allocate an iovec per block which points to the block's starting address
		ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
		for (unsigned int i = 0; i < ring->req.tp_block_nr; i++) {
			ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
			ring->rd[i].iov_len = ring->req.tp_block_size;
		}
	}

	// Get interface's MAC address
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, opt_if, sizeof(ifr.ifr_name));
	if (ioctl(psk, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFHWADDR");
		close(psk);
		exit(EXIT_FAILURE);
	}

	// Bind socket to interface to receive packets only from that interface
	struct sockaddr_ll sa_ll;
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = opt_ifindex;
	if (bind(psk, (struct sockaddr *)&sa_ll, sizeof(struct sockaddr_ll)) == -1) {
		perror("bind");
		close(psk);
		exit(EXIT_FAILURE);
	}

	// RX
	if (opt_tpacket_v3) {
		struct pollfd pfd;
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = psk;
		pfd.events = POLLIN | POLLERR;
		pfd.revents = 0;

		unsigned int block_num = 0;
		for (;;) {
			struct block_desc *pbd;
			pbd = (struct block_desc *)ring->rd[block_num].iov_base;

			if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
				// Wait until kernel transfers ownership of this block to user.
				poll(&pfd, 1, -1);
				continue;
			}

			uint32_t num = pbd->h1.num_pkts;
			struct tpacket3_hdr *ppd;
			ppd = (struct tpacket3_hdr *)((uint8_t *)pbd + pbd->h1.offset_to_first_pkt);

			for (uint32_t i = 0; i < num; i++) {
				stats_rx_packets++;

				// Move to next packet
				ppd = (struct tpacket3_hdr *)((uint8_t *)ppd + ppd->tp_next_offset);
			}

			// Transfer ownership of block back to kernel.
			pbd->h1.block_status = TP_STATUS_KERNEL;

			// Move to next block
			block_num = (block_num + 1) % ring->req.tp_block_nr;
		}
	} else {
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
	}

	close(psk);
	exit(EXIT_SUCCESS);
}
