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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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
		" -i, --interface=DEVNAME\n"
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

static unsigned long time_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static unsigned long stats_tx_packets;

static void *stats_thread(void *arg)
{
	(void)arg;
	unsigned long prev_time_now = time_now();
	unsigned long prev_stats_tx_packets = 0;

	for (;;) {
		usleep(1000000);
		unsigned long now = time_now();
		unsigned long tx_packets = stats_tx_packets;

		unsigned long ns = now - prev_time_now;
		unsigned long packets = tx_packets - prev_stats_tx_packets;

		printf("%'-11.0f pps\n", packets * 1000000000. / ns);

		prev_time_now = now;
		prev_stats_tx_packets = tx_packets;
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
	psk = socket(AF_PACKET, SOCK_RAW, 0);
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
		// Register a TX ring
		ring = malloc(sizeof(*ring));
		unsigned int block_size = SZ_4M;
		unsigned int block_nr = 64;
		unsigned int frame_size = SZ_2K;
		memset(&ring->req, 0, sizeof(ring->req));
		ring->req.tp_block_size = block_size;
		ring->req.tp_block_nr = block_nr;
		ring->req.tp_frame_size = frame_size;
		ring->req.tp_frame_nr = (block_size * block_nr) / frame_size;
		if (setsockopt(psk, SOL_PACKET, PACKET_TX_RING, &ring->req, sizeof(ring->req)) == -1) {
			perror("PACKET_TX_RING");
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

	if (opt_tpacket_v3) {
		// Bind socket to interface
		struct sockaddr_ll sa_ll;
		sa_ll.sll_family = AF_PACKET;
		sa_ll.sll_protocol = 0;
		sa_ll.sll_ifindex = opt_ifindex;
		if (bind(psk, (struct sockaddr *)&sa_ll, sizeof(struct sockaddr_ll)) == -1) {
			perror("bind");
			close(psk);
			exit(EXIT_FAILURE);
		}
	}


	// Construct packet to send
	//----------------------------------------------------------------------
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
	//----------------------------------------------------------------------

	// TX
	if (opt_tpacket_v3) {
		for (;;) {
			unsigned i = 0;
			for (i = 0; i < ring->req.tp_frame_nr; i++) {
				struct tpacket3_hdr *frame =
					(struct tpacket3_hdr *)((uint8_t *)ring->rd[0].iov_base + (i * ring->req.tp_frame_size));
				frame->tp_snaplen = buffer_len;
				frame->tp_len = buffer_len;
				frame->tp_next_offset = 0;

				// Copy packet into frame
				memcpy((uint8_t *)frame + TPACKET3_HDRLEN - sizeof(struct sockaddr_ll),
				       buffer, buffer_len);

				frame->tp_status = TP_STATUS_SEND_REQUEST;

				__sync_synchronize();
			}
			if (sendto(psk, NULL, 0, 0, NULL, 0) == -1) {
				perror("sendto");
				close(psk);
				exit(EXIT_FAILURE);
			}
			stats_tx_packets += i;
		}
	} else {

		struct sockaddr_ll sa;
		sa.sll_ifindex = opt_ifindex;
		sa.sll_halen = ETH_ALEN;
		sa.sll_addr[0] = 0x11;
		sa.sll_addr[1] = 0x12;
		sa.sll_addr[2] = 0x13;
		sa.sll_addr[3] = 0x14;
		sa.sll_addr[4] = 0x15;
		sa.sll_addr[5] = 0x16;

		for (;;) {
			if (sendto(psk, buffer, buffer_len, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0) {
				perror("sendto");
				close(psk);
				exit(EXIT_FAILURE);
			}
			stats_tx_packets++;
		}
	}

	close(psk);
	exit(EXIT_SUCCESS);
}
