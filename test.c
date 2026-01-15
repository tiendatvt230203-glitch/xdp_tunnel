// xdp_tx_simple.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/xsk.h>

#define IFNAME "enp5s0"
#define QUEUE  0

#define FRAMES   2048
#define FSIZE    XSK_UMEM__DEFAULT_FRAME_SIZE
#define PKT_SIZE 128

static void die(const char *m) { perror(m); exit(1); }

static unsigned short csum(void *buf, int n)
{
	unsigned int sum = 0;
	unsigned short *p = buf;
	while (n > 1) { sum += *p++; n -= 2; }
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

int main()
{
	/* memlock */
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);

	/* UMEM */
	void *buf;
	posix_memalign(&buf, getpagesize(), FRAMES * FSIZE);

	struct xsk_umem *umem;
	struct xsk_ring_prod fq, tx;
	struct xsk_ring_cons cq, rx;

	struct xsk_umem_config ucfg = {
		.fill_size = FRAMES,
		.comp_size = FRAMES,
		.frame_size = FSIZE,
	};

	if (xsk_umem__create(&umem, buf, FRAMES * FSIZE, &fq, &cq, &ucfg))
		die("umem");

	/* fill ring */
	__u32 idx;
	xsk_ring_prod__reserve(&fq, FRAMES, &idx);
	for (int i = 0; i < FRAMES; i++)
		*xsk_ring_prod__fill_addr(&fq, idx + i) = i * FSIZE;
	xsk_ring_prod__submit(&fq, FRAMES);

	/* XSK socket */
	struct xsk_socket *xsk;
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
	};

	int ret = xsk_socket__create_shared(&xsk, IFNAME, QUEUE,
					    umem, &rx, &tx, &fq, &cq, &cfg);
	if (ret) {
		errno = -ret;
		die("xsk_socket");
	}

	/* build packet in frame 0 */
	unsigned char *pkt = xsk_umem__get_data(buf, 0);

	struct ethhdr *eth = (struct ethhdr *)pkt;
	memcpy(eth->h_source, "\x24\x5e\xbe\x57\xf1\x64", 6); /* SRC MAC */
	memcpy(eth->h_dest,   "\xbc\xee\x7b\xda\xc2\x62", 6); /* DST MAC */
	eth->h_proto = htons(ETH_P_IP);

	struct iphdr *ip = (void *)(eth + 1);
	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = inet_addr("192.168.44.1");
	ip->daddr = inet_addr("192.168.44.3");

	struct udphdr *udp = (void *)(ip + 1);
	udp->source = htons(12345);
	udp->dest   = htons(9000);
	udp->len    = htons(PKT_SIZE - sizeof(*eth) - sizeof(*ip));

	memset((void *)(udp + 1), 0x41,
	       PKT_SIZE - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));

	ip->tot_len = htons(PKT_SIZE - sizeof(*eth));
	ip->check = csum(ip, sizeof(*ip));

	/* TX LOOP */
	while (1) {
		__u32 txi;
		if (xsk_ring_prod__reserve(&tx, 1, &txi) != 1)
			continue;

		struct xdp_desc *d = xsk_ring_prod__tx_desc(&tx, txi);
		d->addr = 0;
		d->len  = PKT_SIZE;

		xsk_ring_prod__submit(&tx, 1);
		sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		usleep(1000); /* ~1000 pps */
	}
}

