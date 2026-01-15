// xdp_user_min.c
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define FRAMES 4096
#define FSIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH  64

#define DIE(x) do { perror(x); exit(1); } while (0)

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	const char *ifname = argv[1];
	if (!if_nametoindex(ifname)) DIE("if_nametoindex");

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);

	/* load bpf (only for xsks_map fd) */
	struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
	if (!obj || bpf_object__load(obj)) DIE("load bpf");

	int xsks_map =
		bpf_object__find_map_fd_by_name(obj, "xsks_map");
	if (xsks_map < 0) DIE("xsks_map");

	/* UMEM */
	void *buf;
	if (posix_memalign(&buf, getpagesize(), FRAMES * FSIZE)) DIE("memalign");

	struct xsk_umem *umem;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;

	struct xsk_umem_config ucfg = {
		.fill_size = FRAMES,
		.comp_size = FRAMES,
		.frame_size = FSIZE,
	};

	if (xsk_umem__create(&umem, buf, FRAMES * FSIZE, &fq, &cq, &ucfg))
		DIE("umem");

	__u32 i, idx;
	xsk_ring_prod__reserve(&fq, FRAMES, &idx);
	for (i = 0; i < FRAMES; i++)
		*xsk_ring_prod__fill_addr(&fq, idx + i) = i * FSIZE;
	xsk_ring_prod__submit(&fq, FRAMES);

	/* XSK */
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;

	struct xsk_socket_config xcfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.bind_flags = XDP_COPY,
	};

	int ret = xsk_socket__create_shared(&xsk, ifname, 0,
					    umem, &rx, &tx, &fq, &cq, &xcfg);
	if (ret) {
		if (-ret == ENOTSUPP) return 0; /* im lặng với -524 */
		errno = -ret;
		DIE("xsk_socket");
	}

	int fd = xsk_socket__fd(xsk), key = 0;
	if (bpf_map_update_elem(xsks_map, &key, &fd, 0))
		DIE("map_update");

	/* RX */
	while (1) {
		__u32 rx_idx = 0;
		unsigned int n = xsk_ring_cons__peek(&rx, BATCH, &rx_idx);
		if (!n) continue;

		for (i = 0; i < n; i++) {
			struct xdp_desc *d =
				xsk_ring_cons__rx_desc(&rx, rx_idx + i);
			printf("RX %u\n", d->len);
			*xsk_ring_prod__fill_addr(&fq, i) =
				d->addr & ~(FSIZE - 1);
		}

		xsk_ring_cons__release(&rx, n);
		xsk_ring_prod__submit(&fq, n);
	}
}

