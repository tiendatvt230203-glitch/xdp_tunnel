// xdp_user.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH   64

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *ifname = "eth0";
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) die("if_nametoindex");

	/* allow memlock */
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);

	/* ===== load + attach XDP ===== */
	struct bpf_object *obj;
	obj = bpf_object__open_file("xdp_kern.o", NULL);
	if (!obj) die("open bpf");

	if (bpf_object__load(obj))
		die("load bpf");

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "xdp_sock_prog");
	int prog_fd = bpf_program__fd(prog);

	int xdp_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0)
		die("attach xdp");

	int xsks_map_fd =
		bpf_object__find_map_fd_by_name(obj, "xsks_map");
	if (xsks_map_fd < 0)
		die("find xsks_map");

	/* ===== UMEM ===== */
	void *umem_buf;
	if (posix_memalign(&umem_buf, getpagesize(),
	                   NUM_FRAMES * FRAME_SIZE))
		die("posix_memalign");

	struct xsk_umem *umem;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;

	struct xsk_umem_config umem_cfg = {
		.fill_size = NUM_FRAMES,
		.comp_size = NUM_FRAMES,
		.frame_size = FRAME_SIZE,
		.frame_headroom = 0,
		.flags = 0,
	};

	if (xsk_umem__create(&umem, umem_buf,
	                     NUM_FRAMES * FRAME_SIZE,
	                     &fq, &cq, &umem_cfg))
		die("xsk_umem__create");

	/* fill ring */
	__u32 idx;
	xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx);
	for (int i = 0; i < NUM_FRAMES; i++)
		*xsk_ring_prod__fill_addr(&fq, idx + i) =
			i * FRAME_SIZE;
	xsk_ring_prod__submit(&fq, NUM_FRAMES);

	/* ===== XSK SOCKET ===== */
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;

	struct xsk_socket_config xsk_cfg;
	memset(&xsk_cfg, 0, sizeof(xsk_cfg));

	xsk_cfg.rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags    = xdp_flags;
	xsk_cfg.bind_flags   = XDP_COPY | XDP_USE_NEED_WAKEUP;

	if (xsk_socket__create_shared(&xsk,
	                              ifname,
	                              0,
	                              umem,
	                              &rx,
	                              &tx,
	                              &fq,
	                              &cq,
	                              &xsk_cfg))
		die("xsk_socket__create");

	/* put xsk fd into map */
	int key = 0;
	int fd  = xsk_socket__fd(xsk);
	if (bpf_map_update_elem(xsks_map_fd, &key, &fd, 0))
		die("map update");

	printf("AF_XDP running on %s\n", ifname);

	/* ===== RX LOOP ===== */
	while (1) {
		__u32 idx_rx = 0;
		unsigned int rcvd;

		rcvd = xsk_ring_cons__peek(&rx, RX_BATCH, &idx_rx);
		if (!rcvd)
			continue;

		for (int i = 0; i < rcvd; i++) {
			struct xdp_desc *d =
				xsk_ring_cons__rx_desc(&rx, idx_rx + i);
			void *pkt =
				xsk_umem__get_data(umem_buf, d->addr);

			printf("RX len=%u\n", d->len);

			/* return frame */
			*xsk_ring_prod__fill_addr(&fq, idx + i) =
				d->addr & ~(FRAME_SIZE - 1);
		}

		xsk_ring_cons__release(&rx, rcvd);
		xsk_ring_prod__submit(&fq, rcvd);
	}
}



CLANG ?= clang
CC    ?= gcc

all:
	$(CLANG) -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o
	$(CC) -O2 xdp_user.c -o xdp_user -lbpf -lelf -lpthread

clean:
	rm -f xdp_kern.o xdp_user

