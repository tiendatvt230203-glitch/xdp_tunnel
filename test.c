#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/resource.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define MAX_IFS 3
#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH 64

static void die(const char *msg)
{
	perror(msg);
	exit(1);
}

struct iface {
	const char *ifname;
	int ifindex;

	struct bpf_object *obj;
	int xsks_map_fd;

	struct xsk_umem *umem;
	void *umem_buf;

	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;

	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
};

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <if1> <if2> <if3>\n", argv[0]);
		exit(1);
	}

	struct iface ifs[MAX_IFS];

	/* memlock */
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);

	/* open BPF once to get prog fd */
	struct bpf_object *base_obj =
		bpf_object__open_file("xdp_kern.o", NULL);
	if (!base_obj) die("open bpf");

	if (bpf_object__load(base_obj))
		die("load bpf");

	struct bpf_program *prog =
		bpf_object__find_program_by_name(base_obj, "xdp_sock_prog");
	int prog_fd = bpf_program__fd(prog);

	int xdp_attach_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

	/* setup per interface */
	for (int i = 0; i < MAX_IFS; i++) {
		ifs[i].ifname = argv[i + 1];
		ifs[i].ifindex = if_nametoindex(ifs[i].ifname);
		if (!ifs[i].ifindex)
			die("if_nametoindex");

		/* attach XDP */
		if (bpf_set_link_xdp_fd(ifs[i].ifindex,
					prog_fd,
					xdp_attach_flags) < 0)
			die("attach xdp");

		/* load BPF object again (map per IF) */
		ifs[i].obj = bpf_object__open_file("xdp_kern.o", NULL);
		if (!ifs[i].obj) die("open bpf per-if");

		if (bpf_object__load(ifs[i].obj))
			die("load bpf per-if");

		ifs[i].xsks_map_fd =
			bpf_object__find_map_fd_by_name(ifs[i].obj, "xsks_map");
		if (ifs[i].xsks_map_fd < 0)
			die("find xsks_map");

		/* UMEM */
		if (posix_memalign(&ifs[i].umem_buf,
				   getpagesize(),
				   NUM_FRAMES * FRAME_SIZE))
			die("posix_memalign");

		struct xsk_umem_config umem_cfg = {
			.fill_size = NUM_FRAMES,
			.comp_size = NUM_FRAMES,
			.frame_size = FRAME_SIZE,
			.frame_headroom = 0,
			.flags = 0,
		};

		if (xsk_umem__create(&ifs[i].umem,
				     ifs[i].umem_buf,
				     NUM_FRAMES * FRAME_SIZE,
				     &ifs[i].fq,
				     &ifs[i].cq,
				     &umem_cfg))
			die("xsk_umem__create");

		__u32 idx;
		xsk_ring_prod__reserve(&ifs[i].fq, NUM_FRAMES, &idx);
		for (int j = 0; j < NUM_FRAMES; j++)
			*xsk_ring_prod__fill_addr(&ifs[i].fq, idx + j) =
				j * FRAME_SIZE;
		xsk_ring_prod__submit(&ifs[i].fq, NUM_FRAMES);

		/* XSK socket */
		struct xsk_socket_config xsk_cfg;
		memset(&xsk_cfg, 0, sizeof(xsk_cfg));

		xsk_cfg.rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS;
		xsk_cfg.tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
		xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
		xsk_cfg.xdp_flags    = XDP_FLAGS_DRV_MODE;
		xsk_cfg.bind_flags   = XDP_COPY | XDP_USE_NEED_WAKEUP;

		if (xsk_socket__create_shared(&ifs[i].xsk,
					      ifs[i].ifname,
					      0,
					      ifs[i].umem,
					      &ifs[i].rx,
					      &ifs[i].tx,
					      &ifs[i].fq,
					      &ifs[i].cq,
					      &xsk_cfg))
			die("xsk_socket__create");

		int key = 0;
		int fd  = xsk_socket__fd(ifs[i].xsk);
		if (bpf_map_update_elem(ifs[i].xsks_map_fd,
					&key, &fd, 0))
			die("map update");
	}

	printf("AF_XDP attached to 3 interfaces\n");

	/* RX loop */
	while (1) {
		for (int i = 0; i < MAX_IFS; i++) {
			__u32 idx_rx = 0;
			unsigned int rcvd;

			rcvd = xsk_ring_cons__peek(&ifs[i].rx,
						   RX_BATCH,
						   &idx_rx);
			if (!rcvd)
				continue;

			for (int j = 0; j < rcvd; j++) {
				struct xdp_desc *d =
					xsk_ring_cons__rx_desc(&ifs[i].rx,
							       idx_rx + j);
				printf("[%s] RX len=%u\n",
				       ifs[i].ifname, d->len);

				*xsk_ring_prod__fill_addr(&ifs[i].fq, j) =
					d->addr & ~(FRAME_SIZE - 1);
			}

			xsk_ring_cons__release(&ifs[i].rx, rcvd);
			xsk_ring_prod__submit(&ifs[i].fq, rcvd);
		}
	}
}




CLANG ?= clang
CC    ?= gcc

all:
	$(CLANG) -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o
	$(CC) -O2 xdp_user.c -o xdp_user -lbpf -lelf -lpthread

clean:
	rm -f xdp_kern.o xdp_user

