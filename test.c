// xdp_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    __u32 qid = ctx->rx_queue_index;

    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


// xdp_user.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH   64

static void hexdump(void *data, int len)
{
    unsigned char *p = data;
    for (int i = 0; i < len; i++) {
        printf("%02x ", p[i]);
        if ((i & 15) == 15) printf("\n");
    }
    printf("\n\n");
}

int main(int argc, char **argv)
{
    const char *ifname = "eth0";
    int ifindex = if_nametoindex(ifname);
    void *umem_buf;
    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons rx;
    struct xsk_socket *xsk;
    int xsks_map_fd;
    uint32_t idx;

    /* UMEM */
    posix_memalign(&umem_buf, getpagesize(),
                   NUM_FRAMES * FRAME_SIZE);

    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };

    xsk_umem__create(&umem, umem_buf,
                     NUM_FRAMES * FRAME_SIZE,
                     &fq, NULL, &umem_cfg);

    /* Populate fill ring */
    xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx);
    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, NUM_FRAMES);

    /* XSK socket */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = 1024,
        .tx_size = 0,
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
        .bind_flags = XDP_COPY,
    };

    xsk_socket__create(&xsk, ifname, 0, umem,
                       &rx, NULL, &xsk_cfg);

    /* Load XDP & get xsks_map fd */
    struct bpf_object *obj;
    obj = bpf_object__open_file("xdp_kern.o", NULL);
    bpf_object__load(obj);
    bpf_object__attach_xdp(obj, ifindex);

    xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    int fd = xsk_socket__fd(xsk);
    int key = 0;
    bpf_map_update_elem(xsks_map_fd, &key, &fd, 0);

    printf("AF_XDP running on %s\n", ifname);

    /* RX loop */
    while (1) {
        unsigned int rcvd;
        uint32_t idx_rx = 0;

        rcvd = xsk_ring_cons__peek(&rx, RX_BATCH, &idx_rx);
        if (!rcvd)
            continue;

        for (int i = 0; i < rcvd; i++) {
            struct xdp_desc *d;
            void *pkt;

            d = xsk_ring_cons__rx_desc(&rx, idx_rx + i);
            pkt = xsk_umem__get_data(umem_buf, d->addr);

            printf("RX packet len=%u\n", d->len);
            hexdump(pkt, d->len);
        }

        xsk_ring_cons__release(&rx, rcvd);
    }
}


clang -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o
gcc xdp_user.c -o xdp_user \
    -lbpf -lelf -lpthread

