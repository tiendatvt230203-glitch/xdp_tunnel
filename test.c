// gcc -O2 -Wall xdp_recv.c -o xdp_recv -lbpf -lxdp -lelf -lz
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_IFS 3
static const char *ifs[NUM_IFS] = {"enp4s0","enp5s0","enp6s0"};

#define FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH 64

static void parse(void *data, size_t len, const char *ifn)
{
    struct ethhdr *eth = data;
    if (len < sizeof(*eth)) return;

    printf("[%s] ETH %02x:%02x:%02x:%02x:%02x:%02x -> "
           "%02x:%02x:%02x:%02x:%02x:%02x\n",
        ifn,
        eth->h_source[0],eth->h_source[1],eth->h_source[2],
        eth->h_source[3],eth->h_source[4],eth->h_source[5],
        eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],
        eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);

    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    struct iphdr *ip = (void *)(eth + 1);
    struct in_addr s = {ip->saddr}, d = {ip->daddr};

    printf("[%s] IP %s -> %s proto=%u\n",
           ifn, inet_ntoa(s), inet_ntoa(d), ip->protocol);

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *u = (void *)((char*)ip + ip->ihl*4);
        printf("[%s] UDP %u -> %u\n",
               ifn, ntohs(u->source), ntohs(u->dest));
    }
    printf("----\n");
}

int main(void)
{
    /* === LẤY MAP FD ĐÃ CÓ TRONG KERNEL === */
    int xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        perror("bpf_obj_get xsks_map");
        return 1;
    }

    /* === UMEM === */
    void *buf = aligned_alloc(getpagesize(), FRAMES * FRAME_SIZE);

    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;

    struct xsk_umem_config ucfg = {
        .fill_size = 2048,
        .comp_size = 2048,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    if (xsk_umem__create(&umem, buf, FRAMES * FRAME_SIZE,
                         &fq, &cq, &ucfg)) {
        perror("xsk_umem__create");
        return 1;
    }

    __u32 idx;
    xsk_ring_prod__reserve(&fq, 2048, &idx);
    for (int i = 0; i < 2048; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, 2048);

    /* === SOCKETS === */
    struct xsk_socket *xsk[NUM_IFS];
    struct xsk_ring_cons rx[NUM_IFS];

    struct xsk_socket_config sc = {
        .rx_size = 2048,
        .tx_size = 0,
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    for (int i = 0; i < NUM_IFS; i++) {
        if (xsk_socket__create(&xsk[i], ifs[i], 0,
                               umem, &rx[i], NULL, &sc)) {
            perror("xsk_socket__create");
            return 1;
        }

        int fd = xsk_socket__fd(xsk[i]);
        __u32 key = 0;
        if (bpf_map_update_elem(xsks_map_fd, &key, &fd, 0)) {
            perror("bpf_map_update_elem");
            return 1;
        }

        printf("AF_XDP bound to %s\n", ifs[i]);
    }

    /* === RX LOOP === */
    struct pollfd pfd[NUM_IFS];

    while (1) {
        for (int i = 0; i < NUM_IFS; i++) {
            pfd[i].fd = xsk_socket__fd(xsk[i]);
            pfd[i].events = POLLIN;
        }

        poll(pfd, NUM_IFS, -1);

        for (int i = 0; i < NUM_IFS; i++) {
            if (!(pfd[i].revents & POLLIN)) continue;

            __u32 rx_idx;
            unsigned rcvd = xsk_ring_cons__peek(&rx[i], RX_BATCH, &rx_idx);
            if (!rcvd) continue;

            __u32 fq_idx;
            xsk_ring_prod__reserve(&fq, rcvd, &fq_idx);

            for (unsigned j = 0; j < rcvd; j++) {
                const struct xdp_desc *d =
                    xsk_ring_cons__rx_desc(&rx[i], rx_idx + j);

                void *pkt = xsk_umem__get_data(
                    buf, xsk_umem__add_offset_to_addr(d->addr));

                parse(pkt, d->len, ifs[i]);

                *xsk_ring_prod__fill_addr(&fq, fq_idx + j) =
                    xsk_umem__extract_addr(d->addr);
            }

            xsk_ring_prod__submit(&fq, rcvd);
            xsk_ring_cons__release(&rx[i], rcvd);
        }
    }
}

