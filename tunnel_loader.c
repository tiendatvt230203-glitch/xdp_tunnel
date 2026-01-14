#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES  2048
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define MAX_WAN     3

static volatile int running = 1;
static void sig(int s) { (void)s; running = 0; }

/* WAN config */
static int wan_fd[MAX_WAN];
static int wan_ifindex[MAX_WAN];
static int num_wan;

/* AF_XDP */
static struct xsk_socket *xsk;
static struct xsk_ring_cons rx;
static struct xsk_umem *umem;
static void *buf;

/* VERY SIMPLE LB STATE */
static int rr = 0;

/* chọn WAN (stub – sửa sau) */
static int select_wan(void) {
    int w = rr;
    rr = (rr + 1) % num_wan;
    return w;
}

int main(int argc, char **argv)
{
    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    /* hardcode test cho gọn */
    char *lan_if = "enp7s0";
    char *wan_if[] = {"enp4s0","enp5s0","enp6s0"};
    num_wan = 3;

    for (int i=0;i<num_wan;i++) {
        wan_ifindex[i] = if_nametoindex(wan_if[i]);
        wan_fd[i] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        struct sockaddr_ll s = {
            .sll_family = AF_PACKET,
            .sll_ifindex = wan_ifindex[i],
            .sll_protocol = htons(ETH_P_ALL),
        };
        bind(wan_fd[i], (void *)&s, sizeof(s));
    }

    /* AF_XDP init */
    posix_memalign(&buf, getpagesize(), NUM_FRAMES*FRAME_SIZE);
    struct xsk_umem_config uc = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
    };
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    xsk_umem__create(&umem, buf, NUM_FRAMES*FRAME_SIZE, &fq, &cq, &uc);

    struct xsk_socket_config xc = {
        .rx_size = NUM_FRAMES,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    };
    xsk_socket__create(&xsk, lan_if, 0, umem, &rx, NULL, &xc);

    printf("Running (bypass, no crypto)...\n");

    while (running) {
        uint32_t idx;
        uint32_t n = xsk_ring_cons__peek(&rx, 32, &idx);
        if (!n) { usleep(1000); continue; }

        for (uint32_t i=0;i<n;i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&rx, idx+i)->addr;
            uint32_t len  = xsk_ring_cons__rx_desc(&rx, idx+i)->len;
            uint8_t *pkt  = xsk_umem__get_data(buf, addr);

            /* ===== HOOK 1: encrypt_packet(pkt,len) ===== */

            int w = select_wan();

            /* ===== HOOK 2: set MAC / rewrite header ===== */

            struct sockaddr_ll s = {
                .sll_family  = AF_PACKET,
                .sll_ifindex = wan_ifindex[w],
            };
            sendto(wan_fd[w], pkt, len, 0, (void *)&s, sizeof(s));

            /* return frame */
            uint32_t f;
            xsk_ring_prod__reserve(&fq,1,&f);
            *xsk_ring_prod__fill_addr(&fq,f) = addr;
            xsk_ring_prod__submit(&fq,1);
        }
        xsk_ring_cons__release(&rx,n);
    }
    return 0;
}

