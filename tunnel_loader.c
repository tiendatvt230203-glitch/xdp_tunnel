#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 2048
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH      32

static volatile int running = 1;
static void sig(int s){ (void)s; running = 0; }

static void die(const char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

int main()
{
    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    /* ===== CONFIG ===== */
    const char *lan_if = "enp7s0";
    const char *wan_if = "enp5s0";   // ÉP CỨNG WAN
    int wan_ifindex = if_nametoindex(wan_if);
    if (wan_ifindex == 0) die("if_nametoindex(wan) failed");

    /* ===== RAW SOCKET WAN ===== */
    int wan_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (wan_fd < 0) die("socket(AF_PACKET) failed");

    struct sockaddr_ll wan_addr = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = wan_ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    if (bind(wan_fd, (void*)&wan_addr, sizeof(wan_addr)) < 0) die("bind(wan_fd) failed");

    /* ===== AF_XDP LAN ===== */
    void *buf = NULL;
    if (posix_memalign(&buf, getpagesize(), (size_t)NUM_FRAMES * FRAME_SIZE) != 0) {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }

    struct xsk_umem *umem = NULL;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;   /* phải có CQ */
    struct xsk_ring_cons rx;

    struct xsk_umem_config uc = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };
    if (xsk_umem__create(&umem, buf, (size_t)NUM_FRAMES * FRAME_SIZE, &fq, &cq, &uc) != 0) {
        fprintf(stderr, "xsk_umem__create failed\n");
        return 1;
    }

    struct xsk_socket *xsk = NULL;
    struct xsk_socket_config xc = {
        .rx_size = NUM_FRAMES,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = 0,
    };
    if (xsk_socket__create(&xsk, lan_if, 0, umem, &rx, NULL, &xc) != 0) {
        fprintf(stderr, "xsk_socket__create failed\n");
        return 1;
    }

    /* fill ring lần đầu */
    uint32_t idx;
    int reserved = xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx);
    if (reserved != NUM_FRAMES) {
        fprintf(stderr, "fq reserve failed: reserved=%d\n", reserved);
        return 1;
    }
    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = (uint64_t)i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, NUM_FRAMES);

    printf("RUNNING: LAN %s -> WAN %s (FORCED)\n", lan_if, wan_if);

    /* ===== LOOP ===== */
    while (running) {
        uint32_t rx_idx;
        uint32_t rcvd = xsk_ring_cons__peek(&rx, BATCH, &rx_idx);
        if (!rcvd) { usleep(1000); continue; }

        for (uint32_t i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&rx, rx_idx + i)->addr;
            uint32_t len  = xsk_ring_cons__rx_desc(&rx, rx_idx + i)->len;

            /* addr có thể chứa offset bits -> extract cho an toàn */
            uint64_t base = xsk_umem__extract_addr(addr);
            void *pkt = xsk_umem__get_data(buf, base);

            /* SEND THẲNG RA enp5s0 */
            (void)sendto(wan_fd, pkt, len, 0, (void*)&wan_addr, sizeof(wan_addr));

            /* trả frame: phải check reserve */
            uint32_t f;
            if (xsk_ring_prod__reserve(&fq, 1, &f) == 1) {
                *xsk_ring_prod__fill_addr(&fq, f) = base;
                xsk_ring_prod__submit(&fq, 1);
            }
        }

        xsk_ring_cons__release(&rx, rcvd);
    }

    return 0;
}

