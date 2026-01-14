#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 2048
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

static volatile int running = 1;
static void sig(int s){ (void)s; running = 0; }

int main()
{
    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    /* ===== CONFIG ===== */
    char *lan_if = "enp7s0";
    char *wan_if = "enp5s0";   // ÉP CỨNG WAN
    int wan_ifindex = if_nametoindex(wan_if);

    /* ===== RAW SOCKET WAN ===== */
    int wan_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll wan_addr = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = wan_ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    bind(wan_fd, (void*)&wan_addr, sizeof(wan_addr));

    /* ===== AF_XDP LAN ===== */
    void *buf;
    posix_memalign(&buf, getpagesize(), NUM_FRAMES * FRAME_SIZE);

    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons rx;

    struct xsk_umem_config uc = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
    };
    xsk_umem__create(&umem, buf, NUM_FRAMES*FRAME_SIZE, &fq, NULL, &uc);

    struct xsk_socket *xsk;
    struct xsk_socket_config xc = {
        .rx_size = NUM_FRAMES,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    };
    xsk_socket__create(&xsk, lan_if, 0, umem, &rx, NULL, &xc);

    /* fill ring */
    uint32_t idx;
    xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx);
    for (int i=0;i<NUM_FRAMES;i++)
        *xsk_ring_prod__fill_addr(&fq, idx+i) = i*FRAME_SIZE;
    xsk_ring_prod__submit(&fq, NUM_FRAMES);

    printf("RUNNING: LAN %s → WAN %s (FORCED)\n", lan_if, wan_if);

    /* ===== LOOP ===== */
    while (running) {
        uint32_t rcvd = xsk_ring_cons__peek(&rx, 32, &idx);
        if (!rcvd) { usleep(1000); continue; }

        for (uint32_t i=0;i<rcvd;i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&rx, idx+i)->addr;
            uint32_t len  = xsk_ring_cons__rx_desc(&rx, idx+i)->len;
            void *pkt = (char*)buf + addr;

            /* SEND THẲNG RA enp5s0 */
            sendto(wan_fd, pkt, len, 0,
                   (void*)&wan_addr, sizeof(wan_addr));

            /* trả frame */
            uint32_t f;
            xsk_ring_prod__reserve(&fq,1,&f);
            *xsk_ring_prod__fill_addr(&fq,f) = addr;
            xsk_ring_prod__submit(&fq,1);
        }
        xsk_ring_cons__release(&rx, rcvd);
    }

    return 0;
}

