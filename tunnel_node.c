// tunnel_node.c - L2 tunnel with AF_XDP load balancing (no encryption)
// FIXED: queue mapping, MAC rewrite, replay disabled, TX lock
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/if_xdp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include "tunnel.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE 32

struct xsk_ctx {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx, fq;
    struct xsk_ring_cons cq;
    void *umem_area;
    uint32_t frames[NUM_FRAMES];
    uint32_t frame_cnt;
    int ifidx;
    char ifname[16];
    uint8_t local_mac[6];
    struct bpf_object *bpf_obj;
    int xdp_prog_fd;
    pthread_spinlock_t tx_lock;  // FIX: TX thread-safe
};

struct wan_ctx {
    struct xsk_ctx xsk;
    uint8_t peer_mac[6];
    uint64_t tx_seq;
};

static struct xsk_ctx lan_ctx;
static struct wan_ctx wan[MAX_WAN];
static int wan_cnt = 0;
static volatile int run = 1;

static void sig_handler(int s) { (void)s; run = 0; }

static uint64_t alloc_frame(struct xsk_ctx *ctx) {
    return ctx->frame_cnt ? ctx->frames[--ctx->frame_cnt] : UINT64_MAX;
}

static void free_frame(struct xsk_ctx *ctx, uint64_t f) {
    if (ctx->frame_cnt < NUM_FRAMES) ctx->frames[ctx->frame_cnt++] = f;
}

static void get_mac(const char *ifname, uint8_t *mac) {
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (f) {
        unsigned int m[6];
        if (fscanf(f, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6)
            for (int i = 0; i < 6; i++) mac[i] = m[i];
        fclose(f);
    }
}

// Set NIC to single queue (fix rx_queue_index issue)
static void set_single_queue(const char *ifname) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ethtool -L %s combined 1 2>/dev/null", ifname);
    (void)system(cmd);
}

static uint32_t flow_hash(const uint8_t *pkt, int len) {
    if (len < ETH_HLEN + 20) return 0;
    const struct iphdr *ip = (void*)(pkt + ETH_HLEN);
    uint32_t h = ip->saddr ^ ip->daddr ^ ip->protocol;
    int ihl = ip->ihl * 4;
    if (len >= ETH_HLEN + ihl + 4) {
        const uint16_t *p = (void*)(pkt + ETH_HLEN + ihl);
        h ^= (p[0] << 16) | p[1];
    }
    h ^= h >> 16;
    h *= 0x85ebca6b;
    return h;
}

static int load_xdp_program(struct xsk_ctx *ctx) {
    ctx->bpf_obj = bpf_object__open_file("tunnel.bpf.o", NULL);
    if (libbpf_get_error(ctx->bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return -1;
    }

    if (bpf_object__load(ctx->bpf_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(ctx->bpf_obj);
        ctx->bpf_obj = NULL;
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->bpf_obj, "xdp_sock_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(ctx->bpf_obj);
        ctx->bpf_obj = NULL;
        return -1;
    }

    ctx->xdp_prog_fd = bpf_program__fd(prog);

    // Try native mode first, fallback to SKB (use older API for compatibility)
    if (bpf_set_link_xdp_fd(ctx->ifidx, ctx->xdp_prog_fd, XDP_FLAGS_DRV_MODE) < 0) {
        if (bpf_set_link_xdp_fd(ctx->ifidx, ctx->xdp_prog_fd, XDP_FLAGS_SKB_MODE) < 0) {
            fprintf(stderr, "Failed to attach XDP to %s\n", ctx->ifname);
            bpf_object__close(ctx->bpf_obj);
            ctx->bpf_obj = NULL;
            return -1;
        }
        printf("  [%s] XDP attached (SKB mode)\n", ctx->ifname);
    } else {
        printf("  [%s] XDP attached (native mode)\n", ctx->ifname);
    }

    return 0;
}

static int xsk_setup(struct xsk_ctx *ctx, const char *ifname) {
    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->ifname, ifname, 15);
    ctx->ifidx = if_nametoindex(ifname);
    if (!ctx->ifidx) return -1;

    get_mac(ifname, ctx->local_mac);
    pthread_spin_init(&ctx->tx_lock, PTHREAD_PROCESS_PRIVATE);

    // FIX: Set single queue to match xsks_map key=0
    set_single_queue(ifname);

    if (load_xdp_program(ctx) < 0) return -1;

    struct bpf_map *map = bpf_object__find_map_by_name(ctx->bpf_obj, "xsks_map");
    int xsks_map_fd = map ? bpf_map__fd(map) : -1;

    size_t sz = NUM_FRAMES * FRAME_SIZE;
    ctx->umem_area = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ctx->umem_area == MAP_FAILED) return -1;

    struct xsk_umem_config ucfg = {
        .fill_size = 4096,
        .comp_size = 4096,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    if (xsk_umem__create(&ctx->umem, ctx->umem_area, sz, &ctx->fq, &ctx->cq, &ucfg)) {
        munmap(ctx->umem_area, sz);
        return -1;
    }

    for (uint32_t i = 0; i < NUM_FRAMES; i++) ctx->frames[i] = i * FRAME_SIZE;
    ctx->frame_cnt = NUM_FRAMES;

    struct xsk_socket_config xcfg = {
        .rx_size = 4096,
        .tx_size = 4096,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_USE_NEED_WAKEUP
    };

    int ret = xsk_socket__create(&ctx->xsk, ifname, 0, ctx->umem, &ctx->rx, &ctx->tx, &xcfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create(%s) failed: %d\n", ifname, ret);
        xsk_umem__delete(ctx->umem);
        munmap(ctx->umem_area, sz);
        return -1;
    }

    // FIX: Register XSK with key=0 (matching single queue)
    if (xsks_map_fd >= 0) {
        int fd = xsk_socket__fd(ctx->xsk);
        uint32_t key = 0;
        if (bpf_map_update_elem(xsks_map_fd, &key, &fd, 0) < 0) {
            fprintf(stderr, "Failed to update xsks_map\n");
        }
    }

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&ctx->fq, 4096, &idx) == 4096) {
        for (int i = 0; i < 4096; i++)
            *xsk_ring_prod__fill_addr(&ctx->fq, idx + i) = alloc_frame(ctx);
        xsk_ring_prod__submit(&ctx->fq, 4096);
    }

    printf("  [%s] XSK ready (MAC %02x:%02x:%02x:%02x:%02x:%02x)\n",
           ctx->ifname,
           ctx->local_mac[0], ctx->local_mac[1], ctx->local_mac[2],
           ctx->local_mac[3], ctx->local_mac[4], ctx->local_mac[5]);
    return 0;
}

static void xsk_cleanup(struct xsk_ctx *ctx) {
    if (ctx->xsk) xsk_socket__delete(ctx->xsk);
    if (ctx->umem) xsk_umem__delete(ctx->umem);
    if (ctx->umem_area) munmap(ctx->umem_area, NUM_FRAMES * FRAME_SIZE);

    if (ctx->ifidx) {
        bpf_set_link_xdp_fd(ctx->ifidx, -1, 0);
        printf("  [%s] XDP detached\n", ctx->ifname);
    }
    if (ctx->bpf_obj) bpf_object__close(ctx->bpf_obj);
    pthread_spin_destroy(&ctx->tx_lock);
}

// FIX: TX with spinlock for thread-safety
static void xsk_tx(struct xsk_ctx *ctx, const void *data, int len) {
    pthread_spin_lock(&ctx->tx_lock);

    uint32_t idx_cq;
    unsigned int comp = xsk_ring_cons__peek(&ctx->cq, 64, &idx_cq);
    if (comp) {
        for (unsigned int i = 0; i < comp; i++)
            free_frame(ctx, *xsk_ring_cons__comp_addr(&ctx->cq, idx_cq + i));
        xsk_ring_cons__release(&ctx->cq, comp);
    }

    uint32_t idx_tx;
    if (xsk_ring_prod__reserve(&ctx->tx, 1, &idx_tx) != 1) {
        pthread_spin_unlock(&ctx->tx_lock);
        return;
    }

    uint64_t addr = alloc_frame(ctx);
    if (addr == UINT64_MAX) {
        pthread_spin_unlock(&ctx->tx_lock);
        return;
    }

    memcpy(xsk_umem__get_data(ctx->umem_area, addr), data, len);
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&ctx->tx, idx_tx);
    d->addr = addr;
    d->len = len;
    xsk_ring_prod__submit(&ctx->tx, 1);

    if (xsk_ring_prod__needs_wakeup(&ctx->tx))
        sendto(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    pthread_spin_unlock(&ctx->tx_lock);
}

static void xsk_refill_fq(struct xsk_ctx *ctx, unsigned int n) {
    uint32_t fi = 0;
    unsigned int fr = xsk_prod_nb_free(&ctx->fq, n);
    if (fr && xsk_ring_prod__reserve(&ctx->fq, fr, &fi) == fr) {
        for (unsigned int i = 0; i < fr; i++)
            *xsk_ring_prod__fill_addr(&ctx->fq, fi + i) = alloc_frame(ctx);
        xsk_ring_prod__submit(&ctx->fq, fr);
    }
}

// LAN RX: receive IP -> encapsulate -> send to WAN
static void *lan_rx_loop(void *arg) {
    (void)arg;
    uint8_t out[4096];

    while (run) {
        uint32_t idx = 0;
        unsigned int n = xsk_ring_cons__peek(&lan_ctx.rx, BATCH_SIZE, &idx);
        if (!n) {
            struct pollfd pfd = {.fd = xsk_socket__fd(lan_ctx.xsk), .events = POLLIN};
            poll(&pfd, 1, 10);
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&lan_ctx.rx, idx + i)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&lan_ctx.rx, idx + i)->len;
            uint8_t *pkt = xsk_umem__get_data(lan_ctx.umem_area, addr);

            struct ethhdr *in_eth = (void*)pkt;
            if (ntohs(in_eth->h_proto) != ETH_P_IP) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            if (len > MAX_INNER_LEN || len < ETH_HLEN) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            uint32_t h = flow_hash(pkt, len);
            int path = h % wan_cnt;
            struct wan_ctx *w = &wan[path];

            // Build tunnel frame
            struct ethhdr *out_eth = (void*)out;
            memcpy(out_eth->h_dest, w->peer_mac, 6);
            memcpy(out_eth->h_source, w->xsk.local_mac, 6);
            out_eth->h_proto = htons(TUN_ETYPE);

            struct tun_hdr *hdr = (void*)(out + ETH_HLEN);
            hdr->ver = TUN_VERSION;
            hdr->flags = 0;
            hdr->key_id = 0;
            hdr->path_id = path;
            hdr->reserved = 0;
            hdr->inner_len = htons(len);
            hdr->seq = htobe64(__sync_add_and_fetch(&w->tx_seq, 1));

            memcpy(out + ETH_HLEN + TUN_HDR_SIZE, pkt, len);

            int total = ETH_HLEN + TUN_HDR_SIZE + len;
            xsk_tx(&w->xsk, out, total);
            free_frame(&lan_ctx, addr);
        }

        xsk_ring_cons__release(&lan_ctx.rx, n);
        xsk_refill_fq(&lan_ctx, n);
    }
    return NULL;
}

// WAN RX: receive tunnel -> decapsulate -> send to LAN
static void *wan_rx_loop(void *arg) {
    int path = (int)(intptr_t)arg;
    struct xsk_ctx *ctx = &wan[path].xsk;
    uint8_t out[4096];

    while (run) {
        uint32_t idx = 0;
        unsigned int n = xsk_ring_cons__peek(&ctx->rx, BATCH_SIZE, &idx);
        if (!n) {
            struct pollfd pfd = {.fd = xsk_socket__fd(ctx->xsk), .events = POLLIN};
            poll(&pfd, 1, 10);
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&ctx->rx, idx + i)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&ctx->rx, idx + i)->len;
            uint8_t *pkt = xsk_umem__get_data(ctx->umem_area, addr);

            struct ethhdr *eth = (void*)pkt;
            if (ntohs(eth->h_proto) != TUN_ETYPE) {
                free_frame(ctx, addr);
                continue;
            }

            if (len < ETH_HLEN + TUN_HDR_SIZE) {
                free_frame(ctx, addr);
                continue;
            }

            struct tun_hdr *hdr = (void*)(pkt + ETH_HLEN);
            if (hdr->ver != TUN_VERSION) {
                free_frame(ctx, addr);
                continue;
            }

            // FIX: Replay check DISABLED for multipath (reordering expected)
            // Will re-enable with sliding window when adding encryption

            uint16_t inner_len = ntohs(hdr->inner_len);
            if (len < ETH_HLEN + TUN_HDR_SIZE + inner_len || inner_len < ETH_HLEN) {
                free_frame(ctx, addr);
                continue;
            }

            // Get inner packet
            uint8_t *inner = pkt + ETH_HLEN + TUN_HDR_SIZE;

            // FIX: Rewrite MAC header before sending to LAN
            // Keep original dst MAC (client), rewrite src to LAN interface MAC
            memcpy(out, inner, inner_len);
            struct ethhdr *out_eth = (void*)out;
            // dst MAC stays as-is (original destination)
            // src MAC = LAN interface MAC (so switch learns correctly)
            memcpy(out_eth->h_source, lan_ctx.local_mac, 6);

            xsk_tx(&lan_ctx, out, inner_len);
            free_frame(ctx, addr);
        }

        xsk_ring_cons__release(&ctx->rx, n);
        xsk_refill_fq(ctx, n);
    }
    return NULL;
}

static void cleanup_all(void) {
    printf("Cleaning up...\n");
    xsk_cleanup(&lan_ctx);
    for (int i = 0; i < wan_cnt; i++)
        xsk_cleanup(&wan[i].xsk);
}

static int parse_wan_arg(const char *arg, char *ifname, uint8_t *peer_mac) {
    char buf[64];
    strncpy(buf, arg, 63);
    buf[63] = 0;
    char *at = strchr(buf, '@');
    if (!at) return -1;
    *at = 0;
    strncpy(ifname, buf, 15);
    ifname[15] = 0;
    unsigned int m[6];
    if (sscanf(at + 1, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) peer_mac[i] = m[i];
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <lan_if> <wan1@peer_mac1> [wan2@peer_mac2...]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *lan_if = argv[1];

    // Parse WAN
    for (int i = 2; i < argc && wan_cnt < MAX_WAN; i++) {
        if (!strchr(argv[i], '@')) continue;
        char ifname[16];
        uint8_t peer_mac[6];
        if (parse_wan_arg(argv[i], ifname, peer_mac) == 0) {
            int ifidx = if_nametoindex(ifname);
            if (ifidx) {
                wan[wan_cnt].xsk.ifidx = ifidx;
                strncpy(wan[wan_cnt].xsk.ifname, ifname, 15);
                memcpy(wan[wan_cnt].peer_mac, peer_mac, 6);
                wan_cnt++;
            }
        }
    }

    if (wan_cnt == 0) { fprintf(stderr, "No WAN\n"); return 1; }

    printf("Setting up LAN: %s\n", lan_if);
    strncpy(lan_ctx.ifname, lan_if, 15);
    lan_ctx.ifidx = if_nametoindex(lan_if);
    if (xsk_setup(&lan_ctx, lan_if) < 0) {
        fprintf(stderr, "LAN setup failed\n");
        return 1;
    }

    pthread_t wan_threads[MAX_WAN];
    int wan_ok = 0;

    for (int i = 0; i < wan_cnt; i++) {
        printf("Setting up WAN[%d]: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               i, wan[i].xsk.ifname,
               wan[i].peer_mac[0], wan[i].peer_mac[1], wan[i].peer_mac[2],
               wan[i].peer_mac[3], wan[i].peer_mac[4], wan[i].peer_mac[5]);

        if (xsk_setup(&wan[i].xsk, wan[i].xsk.ifname) < 0) {
            fprintf(stderr, "WAN[%d] setup failed\n", i);
            continue;
        }
        pthread_create(&wan_threads[i], NULL, wan_rx_loop, (void*)(intptr_t)i);
        wan_ok++;
    }

    if (wan_ok == 0) {
        fprintf(stderr, "No WAN interfaces ready\n");
        cleanup_all();
        return 1;
    }

    pthread_t lan_thread;
    pthread_create(&lan_thread, NULL, lan_rx_loop, NULL);

    printf("Tunnel running (NO ENCRYPTION, NO REPLAY CHECK). Ctrl+C to stop.\n");

    while (run) sleep(1);

    printf("\nShutting down...\n");
    run = 0;

    pthread_join(lan_thread, NULL);
    for (int i = 0; i < wan_cnt; i++)
        pthread_join(wan_threads[i], NULL);

    cleanup_all();
    printf("Done.\n");
    return 0;
}

