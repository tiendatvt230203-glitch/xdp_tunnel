// tunnel_xdp_lb.c - VXLAN Load Balancer with AF_XDP (kernel bypass)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define MAX_TUN 4
#define MAX_PKT 4096
#define SPLIT_TH 1500
#define TUN_ETYPE 0x88B5
#define MAGIC 0x53504C54
#define REASM_SLOTS 128

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE 64

struct hdr {
    uint32_t magic;
    uint16_t id;
    uint8_t part;
    uint8_t total;
} __attribute__((packed));

struct tun {
    char name[16];
    int fd;
    int ifidx;
    uint8_t peer[6];
    atomic_uint_fast64_t tx_bytes;
    atomic_uint_fast64_t tx_pkts;
};

// AF_XDP socket for LAN
struct xsk_info {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    void *umem_area;
    uint32_t umem_frame_free[NUM_FRAMES];
    uint32_t umem_frame_free_cnt;
};

static struct xsk_info *lan_xsk = NULL;
static int lan_ifidx = 0;
static char lan_ifname[16];

// For sending to LAN (decapsulated packets) - use AF_PACKET
static int lan_tx_fd = -1;

static struct tun tuns[MAX_TUN];
static int tun_cnt = 0;
static atomic_uint msg_id = 1;
static volatile int run = 1;

static struct bpf_object *bpf_obj = NULL;
static int xdp_prog_fd = -1;

struct reasm_slot {
    uint16_t id;
    uint8_t buf[2][MAX_PKT];
    int len[2];
};

static struct reasm_slot reasm[REASM_SLOTS];
static pthread_spinlock_t reasm_lock;

static void stop(int s) { (void)s; run = 0; }

static int get_ifidx(const char *n) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq i;
    memset(&i, 0, sizeof(i));
    strncpy(i.ifr_name, n, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &i) < 0) { close(s); return -1; }
    close(s);
    return i.ifr_ifindex;
}

static int rawsock(int ifidx) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll s;
    memset(&s, 0, sizeof(s));
    s.sll_family = AF_PACKET;
    s.sll_protocol = htons(ETH_P_ALL);
    s.sll_ifindex = ifidx;
    if (bind(fd, (void *)&s, sizeof(s)) < 0) { close(fd); return -1; }
    return fd;
}

static void send_raw(int fd, int ifidx, const uint8_t dst[6], const void *buf, int len) {
    struct sockaddr_ll s;
    memset(&s, 0, sizeof(s));
    s.sll_family = AF_PACKET;
    s.sll_ifindex = ifidx;
    s.sll_halen = 6;
    memcpy(s.sll_addr, dst, 6);
    sendto(fd, buf, len, 0, (void *)&s, sizeof(s));
}

// === AF_XDP Functions ===

static uint64_t xsk_alloc_umem_frame(struct xsk_info *xsk) {
    if (xsk->umem_frame_free_cnt == 0)
        return UINT64_MAX;
    return xsk->umem_frame_free[--xsk->umem_frame_free_cnt];
}

static void xsk_free_umem_frame(struct xsk_info *xsk, uint64_t frame) {
    xsk->umem_frame_free[xsk->umem_frame_free_cnt++] = frame;
}

static struct xsk_info *xsk_create(const char *ifname, int queue_id, int xsks_map_fd) {
    struct xsk_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;

    // Allocate UMEM
    size_t umem_size = NUM_FRAMES * FRAME_SIZE;
    xsk->umem_area = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (xsk->umem_area == MAP_FAILED) {
        // Fallback without hugepages
        xsk->umem_area = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (xsk->umem_area == MAP_FAILED) {
            free(xsk);
            return NULL;
        }
    }

    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };

    int ret = xsk_umem__create(&xsk->umem, xsk->umem_area, umem_size,
                                &xsk->fq, &xsk->cq, &umem_cfg);
    if (ret) {
        munmap(xsk->umem_area, umem_size);
        free(xsk);
        return NULL;
    }

    // Init frame allocator
    for (uint32_t i = 0; i < NUM_FRAMES; i++)
        xsk->umem_frame_free[i] = i * FRAME_SIZE;
    xsk->umem_frame_free_cnt = NUM_FRAMES;

    // Create XSK socket
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP
    };

    ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                              &xsk->rx, &xsk->tx, &xsk_cfg);
    if (ret) {
        // Fallback to SKB mode
        xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                                  &xsk->rx, &xsk->tx, &xsk_cfg);
        if (ret) {
            xsk_umem__delete(xsk->umem);
            munmap(xsk->umem_area, umem_size);
            free(xsk);
            return NULL;
        }
    }

    // Update xsks_map with this socket
    int fd = xsk_socket__fd(xsk->xsk);
    uint32_t key = queue_id;
    ret = bpf_map_update_elem(xsks_map_fd, &key, &fd, 0);
    if (ret) {
        fprintf(stderr, "Warning: failed to update xsks_map: %s\n", strerror(errno));
    }

    // Populate fill queue
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&xsk->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret == XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
            *xsk_ring_prod__fill_addr(&xsk->fq, idx++) = xsk_alloc_umem_frame(xsk);
        }
        xsk_ring_prod__submit(&xsk->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    }

    return xsk;
}

static void xsk_destroy(struct xsk_info *xsk) {
    if (!xsk) return;
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(xsk->umem);
    munmap(xsk->umem_area, NUM_FRAMES * FRAME_SIZE);
    free(xsk);
}

// === Load Balancer Logic ===

static atomic_uint rr_counter = 0;

static inline int pick_tunnel(const uint8_t *frame, int len) {
    (void)frame;
    (void)len;
    return atomic_fetch_add(&rr_counter, 1) % tun_cnt;
}

static void process_lan_packet(const uint8_t *frame, int len) {
    if (len < ETH_HLEN) return;

    int t = pick_tunnel(frame, len);

    uint8_t out[MAX_PKT + 64];
    struct ethhdr *e = (void *)out;
    struct hdr *h = (void *)(out + ETH_HLEN);

    memcpy(e->h_dest, tuns[t].peer, 6);
    memset(e->h_source, 0x02, 6);
    e->h_proto = htons(TUN_ETYPE);

    if (len <= SPLIT_TH) {
        h->magic = htonl(MAGIC);
        h->id = htons(atomic_fetch_add(&msg_id, 1));
        h->part = 0;
        h->total = 1;
        memcpy(out + ETH_HLEN + sizeof(*h), frame, len);

        int out_len = ETH_HLEN + sizeof(*h) + len;
        send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer, out, out_len);

        atomic_fetch_add(&tuns[t].tx_bytes, out_len);
        atomic_fetch_add(&tuns[t].tx_pkts, 1);
        return;
    }

    // Split packet > SPLIT_TH
    int half = len / 2;
    uint16_t id = atomic_fetch_add(&msg_id, 1);

    h->magic = htonl(MAGIC);
    h->id = htons(id);
    h->total = 2;

    h->part = 0;
    memcpy(out + ETH_HLEN + sizeof(*h), frame, half);
    int out_len = ETH_HLEN + sizeof(*h) + half;
    send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer, out, out_len);
    atomic_fetch_add(&tuns[t].tx_bytes, out_len);
    atomic_fetch_add(&tuns[t].tx_pkts, 1);

    h->part = 1;
    memcpy(out + ETH_HLEN + sizeof(*h), frame + half, len - half);
    out_len = ETH_HLEN + sizeof(*h) + (len - half);
    send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer, out, out_len);
    atomic_fetch_add(&tuns[t].tx_bytes, out_len);
    atomic_fetch_add(&tuns[t].tx_pkts, 1);
}

static void tun_rx(const uint8_t *pkt, int len, int tidx) {
    if (len < ETH_HLEN + (int)sizeof(struct hdr)) return;

    const struct ethhdr *e = (const void *)pkt;
    if (ntohs(e->h_proto) != TUN_ETYPE) return;

    const struct hdr *h = (const void *)(pkt + ETH_HLEN);
    if (ntohl(h->magic) != MAGIC) return;

    int total = h->total;
    int part = h->part;
    uint16_t id = ntohs(h->id);
    int plen = len - ETH_HLEN - sizeof(*h);
    const uint8_t *payload = pkt + ETH_HLEN + sizeof(*h);

    (void)tidx;
    if (plen < 6) return;

    if (total == 1) {
        const uint8_t *dst = payload;
        send_raw(lan_tx_fd, lan_ifidx, dst, payload, plen);
        return;
    }

    if (total != 2 || part > 1) return;

    int slot = id % REASM_SLOTS;

    pthread_spin_lock(&reasm_lock);
    struct reasm_slot *r = &reasm[slot];

    if (r->id != id) {
        r->id = id;
        r->len[0] = r->len[1] = 0;
    }

    if (plen <= MAX_PKT && r->len[part] == 0) {
        memcpy(r->buf[part], payload, plen);
        r->len[part] = plen;
    }

    if (r->len[0] && r->len[1]) {
        uint8_t out[MAX_PKT * 2];
        int outlen = r->len[0] + r->len[1];
        memcpy(out, r->buf[0], r->len[0]);
        memcpy(out + r->len[0], r->buf[1], r->len[1]);
        r->len[0] = r->len[1] = 0;
        pthread_spin_unlock(&reasm_lock);

        const uint8_t *dst = out;
        send_raw(lan_tx_fd, lan_ifidx, dst, out, outlen);
        return;
    }

    pthread_spin_unlock(&reasm_lock);
}

// === Threads ===

static void *lan_xdp_loop(void *x) {
    (void)x;
    struct xsk_info *xsk = lan_xsk;

    while (run) {
        // Check for received packets
        uint32_t idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);

        if (!rcvd) {
            // Need wakeup?
            if (xsk_ring_prod__needs_wakeup(&xsk->fq)) {
                struct pollfd pfd = { .fd = xsk_socket__fd(xsk->xsk), .events = POLLIN };
                poll(&pfd, 1, 100);
            }
            continue;
        }

        // Process received packets
        for (unsigned int i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
            idx_rx++;

            uint64_t orig_addr = xsk_umem__extract_addr(addr);
            uint8_t *pkt = xsk_umem__get_data(xsk->umem_area, addr);

            // Process packet through LB
            process_lan_packet(pkt, len);

            // Return frame to free list
            xsk_free_umem_frame(xsk, orig_addr);
        }

        xsk_ring_cons__release(&xsk->rx, rcvd);

        // Refill fill queue
        uint32_t idx_fq = 0;
        unsigned int stock = xsk_prod_nb_free(&xsk->fq, rcvd);
        if (stock > 0) {
            stock = xsk_ring_prod__reserve(&xsk->fq, stock, &idx_fq);
            for (unsigned int i = 0; i < stock; i++) {
                *xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) = xsk_alloc_umem_frame(xsk);
            }
            xsk_ring_prod__submit(&xsk->fq, stock);
        }
    }

    return NULL;
}

static void *tun_loop(void *x) {
    (void)x;
    struct pollfd p[MAX_TUN];
    uint8_t b[MAX_PKT];
    for (int i = 0; i < tun_cnt; i++) {
        p[i].fd = tuns[i].fd;
        p[i].events = POLLIN;
    }
    while (run) {
        if (poll(p, tun_cnt, 100) <= 0) continue;
        for (int i = 0; i < tun_cnt; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            ssize_t n = recv(tuns[i].fd, b, sizeof(b), 0);
            if (n <= 0) continue;
            // Don't filter source MAC 0x02 here - we need packets from remote LB
            tun_rx(b, (int)n, i);
        }
    }
    return NULL;
}

static void *stats_loop(void *x) {
    (void)x;
    uint64_t prev_bytes[MAX_TUN] = {0};

    while (run) {
        sleep(5);
        if (!run) break;

        printf("\n=== Bandwidth Stats (5s) ===\n");
        uint64_t total_rate = 0;

        for (int i = 0; i < tun_cnt; i++) {
            uint64_t bytes = atomic_load(&tuns[i].tx_bytes);
            uint64_t delta = bytes - prev_bytes[i];
            uint64_t mbps = (delta * 8) / (5 * 1000000);

            printf("  %s: %3lu Mbps (%lu MB total)\n",
                   tuns[i].name, mbps, bytes / (1024 * 1024));

            prev_bytes[i] = bytes;
            total_rate += mbps;
        }
        printf("  TOTAL: %lu Mbps\n", total_rate);
    }
    return NULL;
}

// === XDP Program Loading ===

static int load_xdp_program(const char *ifname) {
    char bpf_file[] = "tunnel.bpf.o";

    bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", bpf_file);
        return -1;
    }

    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(bpf_obj);
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "xdp_sock_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(bpf_obj);
        return -1;
    }

    xdp_prog_fd = bpf_program__fd(prog);

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get ifindex for %s\n", ifname);
        bpf_object__close(bpf_obj);
        return -1;
    }

    // Try native mode first, fallback to SKB
    if (bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        if (bpf_xdp_attach(ifindex, xdp_prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_object__close(bpf_obj);
            return -1;
        }
        printf("[XDP] Attached in SKB mode to %s\n", ifname);
    } else {
        printf("[XDP] Attached in native mode to %s\n", ifname);
    }

    return 0;
}

static void unload_xdp_program(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex) {
        bpf_xdp_detach(ifindex, 0, NULL);
        printf("[XDP] Detached from %s\n", ifname);
    }
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }
}

int main(int c, char **v) {
    if (c < 3) {
        printf("Usage: %s <lan_if> <tun1> [tun2...]\n", v[0]);
        printf("AF_XDP Load Balancer - kernel bypass, per-packet round-robin\n");
        return 1;
    }

    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    pthread_spin_init(&reasm_lock, PTHREAD_PROCESS_PRIVATE);

    strncpy(lan_ifname, v[1], sizeof(lan_ifname) - 1);
    lan_ifidx = get_ifidx(v[1]);
    if (lan_ifidx < 0) { printf("Bad lan if\n"); return 1; }

    // Load XDP program
    if (load_xdp_program(lan_ifname) < 0) {
        return 1;
    }

    // Get xsks_map fd
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    if (!map) {
        fprintf(stderr, "Failed to find xsks_map\n");
        unload_xdp_program(lan_ifname);
        return 1;
    }
    int xsks_map_fd = bpf_map__fd(map);

    // Create AF_XDP socket for LAN
    lan_xsk = xsk_create(lan_ifname, 0, xsks_map_fd);
    if (!lan_xsk) {
        fprintf(stderr, "Failed to create AF_XDP socket for LAN\n");
        unload_xdp_program(lan_ifname);
        return 1;
    }
    printf("[INIT] LAN=%s ifidx=%d (AF_XDP)\n", v[1], lan_ifidx);

    // AF_PACKET for sending to LAN (decapsulated packets)
    lan_tx_fd = rawsock(lan_ifidx);
    if (lan_tx_fd < 0) {
        fprintf(stderr, "Failed to create LAN TX socket\n");
        xsk_destroy(lan_xsk);
        unload_xdp_program(lan_ifname);
        return 1;
    }

    // Setup tunnel interfaces (AF_PACKET)
    for (int i = 2; i < c && tun_cnt < MAX_TUN; i++) {
        memset(&tuns[tun_cnt], 0, sizeof(tuns[tun_cnt]));
        strncpy(tuns[tun_cnt].name, v[i], 15);
        tuns[tun_cnt].ifidx = get_ifidx(v[i]);
        if (tuns[tun_cnt].ifidx < 0) { printf("Bad tun %s\n", v[i]); continue; }
        tuns[tun_cnt].fd = rawsock(tuns[tun_cnt].ifidx);
        if (tuns[tun_cnt].fd < 0) { printf("Tun rawsock fail %s\n", v[i]); continue; }
        memset(tuns[tun_cnt].peer, 0xff, 6);
        printf("[TUN] %s ifidx=%d (AF_PACKET)\n", tuns[tun_cnt].name, tuns[tun_cnt].ifidx);
        tun_cnt++;
    }

    if (!tun_cnt) {
        printf("No tunnels\n");
        xsk_destroy(lan_xsk);
        unload_xdp_program(lan_ifname);
        return 1;
    }

    pthread_t lan_th, tun_th, stats_th;
    pthread_create(&lan_th, 0, lan_xdp_loop, 0);
    pthread_create(&tun_th, 0, tun_loop, 0);
    pthread_create(&stats_th, 0, stats_loop, 0);

    printf("[RUN] AF_XDP LB - kernel bypass, %d tunnels\n", tun_cnt);
    printf("[INFO] Kernel will NOT forward packets - only this LB handles traffic\n");

    while (run) sleep(1);

    pthread_join(lan_th, 0);
    pthread_join(tun_th, 0);
    pthread_join(stats_th, 0);

    xsk_destroy(lan_xsk);
    close(lan_tx_fd);
    unload_xdp_program(lan_ifname);
    pthread_spin_destroy(&reasm_lock);

    printf("[EXIT] XDP program detached, kernel routing restored\n");

    return 0;
}
