// tunnel_daemon.c - Multi-queue AF_XDP LB (OPTIMIZED 95%)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <time.h>
#include <dirent.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define MAX_TUN       4
#define MAX_QUEUES    16
#define NUM_FRAMES    4096
#define FRAME_SIZE    XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE    64
#define MAGIC         0x544E4C31
#define ETYPE         0x88B5
#define REASM_SLOTS   64
#define REASM_TICKS   200  // ~2s với poll 10ms

struct hdr { uint32_t magic; uint16_t id; uint8_t part, total; } __attribute__((packed));
struct pool { uint64_t f[NUM_FRAMES]; uint32_t h, t; };

struct xsk {
    struct xsk_socket *sk;
    struct xsk_umem *umem;
    void *mem;
    struct xsk_ring_prod fq, tx;
    struct xsk_ring_cons cq, rx;
    struct pool pool;
    int tx_pending;
};

struct iface {
    int ifidx;
    char name[16];
    int num_queues;
    struct xsk xsks[MAX_QUEUES];
    struct xdp_program *prog;
    int map_fd;
};

// Per-thread reasm slot (không race)
struct reasm_slot { uint16_t id; uint32_t tick; uint8_t b[2][2048]; int l[2]; };

static struct iface lan;
static struct iface tun[MAX_TUN];
static int tun_cnt;
static volatile int run = 1;

static void stop(int s) { (void)s; run = 0; }

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu % sysconf(_SC_NPROCESSORS_ONLN), &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static int get_num_queues(int ifidx) {
    char name[16], path[128];
    if (!if_indextoname(ifidx, name)) return 1;
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", name);
    DIR *dir = opendir(path);
    if (!dir) return 1;
    int cnt = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)))
        if (strncmp(ent->d_name, "rx-", 3) == 0) cnt++;
    closedir(dir);
    return cnt > 0 ? (cnt > MAX_QUEUES ? MAX_QUEUES : cnt) : 1;
}

// Lock-free pool (single-thread per pool)
static void pool_init(struct pool *p) {
    p->h = 0; p->t = NUM_FRAMES;
    for (uint32_t i = 0; i < NUM_FRAMES; i++) p->f[i] = i * FRAME_SIZE;
}

static uint64_t pool_get(struct pool *p) {
    if (p->h == p->t) return UINT64_MAX;
    return p->f[p->h++ % NUM_FRAMES];
}

static void pool_put(struct pool *p, uint64_t a) {
    p->f[p->t++ % NUM_FRAMES] = a;
}

static int setup_xsk_socket(struct xsk *x, const char *ifname, int qid) {
    memset(x, 0, sizeof(*x));
    size_t sz = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&x->mem, getpagesize(), sz)) return -1;

    struct xsk_umem_config uc = {
        .fill_size = NUM_FRAMES, .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };
    if (xsk_umem__create(&x->umem, x->mem, sz, &x->fq, &x->cq, &uc)) return -1;

    pool_init(&x->pool);

    struct xsk_socket_config sc = {
        .rx_size = NUM_FRAMES, .tx_size = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    };
    if (xsk_socket__create(&x->sk, ifname, qid, x->umem, &x->rx, &x->tx, &sc)) {
        sc.bind_flags = XDP_USE_NEED_WAKEUP;  // fallback no zerocopy
        sc.xdp_flags = XDP_FLAGS_DRV_MODE;
        if (xsk_socket__create(&x->sk, ifname, qid, x->umem, &x->rx, &x->tx, &sc)) {
            sc.xdp_flags = XDP_FLAGS_SKB_MODE;
            if (xsk_socket__create(&x->sk, ifname, qid, x->umem, &x->rx, &x->tx, &sc)) return -1;
        }
    }

    __u32 idx;
    int n = NUM_FRAMES / 2;
    if (xsk_ring_prod__reserve(&x->fq, n, &idx) != (unsigned)n) return -1;
    for (int i = 0; i < n; i++) *xsk_ring_prod__fill_addr(&x->fq, idx++) = pool_get(&x->pool);
    xsk_ring_prod__submit(&x->fq, n);

    return 0;
}

static int setup_iface(struct iface *ifc, int ifidx, int max_queues) {
    memset(ifc, 0, sizeof(*ifc));
    ifc->ifidx = ifidx;
    if (!if_indextoname(ifidx, ifc->name)) return -1;

    int detected = get_num_queues(ifidx);
    ifc->num_queues = (max_queues > 0 && max_queues < detected) ? max_queues : detected;

    ifc->prog = xdp_program__open_file("tunnel.bpf.o", "xdp", NULL);
    if (!ifc->prog) return -1;
    if (xdp_program__attach(ifc->prog, ifidx, XDP_MODE_NATIVE, 0))
        if (xdp_program__attach(ifc->prog, ifidx, XDP_MODE_SKB, 0)) return -1;

    struct bpf_map *m = bpf_object__find_map_by_name(xdp_program__bpf_obj(ifc->prog), "xsks_map");
    if (!m) return -1;
    ifc->map_fd = bpf_map__fd(m);

    for (int q = 0; q < ifc->num_queues; q++) {
        if (setup_xsk_socket(&ifc->xsks[q], ifc->name, q)) return -1;
        int key = q, val = xsk_socket__fd(ifc->xsks[q].sk);
        bpf_map_update_elem(ifc->map_fd, &key, &val, BPF_ANY);
    }
    return 0;
}

static void complete_tx(struct xsk *x) {
    __u32 idx;
    unsigned n = xsk_ring_cons__peek(&x->cq, BATCH_SIZE, &idx);
    for (unsigned i = 0; i < n; i++)
        pool_put(&x->pool, *xsk_ring_cons__comp_addr(&x->cq, idx++));
    if (n) xsk_ring_cons__release(&x->cq, n);
}

static void tx_flush(struct xsk *x) {
    if (x->tx_pending && xsk_ring_prod__needs_wakeup(&x->tx))
        sendto(xsk_socket__fd(x->sk), 0, 0, MSG_DONTWAIT, 0, 0);
    x->tx_pending = 0;
}

// Zero-copy TX: trả về pointer trực tiếp vào TX frame
static void *tx_alloc(struct xsk *x, uint64_t *addr_out) {
    uint64_t a = pool_get(&x->pool);
    if (a == UINT64_MAX) return NULL;
    *addr_out = a;
    return x->mem + a;
}

static int tx_submit(struct xsk *x, uint64_t addr, int len) {
    __u32 idx;
    if (xsk_ring_prod__reserve(&x->tx, 1, &idx) != 1) {
        pool_put(&x->pool, addr);
        return -1;
    }
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx);
    d->addr = addr;
    d->len = len;
    xsk_ring_prod__submit(&x->tx, 1);
    x->tx_pending++;
    if (x->tx_pending >= BATCH_SIZE) tx_flush(x);
    return 0;
}

static void refill_fq(struct xsk *x, uint64_t *a, int n) {
    __u32 idx;
    if (xsk_ring_prod__reserve(&x->fq, n, &idx) == (unsigned)n) {
        for (int i = 0; i < n; i++)
            *xsk_ring_prod__fill_addr(&x->fq, idx++) = a[i];
        xsk_ring_prod__submit(&x->fq, n);
    } else {
        for (int i = 0; i < n; i++) pool_put(&x->pool, a[i]);
    }
}

static uint32_t jenkins_hash(const uint8_t *key, size_t len) {
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) { h += key[i]; h += h << 10; h ^= h >> 6; }
    h += h << 3; h ^= h >> 11; h += h << 15;
    return h;
}

static uint32_t hash_pkt(void *p, int len) {
    struct ethhdr *e = p;
    uint8_t key[36];
    int klen = 0;
    memcpy(key, e->h_source, 6); klen += 6;
    memcpy(key + klen, e->h_dest, 6); klen += 6;
    if (ntohs(e->h_proto) == ETH_P_IP && len >= ETH_HLEN + 20) {
        struct iphdr *ip = p + ETH_HLEN;
        memcpy(key + klen, &ip->saddr, 4); klen += 4;
        memcpy(key + klen, &ip->daddr, 4); klen += 4;
        key[klen++] = ip->protocol;
        if (len >= ETH_HLEN + ip->ihl * 4 + 4)
            memcpy(key + klen, p + ETH_HLEN + ip->ihl * 4, 4), klen += 4;
    }
    return jenkins_hash(key, klen);
}

// Thread context
struct thread_ctx {
    struct iface *ifc;
    int qid;
    int cpu;
    int is_lan;
    int tunnel_id;    // -1 nếu LAN, 0..tun_cnt-1 nếu tunnel
    uint16_t msg_id;  // Per-thread msg_id
    uint32_t tick;    // Per-thread tick counter
    struct reasm_slot reasm[REASM_SLOTS];  // Per-thread reasm
};

// LAN -> VXLAN: Zero-copy, single-producer (src_qid based)
static void proc_lan(struct thread_ctx *ctx, void *p, int len) {
    if (len < ETH_HLEN || !tun_cnt) return;

    uint32_t h = hash_pkt(p, len);
    int t = h % tun_cnt;
    // Single-producer: map theo src_qid (chỉ race-free nếu tun_q >= lan_q)
    int q = ctx->qid % tun[t].num_queues;

    struct xsk *tx_xsk = &tun[t].xsks[q];

    // ✅ Reclaim CQ của đúng TX ring trước khi alloc
    complete_tx(tx_xsk);

    uint64_t addr;
    void *dst = tx_alloc(tx_xsk, &addr);
    if (!dst) return;

    // Build packet trực tiếp vào TX frame (zero-copy)
    struct ethhdr *e = dst;
    struct hdr *hdr = (void *)((uint8_t *)dst + ETH_HLEN);

    memset(e->h_dest, 0xff, 6);
    memset(e->h_source, 0x02, 6);
    e->h_proto = htons(ETYPE);

    hdr->magic = htonl(MAGIC);
    hdr->id = htons((ctx->qid << 12) | (ctx->msg_id++ & 0xFFF));
    hdr->part = 0;
    hdr->total = 1;

    memcpy((uint8_t *)dst + ETH_HLEN + sizeof(*hdr), p, len);
    tx_submit(tx_xsk, addr, ETH_HLEN + sizeof(*hdr) + len);

    // ✅ Flush đúng TX ring
    tx_flush(tx_xsk);
}

// VXLAN -> LAN: Zero-copy, single-producer, per-thread reasm
static void proc_tun(struct thread_ctx *ctx, void *p, int len) {
    if (len < ETH_HLEN + (int)sizeof(struct hdr)) return;

    struct ethhdr *e = p;
    if (ntohs(e->h_proto) != ETYPE) return;

    struct hdr *hdr = (void *)((uint8_t *)p + ETH_HLEN);
    if (ntohl(hdr->magic) != MAGIC) return;

    int pl = len - ETH_HLEN - sizeof(*hdr);
    void *pay = (uint8_t *)p + ETH_HLEN + sizeof(*hdr);
    if (pl < ETH_HLEN) return;

    // ✅ Tránh tun0.q0 và tun1.q0 cùng map về lan.q0
    int q = (ctx->tunnel_id * 997 + ctx->qid) % lan.num_queues;
    struct xsk *tx_xsk = &lan.xsks[q];

    // ✅ Reclaim CQ của đúng TX ring trước khi alloc
    complete_tx(tx_xsk);

    if (hdr->total == 1) {
        uint64_t addr;
        void *dst = tx_alloc(tx_xsk, &addr);
        if (!dst) return;
        memcpy(dst, pay, pl);
        tx_submit(tx_xsk, addr, pl);
        tx_flush(tx_xsk);
        return;
    }

    if (hdr->total != 2 || hdr->part > 1) return;

    uint16_t id = ntohs(hdr->id);
    int s = id % REASM_SLOTS;
    struct reasm_slot *rs = &ctx->reasm[s];

    // Timeout bằng tick (không dùng time())
    if (rs->id != id || (ctx->tick - rs->tick) > REASM_TICKS) {
        rs->id = id;
        rs->tick = ctx->tick;
        rs->l[0] = rs->l[1] = 0;
    }

    if (pl <= 2048 && !rs->l[hdr->part]) {
        memcpy(rs->b[hdr->part], pay, pl);
        rs->l[hdr->part] = pl;
    }

    if (rs->l[0] && rs->l[1]) {
        int ol = rs->l[0] + rs->l[1];
        if (ol >= ETH_HLEN) {
            uint64_t addr;
            void *dst = tx_alloc(tx_xsk, &addr);
            if (dst) {
                memcpy(dst, rs->b[0], rs->l[0]);
                memcpy((uint8_t *)dst + rs->l[0], rs->b[1], rs->l[1]);
                tx_submit(tx_xsk, addr, ol);
                tx_flush(tx_xsk);
            }
        }
        rs->l[0] = rs->l[1] = 0;
    }
}

static void *rx_thread(void *arg) {
    struct thread_ctx *ctx = arg;
    pin_cpu(ctx->cpu);

    struct xsk *x = &ctx->ifc->xsks[ctx->qid];
    struct pollfd pf = { xsk_socket__fd(x->sk), POLLIN, 0 };
    uint64_t addrs[BATCH_SIZE];

    while (run) {
        // Poll với timeout nhỏ (10ms) hoặc busy-poll
        int ret = poll(&pf, 1, 10);
        ctx->tick++;  // Tick counter cho reasm timeout

        // ✅ Không complete_tx(x) ở đây - proc_* đã gọi đúng TX ring

        __u32 idx;
        unsigned n = xsk_ring_cons__peek(&x->rx, BATCH_SIZE, &idx);

        // Busy-poll: nếu có data, tiếp tục không cần poll
        if (!n && ret <= 0) continue;

        int cnt = 0;
        for (unsigned i = 0; i < n; i++) {
            struct xdp_desc *d = xsk_ring_cons__rx_desc(&x->rx, idx++);
            void *pkt = x->mem + d->addr;

            if (((struct ethhdr*)pkt)->h_source[0] != 0x02) {
                if (ctx->is_lan) proc_lan(ctx, pkt, d->len);
                else proc_tun(ctx, pkt, d->len);
            }
            addrs[cnt++] = d->addr;
        }

        xsk_ring_cons__release(&x->rx, n);
        refill_fq(x, addrs, cnt);

        // ✅ Không flush ở đây - proc_* đã flush đúng TX ring
    }

    free(ctx);
    return NULL;
}

static void cleanup_xsk(struct xsk *x) {
    if (x->sk) xsk_socket__delete(x->sk);
    if (x->umem) xsk_umem__delete(x->umem);
    if (x->mem) free(x->mem);
}

static void cleanup_iface(struct iface *ifc) {
    if (ifc->prog) {
        xdp_program__detach(ifc->prog, ifc->ifidx, XDP_MODE_NATIVE, 0);
        xdp_program__detach(ifc->prog, ifc->ifidx, XDP_MODE_SKB, 0);
        xdp_program__close(ifc->prog);
    }
    for (int q = 0; q < ifc->num_queues; q++)
        cleanup_xsk(&ifc->xsks[q]);
}

int main(int c, char **v) {
    if (c < 3) {
        printf("Usage: %s <lan_idx>[:<queues>] <vxlan_idx>[:<queues>] ...\n", v[0]);
        printf("Example: %s 2:4 5:2 6:2\n", v[0]);
        return 1;
    }
    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    int lan_idx, lan_q = 0;
    if (sscanf(v[1], "%d:%d", &lan_idx, &lan_q) < 1) {
        fprintf(stderr, "Invalid LAN\n");
        return 1;
    }
    if (setup_iface(&lan, lan_idx, lan_q)) {
        fprintf(stderr, "LAN %d fail\n", lan_idx);
        return 1;
    }

    for (int i = 2; i < c && tun_cnt < MAX_TUN; i++) {
        int idx, q = 0;
        if (sscanf(v[i], "%d:%d", &idx, &q) < 1) continue;
        if (!setup_iface(&tun[tun_cnt], idx, q)) tun_cnt++;
    }

    if (!tun_cnt) {
        fprintf(stderr, "No tunnels\n");
        return 1;
    }

    int total = lan.num_queues;
    for (int t = 0; t < tun_cnt; t++) total += tun[t].num_queues;

    pthread_t *threads = malloc(total * sizeof(pthread_t));
    int tid = 0, cpu = 0;

    for (int q = 0; q < lan.num_queues; q++) {
        struct thread_ctx *ctx = calloc(1, sizeof(*ctx));
        ctx->ifc = &lan;
        ctx->qid = q;
        ctx->cpu = cpu++;
        ctx->is_lan = 1;
        ctx->tunnel_id = -1;  // LAN không có tunnel_id
        pthread_create(&threads[tid++], 0, rx_thread, ctx);
    }

    for (int t = 0; t < tun_cnt; t++) {
        for (int q = 0; q < tun[t].num_queues; q++) {
            struct thread_ctx *ctx = calloc(1, sizeof(*ctx));
            ctx->ifc = &tun[t];
            ctx->qid = q;
            ctx->cpu = cpu++;
            ctx->is_lan = 0;
            ctx->tunnel_id = t;  // ✅ Để tránh race khi map về LAN queue
            pthread_create(&threads[tid++], 0, rx_thread, ctx);
        }
    }

    while (run) sleep(1);

    for (int i = 0; i < total; i++) pthread_join(threads[i], 0);
    free(threads);

    cleanup_iface(&lan);
    for (int t = 0; t < tun_cnt; t++) cleanup_iface(&tun[t]);

    return 0;
}

