// tunnel_daemon.c - AF_XDP LB across VXLAN tunnels (FINAL)
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
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define MAX_TUN       4
#define NUM_FRAMES    4096
#define FRAME_SIZE    XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE    64
#define MAGIC         0x544E4C31
#define ETYPE         0x88B5
#define REASM_SLOTS   256
#define REASM_TIMEOUT 2  // seconds

struct hdr { uint32_t magic; uint16_t id; uint8_t part, total; } __attribute__((packed));
struct pool { uint64_t f[NUM_FRAMES]; uint32_t h, t; pthread_spinlock_t l; };

struct xsk {
    struct xsk_socket *sk;
    struct xsk_umem *umem;
    void *mem;
    struct xsk_ring_prod fq, tx;
    struct xsk_ring_cons cq, rx;
    struct xdp_program *prog;
    struct pool pool;
    int ifidx, qid;
    char name[16];
    int tx_pending;
};

// Reasm slot với timestamp
struct reasm_slot {
    uint16_t id;
    time_t ts;
    uint8_t b[2][2048];
    int l[2];
};

static struct xsk lan, tun[MAX_TUN];
static int tun_cnt;
static atomic_uint msg_id = 1;
static volatile int run = 1;
static struct reasm_slot reasm[REASM_SLOTS];

static void stop(int s) { (void)s; run = 0; }

// Pin thread to CPU core
static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

static void pool_init(struct pool *p) {
    pthread_spin_init(&p->l, 0);
    p->h = 0; p->t = NUM_FRAMES;
    for (uint32_t i = 0; i < NUM_FRAMES; i++) p->f[i] = i * FRAME_SIZE;
}

static uint64_t pool_get(struct pool *p) {
    uint64_t a = UINT64_MAX;
    pthread_spin_lock(&p->l);
    if (p->h != p->t) a = p->f[p->h++ % NUM_FRAMES];
    pthread_spin_unlock(&p->l);
    return a;
}

static void pool_put(struct pool *p, uint64_t a) {
    pthread_spin_lock(&p->l);
    p->f[p->t++ % NUM_FRAMES] = a;
    pthread_spin_unlock(&p->l);
}

static int setup_xsk(struct xsk *x, const char *name, int qid) {
    memset(x, 0, sizeof(*x));
    strncpy(x->name, name, 15);
    x->ifidx = if_nametoindex(name);
    x->qid = qid;
    if (!x->ifidx) return -1;

    size_t sz = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&x->mem, getpagesize(), sz)) return -1;

    struct xsk_umem_config uc = { NUM_FRAMES, NUM_FRAMES, FRAME_SIZE, 0, 0 };
    if (xsk_umem__create(&x->umem, x->mem, sz, &x->fq, &x->cq, &uc)) return -1;

    pool_init(&x->pool);

    struct xsk_socket_config sc = { NUM_FRAMES, NUM_FRAMES, XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, XDP_FLAGS_DRV_MODE, XDP_USE_NEED_WAKEUP };
    if (xsk_socket__create(&x->sk, name, qid, x->umem, &x->rx, &x->tx, &sc)) {
        sc.xdp_flags = XDP_FLAGS_SKB_MODE;
        if (xsk_socket__create(&x->sk, name, qid, x->umem, &x->rx, &x->tx, &sc)) return -1;
    }

    __u32 idx;
    int n = NUM_FRAMES / 2;
    if (xsk_ring_prod__reserve(&x->fq, n, &idx) != (unsigned)n) return -1;
    for (int i = 0; i < n; i++) *xsk_ring_prod__fill_addr(&x->fq, idx++) = pool_get(&x->pool);
    xsk_ring_prod__submit(&x->fq, n);

    x->prog = xdp_program__open_file("tunnel.bpf.o", "xdp", NULL);
    if (!x->prog) return -1;
    if (xdp_program__attach(x->prog, x->ifidx, XDP_MODE_NATIVE, 0))
        if (xdp_program__attach(x->prog, x->ifidx, XDP_MODE_SKB, 0)) return -1;

    struct bpf_map *m = bpf_object__find_map_by_name(xdp_program__bpf_obj(x->prog), "xsks_map");
    if (m) {
        int k = x->qid, v = xsk_socket__fd(x->sk);
        bpf_map_update_elem(bpf_map__fd(m), &k, &v, 0);
    }

    return 0;
}

static void complete_tx(struct xsk *x) {
    __u32 idx;
    unsigned n = xsk_ring_cons__peek(&x->cq, BATCH_SIZE, &idx);
    for (unsigned i = 0; i < n; i++) pool_put(&x->pool, *xsk_ring_cons__comp_addr(&x->cq, idx++));
    if (n) xsk_ring_cons__release(&x->cq, n);
}

static void tx_flush(struct xsk *x) {
    if (x->tx_pending && xsk_ring_prod__needs_wakeup(&x->tx))
        sendto(xsk_socket__fd(x->sk), 0, 0, MSG_DONTWAIT, 0, 0);
    x->tx_pending = 0;
}

static int tx_enqueue(struct xsk *x, void *p, int len) {
    uint64_t a = pool_get(&x->pool);
    if (a == UINT64_MAX) return -1;
    __u32 idx;
    if (xsk_ring_prod__reserve(&x->tx, 1, &idx) != 1) { pool_put(&x->pool, a); return -1; }
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx);
    d->addr = a; d->len = len;
    memcpy(x->mem + a, p, len);
    xsk_ring_prod__submit(&x->tx, 1);
    x->tx_pending++;
    // Upper bound: flush khi đạt BATCH_SIZE
    if (x->tx_pending >= BATCH_SIZE) tx_flush(x);
    return 0;
}

static void refill_fq(struct xsk *x, uint64_t *a, int n) {
    __u32 idx;
    if (xsk_ring_prod__reserve(&x->fq, n, &idx) == (unsigned)n) {
        for (int i = 0; i < n; i++) *xsk_ring_prod__fill_addr(&x->fq, idx++) = a[i];
        xsk_ring_prod__submit(&x->fq, n);
    } else for (int i = 0; i < n; i++) pool_put(&x->pool, a[i]);
}

static uint32_t jenkins_hash(const uint8_t *key, size_t len) {
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h += key[i];
        h += h << 10;
        h ^= h >> 6;
    }
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
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
        if (len >= ETH_HLEN + ip->ihl * 4 + 4) {
            memcpy(key + klen, p + ETH_HLEN + ip->ihl * 4, 4); klen += 4;
        }
    }
    return jenkins_hash(key, klen);
}

static void proc_lan(void *p, int len) {
    if (len < ETH_HLEN || !tun_cnt) return;
    int t = hash_pkt(p, len) % tun_cnt;
    uint8_t o[2048];
    struct ethhdr *e = (void*)o;
    struct hdr *h = (void*)(o + ETH_HLEN);
    memset(e->h_dest, 0xff, 6);
    memset(e->h_source, 0x02, 6);
    e->h_proto = htons(ETYPE);
    h->magic = htonl(MAGIC);
    h->id = htons(atomic_fetch_add(&msg_id, 1));
    h->part = 0; h->total = 1;
    memcpy(o + ETH_HLEN + sizeof(*h), p, len);
    tx_enqueue(&tun[t], o, ETH_HLEN + sizeof(*h) + len);
}

static void proc_tun(void *p, int len) {
    if (len < ETH_HLEN + (int)sizeof(struct hdr)) return;
    struct ethhdr *e = p;
    if (ntohs(e->h_proto) != ETYPE) return;
    struct hdr *h = p + ETH_HLEN;
    if (ntohl(h->magic) != MAGIC) return;
    int pl = len - ETH_HLEN - sizeof(*h);
    void *pay = p + ETH_HLEN + sizeof(*h);
    if (pl < ETH_HLEN) return;

    if (h->total == 1) { tx_enqueue(&lan, pay, pl); return; }
    if (h->total != 2 || h->part > 1) return;

    uint16_t id = ntohs(h->id);
    int s = id % REASM_SLOTS;
    time_t now = time(NULL);

    // Timeout: reset slot nếu quá cũ hoặc ID khác
    if (reasm[s].id != id || (now - reasm[s].ts) > REASM_TIMEOUT) {
        reasm[s].id = id;
        reasm[s].ts = now;
        reasm[s].l[0] = reasm[s].l[1] = 0;
    }

    if (pl <= 2048 && !reasm[s].l[h->part]) {
        memcpy(reasm[s].b[h->part], pay, pl);
        reasm[s].l[h->part] = pl;
    }

    if (reasm[s].l[0] && reasm[s].l[1]) {
        uint8_t o[4096];
        int ol = reasm[s].l[0] + reasm[s].l[1];
        if (ol >= ETH_HLEN) {
            memcpy(o, reasm[s].b[0], reasm[s].l[0]);
            memcpy(o + reasm[s].l[0], reasm[s].b[1], reasm[s].l[1]);
            tx_enqueue(&lan, o, ol);
        }
        reasm[s].l[0] = reasm[s].l[1] = 0;
    }
}

static void *rx_lan(void *arg) {
    int cpu = arg ? *(int*)arg : 0;
    pin_cpu(cpu);  // Pin to CPU 0

    struct pollfd pf = { xsk_socket__fd(lan.sk), POLLIN, 0 };
    uint64_t addrs[BATCH_SIZE];

    while (run) {
        poll(&pf, 1, 100);
        complete_tx(&lan);
        for (int i = 0; i < tun_cnt; i++) complete_tx(&tun[i]);

        __u32 idx;
        unsigned n = xsk_ring_cons__peek(&lan.rx, BATCH_SIZE, &idx);
        if (!n) continue;

        int cnt = 0;
        for (unsigned i = 0; i < n; i++) {
            struct xdp_desc *d = xsk_ring_cons__rx_desc(&lan.rx, idx++);
            void *p = lan.mem + d->addr;
            if (((struct ethhdr*)p)->h_source[0] != 0x02) proc_lan(p, d->len);
            addrs[cnt++] = d->addr;
        }
        xsk_ring_cons__release(&lan.rx, n);
        refill_fq(&lan, addrs, cnt);

        for (int i = 0; i < tun_cnt; i++) tx_flush(&tun[i]);
    }
    return NULL;
}

static void *rx_tun(void *arg) {
    int cpu = arg ? *(int*)arg : 1;
    pin_cpu(cpu);  // Pin to CPU 1

    struct pollfd pf[MAX_TUN];
    uint64_t addrs[BATCH_SIZE];
    for (int i = 0; i < tun_cnt; i++) { pf[i].fd = xsk_socket__fd(tun[i].sk); pf[i].events = POLLIN; }

    while (run) {
        poll(pf, tun_cnt, 100);
        complete_tx(&lan);

        for (int t = 0; t < tun_cnt; t++) {
            complete_tx(&tun[t]);
            __u32 idx;
            unsigned n = xsk_ring_cons__peek(&tun[t].rx, BATCH_SIZE, &idx);
            if (!n) continue;

            int cnt = 0;
            for (unsigned i = 0; i < n; i++) {
                struct xdp_desc *d = xsk_ring_cons__rx_desc(&tun[t].rx, idx++);
                void *p = tun[t].mem + d->addr;
                if (((struct ethhdr*)p)->h_source[0] != 0x02) proc_tun(p, d->len);
                addrs[cnt++] = d->addr;
            }
            xsk_ring_cons__release(&tun[t].rx, n);
            refill_fq(&tun[t], addrs, cnt);
        }
        tx_flush(&lan);
    }
    return NULL;
}

static void cleanup_xsk(struct xsk *x) {
    if (x->prog) {
        xdp_program__detach(x->prog, x->ifidx, XDP_MODE_NATIVE, 0);
        xdp_program__detach(x->prog, x->ifidx, XDP_MODE_SKB, 0);
        xdp_program__close(x->prog);
    }
    if (x->sk) xsk_socket__delete(x->sk);
    if (x->umem) xsk_umem__delete(x->umem);
    if (x->mem) free(x->mem);
}

int main(int c, char **v) {
    if (c < 3) { printf("Usage: %s <lan> <vxlan1> [vxlan2...]\n", v[0]); return 1; }
    signal(SIGINT, stop); signal(SIGTERM, stop);

    if (setup_xsk(&lan, v[1], 0)) { fprintf(stderr, "LAN fail\n"); return 1; }
    for (int i = 2; i < c && tun_cnt < MAX_TUN; i++)
        if (!setup_xsk(&tun[tun_cnt], v[i], 0)) tun_cnt++;

    if (!tun_cnt) { fprintf(stderr, "No tunnels\n"); return 1; }

    int cpu0 = 0, cpu1 = 1;
    pthread_t t1, t2;
    pthread_create(&t1, 0, rx_lan, &cpu0);
    pthread_create(&t2, 0, rx_tun, &cpu1);

    while (run) sleep(1);

    pthread_join(t1, 0);
    pthread_join(t2, 0);

    cleanup_xsk(&lan);
    for (int i = 0; i < tun_cnt; i++) cleanup_xsk(&tun[i]);
    return 0;
}
