// tunnel_lb.c - VXLAN Load Balancer (ECMP-style flow hash)
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define MAX_TUN 4
#define MAX_PKT 4096
#define SPLIT_TH 1500
#define TUN_ETYPE 0x88B5
#define MAGIC 0x53504C54
#define REASM_SLOTS 128

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
    atomic_uint_fast64_t tx_bytes;  // Stats only
    atomic_uint_fast64_t tx_pkts;
};

static int lan_fd = -1, lan_ifidx = 0;
static struct tun tuns[MAX_TUN];
static int tun_cnt = 0;
static atomic_uint msg_id = 1;
static volatile int run = 1;

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

// Per-packet round-robin counter
static atomic_uint rr_counter = 0;

// Round-robin per packet - mỗi packet đi tunnel khác nhau
static inline int pick_tunnel(const uint8_t *frame, int len) {
    (void)frame;
    (void)len;
    return atomic_fetch_add(&rr_counter, 1) % tun_cnt;
}

static void lan_rx(const uint8_t *frame, int len) {
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
        send_raw(lan_fd, lan_ifidx, dst, payload, plen);
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
        send_raw(lan_fd, lan_ifidx, dst, out, outlen);
        return;
    }

    pthread_spin_unlock(&reasm_lock);
}

static void *lan_loop(void *x) {
    (void)x;
    uint8_t b[MAX_PKT];
    while (run) {
        ssize_t n = recv(lan_fd, b, sizeof(b), 0);
        if (n <= 0) continue;
        if (n >= ETH_HLEN && ((struct ethhdr *)b)->h_source[0] == 0x02) continue;
        lan_rx(b, (int)n);
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
            if (n >= ETH_HLEN && ((struct ethhdr *)b)->h_source[0] == 0x02) continue;
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

int main(int c, char **v) {
    if (c < 3) {
        printf("Usage: %s <lan_if> <tun1> [tun2...]\n", v[0]);
        printf("Per-packet round-robin load balancer\n");
        return 1;
    }

    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    pthread_spin_init(&reasm_lock, PTHREAD_PROCESS_PRIVATE);

    lan_ifidx = get_ifidx(v[1]);
    if (lan_ifidx < 0) { printf("Bad lan if\n"); return 1; }
    lan_fd = rawsock(lan_ifidx);
    if (lan_fd < 0) { printf("LAN rawsock fail\n"); return 1; }
    printf("[INIT] LAN=%s ifidx=%d\n", v[1], lan_ifidx);

    for (int i = 2; i < c && tun_cnt < MAX_TUN; i++) {
        memset(&tuns[tun_cnt], 0, sizeof(tuns[tun_cnt]));
        strncpy(tuns[tun_cnt].name, v[i], 15);
        tuns[tun_cnt].ifidx = get_ifidx(v[i]);
        if (tuns[tun_cnt].ifidx < 0) { printf("Bad tun %s\n", v[i]); continue; }
        tuns[tun_cnt].fd = rawsock(tuns[tun_cnt].ifidx);
        if (tuns[tun_cnt].fd < 0) { printf("Tun rawsock fail %s\n", v[i]); continue; }
        memset(tuns[tun_cnt].peer, 0xff, 6);
        printf("[TUN] %s ifidx=%d\n", tuns[tun_cnt].name, tuns[tun_cnt].ifidx);
        tun_cnt++;
    }

    if (!tun_cnt) { printf("No tunnels\n"); return 1; }

    pthread_t lan_th, tun_th, stats_th;
    pthread_create(&lan_th, 0, lan_loop, 0);
    pthread_create(&tun_th, 0, tun_loop, 0);
    pthread_create(&stats_th, 0, stats_loop, 0);

    printf("[RUN] Per-packet round-robin LB across %d tunnels\n", tun_cnt);

    while (run) sleep(1);

    pthread_join(lan_th, 0);
    pthread_join(tun_th, 0);
    pthread_join(stats_th, 0);
    pthread_spin_destroy(&reasm_lock);

    return 0;
}
