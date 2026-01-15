xdp_tx_3if.c (copy nguyên)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/xsk.h>

#define IF_COUNT 3
static const char *IFNAMES[IF_COUNT] = {"enp4s0", "enp5s0", "enp6s0"};

/* AF_XDP sizing */
#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH      64
#define FRAME_MASK (FRAME_SIZE - 1)

static void die(const char *m) { perror(m); exit(1); }

/* -------- checksum (IPv4 header only) -------- */
static uint16_t csum16(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)data;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* -------- timing -------- */
static uint64_t nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* -------- parse MAC "aa:bb:cc:dd:ee:ff" -------- */
static int parse_mac(const char *s, uint8_t mac[6]) {
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
    return 0;
}

struct xsk_if {
    const char *ifname;
    int ifindex;

    void *umem_buf;
    struct xsk_umem *umem;

    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx; /* unused but required by create_shared signature */

    struct xsk_socket *xsk;

    uint32_t free_top;
    uint64_t *free_addrs;

    uint32_t outstanding_tx;
};

static uint64_t alloc_frame(struct xsk_if *x) {
    if (x->free_top == 0) return UINT64_MAX;
    return x->free_addrs[--x->free_top];
}
static void free_frame(struct xsk_if *x, uint64_t addr) {
    addr &= ~(uint64_t)FRAME_MASK;
    x->free_addrs[x->free_top++] = addr;
}

/* Put all frames into fill ring (even if RX unused, keeps things stable across drivers) */
static void populate_fq(struct xsk_if *x, uint32_t n) {
    uint32_t idx;
    int r = xsk_ring_prod__reserve(&x->fq, n, &idx);
    if (r != (int)n) die("reserve fq");
    for (uint32_t i = 0; i < n; i++)
        *xsk_ring_prod__fill_addr(&x->fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&x->fq, n);
}

/* reap TX completions -> recycle frames */
static void complete_tx(struct xsk_if *x) {
    if (!x->outstanding_tx) return;

    /* kick */
    (void)sendto(xsk_socket__fd(x->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    uint32_t idx;
    unsigned int n = xsk_ring_cons__peek(&x->cq, BATCH, &idx);
    if (!n) return;

    for (unsigned int i = 0; i < n; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&x->cq, idx + i);
        free_frame(x, addr);
    }
    xsk_ring_cons__release(&x->cq, n);

    if (n > x->outstanding_tx) x->outstanding_tx = 0;
    else x->outstanding_tx -= n;
}

/* build: Ethernet + IPv4 + UDP + payload */
static uint32_t build_udp_pkt(uint8_t *pkt,
                              const uint8_t smac[6],
                              const uint8_t dmac[6],
                              uint32_t sip_be,
                              uint32_t dip_be,
                              uint16_t sport,
                              uint16_t dport,
                              const uint8_t *payload,
                              uint16_t payload_len)
{
    struct ethhdr *eth = (struct ethhdr *)pkt;
    memcpy(eth->h_source, smac, 6);
    memcpy(eth->h_dest,   dmac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    memset(ip, 0, sizeof(*ip));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = sip_be;
    ip->daddr = dip_be;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    memset(udp, 0, sizeof(*udp));
    udp->source = htons(sport);
    udp->dest   = htons(dport);

    uint8_t *pl = (uint8_t *)(udp + 1);
    memcpy(pl, payload, payload_len);

    uint16_t ip_len  = sizeof(*ip) + sizeof(*udp) + payload_len;
    ip->tot_len = htons(ip_len);

    uint16_t udp_len = sizeof(*udp) + payload_len;
    udp->len = htons(udp_len);
    udp->check = 0; /* IPv4 UDP checksum optional */

    ip->check = 0;
    ip->check = csum16(ip, sizeof(*ip));

    return sizeof(*eth) + ip_len;
}

static void setup_memlock(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit memlock");
}

static void xsk_setup_one(struct xsk_if *x) {
    x->ifindex = if_nametoindex(x->ifname);
    if (!x->ifindex) die("if_nametoindex");

    if (posix_memalign(&x->umem_buf, getpagesize(), (size_t)NUM_FRAMES * FRAME_SIZE))
        die("posix_memalign");

    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };

    int ret = xsk_umem__create(&x->umem, x->umem_buf,
                              (uint64_t)NUM_FRAMES * FRAME_SIZE,
                              &x->fq, &x->cq, &ucfg);
    if (ret) { errno = -ret; die("xsk_umem__create"); }

    x->free_addrs = calloc(NUM_FRAMES, sizeof(uint64_t));
    if (!x->free_addrs) die("calloc free_addrs");
    for (uint32_t i = 0; i < NUM_FRAMES; i++) x->free_addrs[i] = (uint64_t)i * FRAME_SIZE;
    x->free_top = NUM_FRAMES;

    populate_fq(x, NUM_FRAMES);

    struct xsk_socket_config xcfg;
    memset(&xcfg, 0, sizeof(xcfg));
    xcfg.rx_size      = 0; /* TX only */
    xcfg.tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xcfg.libbpf_flags = 0;
    xcfg.xdp_flags    = 0;
    xcfg.bind_flags   = XDP_COPY;

    ret = xsk_socket__create_shared(&x->xsk, x->ifname, 0, x->umem,
                                    &x->rx, &x->tx, &x->fq, &x->cq, &xcfg);
    if (ret) {
        /* im lặng với -524 */
        if (-ret == ENOTSUPP) exit(1);
        errno = -ret;
        die("xsk_socket__create_shared");
    }
}

/* send batch */
static void tx_burst(struct xsk_if *x,
                     const uint8_t smac[6],
                     const uint8_t dmac[6],
                     uint32_t sip_be, uint32_t dip_be,
                     uint16_t sport, uint16_t dport,
                     const uint8_t *payload, uint16_t payload_len)
{
    uint32_t idx;
    unsigned int n = BATCH;

    if (x->outstanding_tx > (XSK_RING_PROD__DEFAULT_NUM_DESCS / 2))
        complete_tx(x);

    int r = xsk_ring_prod__reserve(&x->tx, n, &idx);
    if (r <= 0) { complete_tx(x); return; }
    n = (unsigned int)r;

    for (unsigned int i = 0; i < n; i++) {
        uint64_t addr = alloc_frame(x);
        if (addr == UINT64_MAX) { n = i; break; }

        uint8_t *pkt = xsk_umem__get_data(x->umem_buf, addr);
        uint32_t len = build_udp_pkt(pkt, smac, dmac, sip_be, dip_be, sport, dport, payload, payload_len);

        struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx + i);
        d->addr = addr;
        d->len  = len;
        d->options = 0;

        x->outstanding_tx++;
    }

    xsk_ring_prod__submit(&x->tx, n);

    /* kick */
    (void)sendto(xsk_socket__fd(x->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage:\n"
        "  sudo %s --dst-mac aa:bb:cc:dd:ee:ff --src-mac aa:bb:cc:dd:ee:ff \\\n"
        "          --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --dport 9000 [--sport 12345] [--pps 1000] [--size 64]\n"
        "Controls while running: press 1/2/3 to select enp4s0/enp5s0/enp6s0, q to quit\n",
        p);
}

int main(int argc, char **argv)
{
    setup_memlock();

    uint8_t dmac[6] = {0}, smac[6] = {0};
    char src_ip_str[64] = {0}, dst_ip_str[64] = {0};
    uint16_t sport = 12345, dport = 9000;
    uint32_t pps = 1000;        /* default */
    uint16_t pkt_size = 128;    /* bytes total payload-ish; we’ll clamp */
    bool have = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dst-mac") && i + 1 < argc) { if (parse_mac(argv[++i], dmac)) return usage(argv[0]), 1; have=true; }
        else if (!strcmp(argv[i], "--src-mac") && i + 1 < argc) { if (parse_mac(argv[++i], smac)) return usage(argv[0]), 1; }
        else if (!strcmp(argv[i], "--src-ip") && i + 1 < argc) { strncpy(src_ip_str, argv[++i], sizeof(src_ip_str)-1); }
        else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc) { strncpy(dst_ip_str, argv[++i], sizeof(dst_ip_str)-1); }
        else if (!strcmp(argv[i], "--sport") && i + 1 < argc) { sport = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--dport") && i + 1 < argc) { dport = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--pps") && i + 1 < argc)   { pps = (uint32_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--size") && i + 1 < argc)  { pkt_size = (uint16_t)atoi(argv[++i]); }
        else { usage(argv[0]); return 1; }
    }

    if (!have || !src_ip_str[0] || !dst_ip_str[0]) { usage(argv[0]); return 1; }

    uint32_t sip_be, dip_be;
    if (inet_pton(AF_INET, src_ip_str, &sip_be) != 1) die("inet_pton src");
    if (inet_pton(AF_INET, dst_ip_str, &dip_be) != 1) die("inet_pton dst");

    if (pps == 0) pps = 1;
    if (pps > 200000) pps = 200000;     /* safety cap */
    if (pkt_size < 64) pkt_size = 64;
    if (pkt_size > 1400) pkt_size = 1400;

    uint16_t payload_len = (pkt_size > (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)))
        ? (uint16_t)(pkt_size - (sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)))
        : 8;

    uint8_t *payload = calloc(payload_len, 1);
    if (!payload) die("calloc payload");
    for (uint16_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)(i & 0xff);

    struct xsk_if ifs[IF_COUNT] = {0};
    for (int i = 0; i < IF_COUNT; i++) {
        ifs[i].ifname = IFNAMES[i];
        xsk_setup_one(&ifs[i]);
        fprintf(stderr, "Ready: %s\n", ifs[i].ifname);
    }

    int active = 0;
    fprintf(stderr, "Active=%s (press 1/2/3 to switch, q quit)\n", IFNAMES[active]);

    /* rate control */
    uint64_t interval_ns = 1000000000ull / (uint64_t)pps;
    uint64_t next_ns = nsec_now();

    struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };

    while (1) {
        /* handle keyboard */
        int pr = poll(&pfd, 1, 0);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            char c;
            if (read(STDIN_FILENO, &c, 1) == 1) {
                if (c == 'q') break;
                if (c == '1') { active = 0; fprintf(stderr, "Active=%s\n", IFNAMES[active]); }
                if (c == '2') { active = 1; fprintf(stderr, "Active=%s\n", IFNAMES[active]); }
                if (c == '3') { active = 2; fprintf(stderr, "Active=%s\n", IFNAMES[active]); }
            }
        }

        uint64_t now = nsec_now();
        if (now < next_ns) continue;

        /* send burst */
        tx_burst(&ifs[active], smac, dmac, sip_be, dip_be, sport, dport, payload, payload_len);

        next_ns += interval_ns;
        /* keep from drifting too far */
        if (now - next_ns > 100000000ull) next_ns = now + interval_ns;

        complete_tx(&ifs[active]);
    }

    return 0;
}

Build
gcc -O2 xdp_tx_3if.c -o xdp_tx_3if -lbpf -lelf -lpthread

Run (ví dụ)
sudo ./xdp_tx_3if \
  --src-mac 24:5e:be:57:f1:64 --dst-mac bc:ee:7b:da:c2:62 \
  --src-ip 192.168.44.1 --dst-ip 192.168.44.3 \
  --dport 9000 --sport 12345 --pps 1000 --size 128
