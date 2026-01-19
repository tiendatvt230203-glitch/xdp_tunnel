// tunnel.c  (COPY NGUYEN FILE NAY)
// Run:
//  Server1: sudo ./tunnel 1
//  Server2: sudo ./tunnel 2
//
// Build:
//  clang -O2 -g -Wall -target bpf -c xdp_kern.c -o xdp_kern.o
//  clang -O2 -g -Wall tunnel.c -o tunnel -lbpf
//
// NOTE: attach XDP CHI tren LOCAL_IF (enp7s0). WAN_IF (enp5s0) chi TX (khong attach XDP).

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define LOCAL_IF "enp7s0"
#define WAN_IF   "enp5s0"

#define FRAMES   4096
#define FSIZE    XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH    64
#define TX_FRAMES 256

static volatile int running = 1;
static void on_sig(int s){ (void)s; running = 0; }
static void die(const char *m){ perror(m); exit(1); }

struct xsk_ctx {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *buf;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    __u32 tx_idx;
};

static struct xsk_ctx local_xsk; // RX from enp7s0 (XDP redirect)
static struct xsk_ctx wan_xsk;   // TX to enp5s0 (NO XDP attach)

/* ========= HARD-CODE MAC (role=1 server1, role=2 server2) ========= */
static unsigned char LOCAL_SRC_MAC[6];
static unsigned char CLIENT_MAC[6];
static unsigned char WAN_SRC_MAC[6];
static unsigned char WAN_PEER_MAC[6];

static void set_role(int role)
{
    if (role == 1) {
        // Server1
        unsigned char ls[6] = {0x20,0x7c,0x14,0xf8,0x0c,0xd2}; // enp7s0 server1
        unsigned char cm[6] = {0x20,0x7c,0x14,0xf8,0x0d,0x08}; // client1
        unsigned char ws[6] = {0x20,0x7c,0x14,0xf8,0x0c,0xd0}; // enp5s0 server1
        unsigned char wp[6] = {0x20,0x7c,0x14,0xf8,0x0d,0x4e}; // enp5s0 server2
        memcpy(LOCAL_SRC_MAC, ls, 6);
        memcpy(CLIENT_MAC,    cm, 6);
        memcpy(WAN_SRC_MAC,   ws, 6);
        memcpy(WAN_PEER_MAC,  wp, 6);
    } else {
        // Server2
        unsigned char ls[6] = {0x20,0x7c,0x14,0xf8,0x0d,0x50}; // enp7s0 server2
        unsigned char cm[6] = {0x20,0x7c,0x14,0xf8,0x0c,0xf6}; // client2
        unsigned char ws[6] = {0x20,0x7c,0x14,0xf8,0x0d,0x4e}; // enp5s0 server2
        unsigned char wp[6] = {0x20,0x7c,0x14,0xf8,0x0c,0xd0}; // enp5s0 server1
        memcpy(LOCAL_SRC_MAC, ls, 6);
        memcpy(CLIENT_MAC,    cm, 6);
        memcpy(WAN_SRC_MAC,   ws, 6);
        memcpy(WAN_PEER_MAC,  wp, 6);
    }
}

static int attach_xdp_local(int prog_fd)
{
    int ifidx = if_nametoindex(LOCAL_IF);
    if (!ifidx) return -1;

    // detach any existing XDP first (avoid native/generic conflict)
    bpf_set_link_xdp_fd(ifidx, -1, XDP_FLAGS_SKB_MODE);
    bpf_set_link_xdp_fd(ifidx, -1, XDP_FLAGS_DRV_MODE);
    bpf_set_link_xdp_fd(ifidx, -1, 0);

    return bpf_set_link_xdp_fd(ifidx, prog_fd, XDP_FLAGS_SKB_MODE);
}

static int setup_umem_and_socket(struct xsk_ctx *x, const char *ifname, int want_rx)
{
    memset(x, 0, sizeof(*x));

    if (posix_memalign(&x->buf, getpagesize(), FRAMES * FSIZE)) return -1;

    struct xsk_umem_config ucfg = {
        .fill_size = FRAMES,
        .comp_size = FRAMES,
        .frame_size = FSIZE,
        .frame_headroom = 0,
        .flags = 0
    };
    if (xsk_umem__create(&x->umem, x->buf, FRAMES * FSIZE, &x->fq, &x->cq, &ucfg)) return -1;

    // Fill ring only if we will RX on this socket
    if (want_rx) {
        __u32 idx;
        __u32 rx_frames = FRAMES - TX_FRAMES; // keep 0..TX_FRAMES-1 for TX reuse
        if (xsk_ring_prod__reserve(&x->fq, rx_frames, &idx) != rx_frames) return -1;
        for (__u32 i = 0; i < rx_frames; i++)
            *xsk_ring_prod__fill_addr(&x->fq, idx + i) = (__u64)(TX_FRAMES + i) * FSIZE;
        xsk_ring_prod__submit(&x->fq, rx_frames);
    }

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP
    };

    int ret = xsk_socket__create(&x->xsk, ifname, 0, x->umem, &x->rx, &x->tx, &cfg);
    if (ret) return ret;

    x->tx_idx = 0;
    return 0;
}

static inline void rewrite_eth(unsigned char *pkt, const unsigned char smac[6], const unsigned char dmac[6])
{
    struct ethhdr *eth = (struct ethhdr *)pkt;
    memcpy(eth->h_source, smac, 6);
    memcpy(eth->h_dest,   dmac, 6);
}

static inline void kick_tx(struct xsk_ctx *x)
{
    if (xsk_ring_prod__needs_wakeup(&x->tx))
        sendto(xsk_socket__fd(x->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static int tx_copy(struct xsk_ctx *dst, const void *pkt, __u32 len)
{
    // drain completion
    __u32 cq_idx;
    unsigned int done = xsk_ring_cons__peek(&dst->cq, TX_FRAMES, &cq_idx);
    if (done) xsk_ring_cons__release(&dst->cq, done);

    __u32 txi;
    if (xsk_ring_prod__reserve(&dst->tx, 1, &txi) != 1) return -1;

    __u64 addr = (__u64)(dst->tx_idx++ % TX_FRAMES) * FSIZE;
    memcpy(xsk_umem__get_data(dst->buf, addr), pkt, len);

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&dst->tx, txi);
    d->addr = addr;
    d->len  = len;

    xsk_ring_prod__submit(&dst->tx, 1);
    kick_tx(dst);
    return 0;
}

static void local_to_wan(void)
{
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&local_xsk.rx, BATCH, &rx_idx);
    if (!n) return;

    for (unsigned int i = 0; i < n; i++) {
        struct xdp_desc *rd = (struct xdp_desc *)xsk_ring_cons__rx_desc(&local_xsk.rx, rx_idx + i);
        unsigned char *pkt = xsk_umem__get_data(local_xsk.buf, rd->addr);

        // rewrite to WAN L2
        rewrite_eth(pkt, WAN_SRC_MAC, WAN_PEER_MAC);

        // TX out WAN
        (void)tx_copy(&wan_xsk, pkt, rd->len);

        // return RX buffer to local FQ
        __u32 fq_idx;
        if (xsk_ring_prod__reserve(&local_xsk.fq, 1, &fq_idx) == 1) {
            *xsk_ring_prod__fill_addr(&local_xsk.fq, fq_idx) = rd->addr & ~(FSIZE - 1);
            xsk_ring_prod__submit(&local_xsk.fq, 1);
        }
    }

    xsk_ring_cons__release(&local_xsk.rx, n);
}

static void wan_to_local(void)
{
    // OPTIONAL: if you want return traffic, you must ALSO RX on WAN.
    // For bypass-kernel ping end-to-end, you need the other server running too.
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&wan_xsk.rx, BATCH, &rx_idx);
    if (!n) return;

    for (unsigned int i = 0; i < n; i++) {
        struct xdp_desc *rd = (struct xdp_desc *)xsk_ring_cons__rx_desc(&wan_xsk.rx, rx_idx + i);
        unsigned char *pkt = xsk_umem__get_data(wan_xsk.buf, rd->addr);

        // rewrite back to client on local
        rewrite_eth(pkt, LOCAL_SRC_MAC, CLIENT_MAC);

        (void)tx_copy(&local_xsk, pkt, rd->len);

        // return RX buffer to wan FQ
        __u32 fq_idx;
        if (xsk_ring_prod__reserve(&wan_xsk.fq, 1, &fq_idx) == 1) {
            *xsk_ring_prod__fill_addr(&wan_xsk.fq, fq_idx) = rd->addr & ~(FSIZE - 1);
            xsk_ring_prod__submit(&wan_xsk.fq, 1);
        }
    }

    xsk_ring_cons__release(&wan_xsk.rx, n);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <role>\n  role=1 server1 | role=2 server2\n", argv[0]);
        return 1;
    }
    int role = atoi(argv[1]);
    if (role != 1 && role != 2) return 1;

    set_role(role);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit");

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    // IMPORTANT: WAN MUST NOT have XDP attached
    // do best-effort detach on WAN to avoid self-loop
    int wan_ifidx = if_nametoindex(WAN_IF);
    if (wan_ifidx) {
        bpf_set_link_xdp_fd(wan_ifidx, -1, XDP_FLAGS_SKB_MODE);
        bpf_set_link_xdp_fd(wan_ifidx, -1, XDP_FLAGS_DRV_MODE);
        bpf_set_link_xdp_fd(wan_ifidx, -1, 0);
    }

    // load BPF for LOCAL only
    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (!obj) die("bpf_object__open_file");
    if (bpf_object__load(obj)) die("bpf_object__load");

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    if (!prog) die("find_program");
    int prog_fd = bpf_program__fd(prog);

    int xsks_map = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xsks_map < 0) die("find xsks_map");

    if (attach_xdp_local(prog_fd) < 0) die("attach_xdp_local");

    // setup XSK local (RX+TX) and WAN (RX+TX) - WAN has NO XDP attach
    int ret;
    ret = setup_umem_and_socket(&local_xsk, LOCAL_IF, 1);
    if (ret) { errno = -ret; die("setup local_xsk"); }

    ret = setup_umem_and_socket(&wan_xsk, WAN_IF, 1);
    if (ret) { errno = -ret; die("setup wan_xsk"); }

    // map local socket into xsks_map so XDP redirects to it
    int fd = xsk_socket__fd(local_xsk.xsk);
    __u32 key = 0;
    if (bpf_map_update_elem(xsks_map, &key, &fd, 0)) die("bpf_map_update_elem");

    struct pollfd fds[2] = {
        {.fd = xsk_socket__fd(local_xsk.xsk), .events = POLLIN},
        {.fd = xsk_socket__fd(wan_xsk.xsk),   .events = POLLIN},
    };

    while (running) {
        poll(fds, 2, 10);
        local_to_wan();
        wan_to_local();
    }

    // detach local XDP
    int local_ifidx = if_nametoindex(LOCAL_IF);
    if (local_ifidx) bpf_set_link_xdp_fd(local_ifidx, -1, XDP_FLAGS_SKB_MODE);
    return 0;
}

