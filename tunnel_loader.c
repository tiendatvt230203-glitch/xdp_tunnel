#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include <errno.h>
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>        // mmap/munmap
#include <sys/socket.h>      // sendto
#include <sys/types.h>

static volatile int running = 1;
static void sigint_handler(int s) { (void)s; running = 0; }

static void die(const char *m) {
    fprintf(stderr, "%s: %s\n", m, strerror(errno));
    exit(1);
}

#define FRAME_SIZE   2048
#define NUM_FRAMES   4096
#define RX_SIZE      1024
#define TX_SIZE      1024

struct port {
    const char *ifname;
    int ifindex;

    // BPF per-port
    struct bpf_object *obj;
    int prog_fd;
    int map_fd;
    __u32 xdp_flags;

    // XSK per-port (single queue 0)
    void *umem_area;
    struct xsk_umem *umem;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    bool need_wakeup; // kept but we force always-kick
};

static int port_setup_xsk(struct port *p, int queue_id)
{
    size_t umem_sz = (size_t)NUM_FRAMES * FRAME_SIZE;
    p->umem_area = mmap(NULL, umem_sz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p->umem_area == MAP_FAILED) return -1;

    struct xsk_umem_config ucfg = {
        .fill_size = RX_SIZE,
        .comp_size = TX_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };

    int err = xsk_umem__create(&p->umem, p->umem_area, umem_sz,
                              &p->fill, &p->comp, &ucfg);
    if (err) { errno = -err; return -1; }

    // Pre-fill fill ring with all frames
    __u32 idx = 0;
    int r = xsk_ring_prod__reserve(&p->fill, NUM_FRAMES, &idx);
    if (r != NUM_FRAMES) return -1;

    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&p->fill, idx + i) = (unsigned long long)i * FRAME_SIZE;

    xsk_ring_prod__submit(&p->fill, NUM_FRAMES);

    // IMPORTANT: force COPY mode + SKB XDP mode to avoid driver ZC limitations
    struct xsk_socket_config cfg = {
        .rx_size = RX_SIZE,
        .tx_size = TX_SIZE,

        // We already attach XDP ourselves (bpf_set_link_xdp_fd),
        // so prevent libbpf from trying to autoload another program.
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,

        .xdp_flags = XDP_FLAGS_SKB_MODE, // force generic
        .bind_flags = XDP_COPY,          // force copy mode
    };

    err = xsk_socket__create(&p->xsk, p->ifname, queue_id, p->umem, &p->rx, &p->tx, &cfg);
    if (err) { errno = -err; return -1; }

    // libbpf on your system may not export xsk_socket__needs_wakeup()
    // and COPY mode works fine with always-kick
    p->need_wakeup = true;

    return 0;
}

static int port_load_attach_bpf(struct port *p, const char *bpf_obj_path)
{
    p->ifindex = if_nametoindex(p->ifname);
    if (!p->ifindex) return -1;

    // Load a NEW instance per interface (so map doesn't collide across NICs)
    p->obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(p->obj)) return -1;
    if (bpf_object__load(p->obj)) return -1;

    struct bpf_program *prog = bpf_object__find_program_by_name(p->obj, "xdp_xsk_redirect");
    if (!prog) return -1;
    p->prog_fd = bpf_program__fd(prog);
    if (p->prog_fd < 0) return -1;

    struct bpf_map *m = bpf_object__find_map_by_name(p->obj, "xsks_map");
    if (!m) return -1;
    p->map_fd = bpf_map__fd(m);
    if (p->map_fd < 0) return -1;

    // IMPORTANT: force SKB mode attach (generic) for compatibility
    p->xdp_flags = XDP_FLAGS_SKB_MODE;
    if (bpf_set_link_xdp_fd(p->ifindex, p->prog_fd, p->xdp_flags) < 0)
        return -1;

    return 0;
}

static int port_bind_xsk_to_map(struct port *p, int queue_id)
{
    int xsk_fd = xsk_socket__fd(p->xsk);
    __u32 q = (__u32)queue_id;
    if (bpf_map_update_elem(p->map_fd, &q, &xsk_fd, BPF_ANY) < 0)
        return -1;
    return 0;
}

static void port_detach_close(struct port *p)
{
    if (p->ifindex) (void)bpf_set_link_xdp_fd(p->ifindex, -1, p->xdp_flags);
    if (p->xsk) xsk_socket__delete(p->xsk);
    if (p->umem) xsk_umem__delete(p->umem);
    if (p->umem_area && p->umem_area != MAP_FAILED)
        munmap(p->umem_area, (size_t)NUM_FRAMES * FRAME_SIZE);
    if (p->obj) bpf_object__close(p->obj);
}

static inline void *umem_ptr(struct port *p, __u64 addr)
{
    return (void *)((char *)p->umem_area + addr);
}

static inline void recycle_addr(struct port *p, __u64 addr)
{
    __u32 idx = 0;
    if (xsk_ring_prod__reserve(&p->fill, 1, &idx) == 1) {
        *xsk_ring_prod__fill_addr(&p->fill, idx) = addr;
        xsk_ring_prod__submit(&p->fill, 1);
    }
}

static inline void kick_tx(struct port *p)
{
    // Always kick (safe for COPY mode)
    (void)p;
    // Use the destination socket fd when sending (done at call site)
}

static void forward_copy(struct port *src, struct port *dst, __u64 addr, __u32 len)
{
    // Take a free dst frame from dst->fill ring
    __u32 idx_f = 0;
    if (xsk_ring_prod__reserve(&dst->fill, 1, &idx_f) != 1) {
        recycle_addr(src, addr);
        return;
    }

    __u64 dst_addr = *xsk_ring_prod__fill_addr(&dst->fill, idx_f);
    xsk_ring_prod__submit(&dst->fill, 1);

    void *sp = umem_ptr(src, addr);
    void *dp = umem_ptr(dst, dst_addr);
    if (len > FRAME_SIZE) len = FRAME_SIZE;
    memcpy(dp, sp, len);

    // TX on dst
    __u32 idx_tx = 0;
    if (xsk_ring_prod__reserve(&dst->tx, 1, &idx_tx) == 1) {
        struct xdp_desc *txd = xsk_ring_prod__tx_desc(&dst->tx, idx_tx);
        txd->addr = dst_addr;
        txd->len  = len;
        xsk_ring_prod__submit(&dst->tx, 1);

        // kick TX (COPY mode)
        sendto(xsk_socket__fd(dst->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    } else {
        recycle_addr(dst, dst_addr);
    }

    // Recycle src frame back to src->fill
    recycle_addr(src, addr);
}

static void reap_completions(struct port *p)
{
    __u32 idx = 0;
    int n = xsk_ring_cons__peek(&p->comp, 64, &idx);
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            __u64 a = *xsk_ring_cons__comp_addr(&p->comp, idx + i);
            recycle_addr(p, a);
        }
        xsk_ring_cons__release(&p->comp, n);
    }
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s <bpf.o> <lan_if=enp7s0> <wan_if1> [wan_if2] [wan_if3]...\n"
        "Example: %s tunnel.bpf.o enp7s0 enp4s0 enp5s0 enp6s0\n", p, p);
}

int main(int argc, char **argv)
{
    if (argc < 4) { usage(argv[0]); return 1; }

    const char *bpf_obj = argv[1];
    const char *lan = argv[2];
    int wan_n = argc - 3;

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    struct port lanp = {.ifname = lan};
    struct port wans[16] = {0};
    if (wan_n > 16) die("too many wans");

    // LAN
    if (port_load_attach_bpf(&lanp, bpf_obj) < 0) die("LAN load/attach failed");
    if (port_setup_xsk(&lanp, 0) < 0) die("LAN xsk setup failed");
    if (port_bind_xsk_to_map(&lanp, 0) < 0) die("LAN bind xsk->map failed");

    // WANs
    for (int i = 0; i < wan_n; i++) {
        wans[i].ifname = argv[i + 3];
        if (port_load_attach_bpf(&wans[i], bpf_obj) < 0) die("WAN load/attach failed");
        if (port_setup_xsk(&wans[i], 0) < 0) die("WAN xsk setup failed");
        if (port_bind_xsk_to_map(&wans[i], 0) < 0) die("WAN bind xsk->map failed");
        printf("WAN[%d]=%s ready\n", i, wans[i].ifname);
    }

    printf("OK. Forwarding:\n");
    printf("  LAN(%s) -> choose WAN(enp4/enp5/enp6...)\n", lanp.ifname);
    printf("  WAN(*)  -> LAN(%s)\n", lanp.ifname);
    printf("Ctrl+C to stop (detaches XDP).\n");

    struct pollfd fds[1 + 16];
    int rr = 0;

    while (running) {
        int nfds = 0;

        fds[nfds++] = (struct pollfd){ .fd = xsk_socket__fd(lanp.xsk), .events = POLLIN };
        for (int i = 0; i < wan_n; i++) {
            fds[nfds++] = (struct pollfd){ .fd = xsk_socket__fd(wans[i].xsk), .events = POLLIN };
        }

        int ret = poll(fds, nfds, 10);
        if (ret < 0) {
            if (errno == EINTR) continue;
            die("poll failed");
        }

        // LAN -> WAN (round robin)
        if (fds[0].revents & POLLIN) {
            __u32 idx = 0;
            int n = xsk_ring_cons__peek(&lanp.rx, 64, &idx);
            if (n > 0) {
                for (int i = 0; i < n; i++) {
                    const struct xdp_desc *d = xsk_ring_cons__rx_desc(&lanp.rx, idx + i);
                    int pick = rr++ % wan_n;
                    forward_copy(&lanp, &wans[pick], d->addr, d->len);
                }
                xsk_ring_cons__release(&lanp.rx, n);
            }
        }

        // WAN -> LAN
        for (int wi = 0; wi < wan_n; wi++) {
            if (fds[1 + wi].revents & POLLIN) {
                __u32 idx = 0;
                int n = xsk_ring_cons__peek(&wans[wi].rx, 64, &idx);
                if (n > 0) {
                    for (int i = 0; i < n; i++) {
                        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&wans[wi].rx, idx + i);
                        forward_copy(&wans[wi], &lanp, d->addr, d->len);
                    }
                    xsk_ring_cons__release(&wans[wi].rx, n);
                }
            }
        }

        // Recycle TX completions
        reap_completions(&lanp);
        for (int i = 0; i < wan_n; i++) reap_completions(&wans[i]);
    }

    port_detach_close(&lanp);
    for (int i = 0; i < wan_n; i++) port_detach_close(&wans[i]);

    printf("Stopped.\n");
    return 0;
}

