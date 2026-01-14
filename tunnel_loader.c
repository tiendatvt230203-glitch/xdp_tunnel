#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
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

static inline __u32 xsk_key(int ifindex, int qid)
{
    return ((__u32)ifindex << 16) | ((__u32)qid & 0xFFFF);
}

struct port {
    const char *ifname;
    int ifindex;

    __u32 xdp_flags;

    void *umem_area;
    struct xsk_umem *umem;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
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

    // fill ring: nạp toàn bộ frame
    __u32 idx = 0;
    int r = xsk_ring_prod__reserve(&p->fill, NUM_FRAMES, &idx);
    if (r != NUM_FRAMES) return -1;

    for (int i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&p->fill, idx + i) = (unsigned long long)i * FRAME_SIZE;

    xsk_ring_prod__submit(&p->fill, NUM_FRAMES);

    // ÉP COPY + SKB để igc/driver nào cũng chạy được
    struct xsk_socket_config cfg = {
        .rx_size = RX_SIZE,
        .tx_size = TX_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY,
    };

    err = xsk_socket__create(&p->xsk, p->ifname, queue_id, p->umem, &p->rx, &p->tx, &cfg);
    if (err) { errno = -err; return -1; }

    return 0;
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

static void forward_copy(struct port *src, struct port *dst, __u64 addr, __u32 len)
{
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

    __u32 idx_tx = 0;
    if (xsk_ring_prod__reserve(&dst->tx, 1, &idx_tx) == 1) {
        struct xdp_desc *txd = xsk_ring_prod__tx_desc(&dst->tx, idx_tx);
        txd->addr = dst_addr;
        txd->len  = len;
        xsk_ring_prod__submit(&dst->tx, 1);

        // COPY mode: cứ kick
        sendto(xsk_socket__fd(dst->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    } else {
        recycle_addr(dst, dst_addr);
    }

    recycle_addr(src, addr);
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
    const char *lan_if  = argv[2];
    int wan_n = argc - 3;
    if (wan_n > 16) die("too many wans");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // 1) Load BPF ONCE
    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) die("bpf_object__open_file failed");
    if (bpf_object__load(obj)) die("bpf_object__load failed");

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_xsk_redirect");
    if (!prog) die("cannot find program xdp_xsk_redirect");
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) die("bpf_program__fd failed");

    struct bpf_map *m = bpf_object__find_map_by_name(obj, "xsks_map");
    if (!m) die("cannot find map xsks_map");
    int map_fd = bpf_map__fd(m);
    if (map_fd < 0) die("bpf_map__fd failed");

    // 2) Prepare ports
    struct port lan = {.ifname = lan_if};
    struct port wans[16] = {0};

    lan.ifindex = if_nametoindex(lan.ifname);
    if (!lan.ifindex) die("if_nametoindex LAN failed");

    for (int i = 0; i < wan_n; i++) {
        wans[i].ifname = argv[i + 3];
        wans[i].ifindex = if_nametoindex(wans[i].ifname);
        if (!wans[i].ifindex) die("if_nametoindex WAN failed");
    }

    // 3) Attach SAME program to ALL interfaces (SKB mode for safety)
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;

    if (bpf_set_link_xdp_fd(lan.ifindex, prog_fd, xdp_flags) < 0)
        die("attach XDP on LAN failed");

    for (int i = 0; i < wan_n; i++) {
        if (bpf_set_link_xdp_fd(wans[i].ifindex, prog_fd, xdp_flags) < 0)
            die("attach XDP on WAN failed");
    }

    // 4) Create XSK per interface and bind into ONE shared xsks_map
    if (port_setup_xsk(&lan, 0) < 0) die("LAN xsk setup failed");
    {
        int xsk_fd = xsk_socket__fd(lan.xsk);
        __u32 key = xsk_key(lan.ifindex, 0);
        if (bpf_map_update_elem(map_fd, &key, &xsk_fd, BPF_ANY) < 0)
            die("LAN bpf_map_update_elem failed");
    }

    for (int i = 0; i < wan_n; i++) {
        if (port_setup_xsk(&wans[i], 0) < 0) die("WAN xsk setup failed");
        int xsk_fd = xsk_socket__fd(wans[i].xsk);
        __u32 key = xsk_key(wans[i].ifindex, 0);
        if (bpf_map_update_elem(map_fd, &key, &xsk_fd, BPF_ANY) < 0)
            die("WAN bpf_map_update_elem failed");

        printf("WAN[%d]=%s (ifindex=%d) ready\n", i, wans[i].ifname, wans[i].ifindex);
    }

    printf("OK. Forwarding:\n");
    printf("  LAN(%s) -> choose WAN\n", lan.ifname);
    printf("  WAN(*)  -> LAN(%s)\n", lan.ifname);
    printf("Ctrl+C to stop (detaches XDP).\n");

    struct pollfd fds[1 + 16];
    int rr = 0;

    while (running) {
        int nfds = 0;

        fds[nfds++] = (struct pollfd){ .fd = xsk_socket__fd(lan.xsk), .events = POLLIN };
        for (int i = 0; i < wan_n; i++)
            fds[nfds++] = (struct pollfd){ .fd = xsk_socket__fd(wans[i].xsk), .events = POLLIN };

        int ret = poll(fds, nfds, 10);
        if (ret < 0) {
            if (errno == EINTR) continue;
            die("poll failed");
        }

        // LAN -> WAN (RR)
        if (fds[0].revents & POLLIN) {
            __u32 idx = 0;
            int n = xsk_ring_cons__peek(&lan.rx, 64, &idx);
            if (n > 0) {
                for (int i = 0; i < n; i++) {
                    const struct xdp_desc *d = xsk_ring_cons__rx_desc(&lan.rx, idx + i);
                    int pick = rr++ % wan_n;
                    forward_copy(&lan, &wans[pick], d->addr, d->len);
                }
                xsk_ring_cons__release(&lan.rx, n);
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
                        forward_copy(&wans[wi], &lan, d->addr, d->len);
                    }
                    xsk_ring_cons__release(&wans[wi].rx, n);
                }
            }
        }

        reap_completions(&lan);
        for (int i = 0; i < wan_n; i++) reap_completions(&wans[i]);
    }

    // detach all
    (void)bpf_set_link_xdp_fd(lan.ifindex, -1, xdp_flags);
    for (int i = 0; i < wan_n; i++)
        (void)bpf_set_link_xdp_fd(wans[i].ifindex, -1, xdp_flags);

    // cleanup
    if (lan.xsk) xsk_socket__delete(lan.xsk);
    if (lan.umem) xsk_umem__delete(lan.umem);
    if (lan.umem_area && lan.umem_area != MAP_FAILED)
        munmap(lan.umem_area, (size_t)NUM_FRAMES * FRAME_SIZE);

    for (int i = 0; i < wan_n; i++) {
        if (wans[i].xsk) xsk_socket__delete(wans[i].xsk);
        if (wans[i].umem) xsk_umem__delete(wans[i].umem);
        if (wans[i].umem_area && wans[i].umem_area != MAP_FAILED)
            munmap(wans[i].umem_area, (size_t)NUM_FRAMES * FRAME_SIZE);
    }

    bpf_object__close(obj);
    printf("Stopped.\n");
    return 0;
}

