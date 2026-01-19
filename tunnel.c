#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#define FRAMES 4096
#define FSIZE  4096
#define BATCH  64

static volatile int running = 1;

/* ========== CONFIG ========== */
static char local_if[32], wan_if[32];
static uint8_t local_mac[6], client_mac[6], wan_mac[6], peer_mac[6];
static uint32_t local_net, local_mask;

/* ========== XSK ========== */
struct xsk {
    struct xsk_socket *sock;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buf;
    int ifindex, prog_fd, map_fd;
    struct bpf_object *obj;
};

static struct xsk local_xsk, wan_xsk;

/* ========== HELPERS ========== */
static void get_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

static void parse_mac(const char *s, uint8_t *mac) {
    unsigned int m[6];
    sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
    for(int i=0;i<6;i++) mac[i]=m[i];
}

static void parse_cidr(const char *s, uint32_t *net, uint32_t *mask) {
    char ip[32]; int prefix=24;
    strcpy(ip, s);
    char *p = strchr(ip, '/');
    if(p) { *p=0; prefix=atoi(p+1); }
    struct in_addr a;
    inet_pton(AF_INET, ip, &a);
    *net = ntohl(a.s_addr);
    *mask = ~0U << (32-prefix);
}

/* ========== LOAD CONFIG ========== */
static int load_config(const char *path, int wan_idx) {
    FILE *f = fopen(path, "r");
    if(!f) { fprintf(stderr, "Cannot open config: %s\n", path); return -1; }

    char line[256], key[32], v1[64], v2[64], v3[64];
    int wan_count = 0;

    while(fgets(line, sizeof(line), f)) {
        if(line[0]=='#' || line[0]=='\n') continue;
        v1[0]=v2[0]=v3[0]=0;
        sscanf(line, "%s %s %s %s", key, v1, v2, v3);

        if(!strcmp(key,"local")) {
            strcpy(local_if, v1);
            get_mac(v1, local_mac);
        }
        else if(!strcmp(key,"localnet")) parse_cidr(v1, &local_net, &local_mask);
        else if(!strcmp(key,"client")) parse_mac(v1, client_mac);
        else if(!strcmp(key,"wan")) {
            if(wan_count == wan_idx) {
                strcpy(wan_if, v1);
                get_mac(v1, wan_mac);
                parse_mac(v3, peer_mac);
            }
            wan_count++;
        }
    }
    fclose(f);
    return 0;
}

/* ========== SETUP XSK ========== */
static int setup_xsk(struct xsk *x, const char *ifname, int is_local) {
    int ret;
    memset(x, 0, sizeof(*x));  /* Clear struct */

    x->ifindex = if_nametoindex(ifname);
    if(!x->ifindex) {
        fprintf(stderr, "[%s] Interface not found\n", ifname);
        return -1;
    }

    /* Load BPF */
    x->obj = bpf_object__open_file("xdp_kern.o", NULL);
    if(!x->obj) {
        fprintf(stderr, "[%s] Failed to open xdp_kern.o\n", ifname);
        return -1;
    }

    ret = bpf_object__load(x->obj);
    if(ret) {
        fprintf(stderr, "[%s] Failed to load BPF object: %d\n", ifname, ret);
        return -1;
    }

    x->map_fd = bpf_object__find_map_fd_by_name(x->obj, "xsks_map");
    if(x->map_fd < 0) {
        fprintf(stderr, "[%s] xsks_map not found\n", ifname);
        return -1;
    }

    /* Get first program fd */
    struct bpf_program *prog = bpf_program__next(NULL, x->obj);
    if(!prog) {
        fprintf(stderr, "[%s] No BPF program found\n", ifname);
        return -1;
    }
    x->prog_fd = bpf_program__fd(prog);

    /* Set mode in config map */
    int cfg_fd = bpf_object__find_map_fd_by_name(x->obj, "config");
    if(cfg_fd >= 0) {
        __u32 k0=0, k1=1, k2=2;
        __u32 mode = is_local ? 0 : 1;
        bpf_map_update_elem(cfg_fd, &k2, &mode, 0);
        if(is_local) {
            bpf_map_update_elem(cfg_fd, &k0, &local_net, 0);
            bpf_map_update_elem(cfg_fd, &k1, &local_mask, 0);
        }
    }

    /* Attach XDP - force replace if exists */
    bpf_set_link_xdp_fd(x->ifindex, -1, 0);  /* detach any existing */
    ret = bpf_set_link_xdp_fd(x->ifindex, x->prog_fd, 0);  /* attach without NOEXIST flag */
    if(ret < 0) {
        fprintf(stderr, "[%s] Failed to attach XDP: %d\n", ifname, ret);
        return -1;
    }

    /* Create UMEM */
    ret = posix_memalign(&x->buf, getpagesize(), FRAMES*FSIZE);
    if(ret) {
        fprintf(stderr, "[%s] posix_memalign failed\n", ifname);
        return -1;
    }

    struct xsk_umem_config ucfg = {.fill_size=FRAMES, .comp_size=FRAMES, .frame_size=FSIZE};
    ret = xsk_umem__create(&x->umem, x->buf, FRAMES*FSIZE, &x->fq, &x->cq, &ucfg);
    if(ret) {
        fprintf(stderr, "[%s] xsk_umem__create failed: %d\n", ifname, ret);
        return -1;
    }

    /* Fill ring */
    __u32 idx = 0;
    ret = xsk_ring_prod__reserve(&x->fq, FRAMES, &idx);
    if(ret != FRAMES) {
        fprintf(stderr, "[%s] fill ring reserve failed: %d\n", ifname, ret);
        return -1;
    }
    for(int i=0; i<FRAMES; i++)
        *xsk_ring_prod__fill_addr(&x->fq, idx+i) = i*FSIZE;
    xsk_ring_prod__submit(&x->fq, FRAMES);

    /* Create socket */
    struct xsk_socket_config xcfg = {
        .rx_size=2048, .tx_size=2048, .bind_flags=XDP_COPY
    };
    ret = xsk_socket__create_shared(&x->sock, ifname, 0, x->umem, &x->rx, &x->tx, &x->fq, &x->cq, &xcfg);
    if(ret) {
        fprintf(stderr, "[%s] xsk_socket__create_shared failed: %d\n", ifname, ret);
        return -1;
    }

    /* Register in map */
    int fd = xsk_socket__fd(x->sock);
    int key = 0;
    bpf_map_update_elem(x->map_fd, &key, &fd, 0);

    printf("[%s] XSK ready (mode=%s)\n", ifname, is_local?"LOCAL":"WAN");
    return 0;
}

static void cleanup_xsk(struct xsk *x) {
    if(x->ifindex) bpf_set_link_xdp_fd(x->ifindex, -1, 0);
    if(x->sock) xsk_socket__delete(x->sock);
    if(x->umem) xsk_umem__delete(x->umem);
    if(x->buf) free(x->buf);
    if(x->obj) bpf_object__close(x->obj);
}

/* ========== FORWARD PACKET ========== */
static void forward(struct xsk *src, struct xsk *dst, uint8_t *new_src, uint8_t *new_dst) {
    __u32 rx_idx = 0, tx_idx = 0;

    /* RX from source */
    unsigned int n = xsk_ring_cons__peek(&src->rx, BATCH, &rx_idx);
    if(!n) return;

    /* Drain completion ring */
    __u32 cq_idx = 0;
    unsigned int done = xsk_ring_cons__peek(&dst->cq, FRAMES, &cq_idx);
    if(done) xsk_ring_cons__release(&dst->cq, done);

    /* Process packets */
    for(unsigned int i=0; i<n; i++) {
        struct xdp_desc *rd = (struct xdp_desc*)xsk_ring_cons__rx_desc(&src->rx, rx_idx+i);
        uint8_t *pkt = xsk_umem__get_data(src->buf, rd->addr);

        /* Rewrite MAC */
        struct ethhdr *eth = (struct ethhdr*)pkt;
        memcpy(eth->h_source, new_src, 6);
        memcpy(eth->h_dest, new_dst, 6);

        /* TX to destination */
        if(xsk_ring_prod__reserve(&dst->tx, 1, &tx_idx)) {
            __u64 addr = (i % 256) * FSIZE;
            memcpy(xsk_umem__get_data(dst->buf, addr), pkt, rd->len);

            struct xdp_desc *td = xsk_ring_prod__tx_desc(&dst->tx, tx_idx);
            td->addr = addr;
            td->len = rd->len;
            xsk_ring_prod__submit(&dst->tx, 1);

            sendto(xsk_socket__fd(dst->sock), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
    }

    /* Return buffers to fill ring */
    __u32 fq_idx = 0;
    if(xsk_ring_prod__reserve(&src->fq, n, &fq_idx) == n) {
        for(unsigned int i=0; i<n; i++) {
            struct xdp_desc *rd = (struct xdp_desc*)xsk_ring_cons__rx_desc(&src->rx, rx_idx+i);
            *xsk_ring_prod__fill_addr(&src->fq, fq_idx+i) = rd->addr & ~(FSIZE-1);
        }
        xsk_ring_prod__submit(&src->fq, n);
    }
    xsk_ring_cons__release(&src->rx, n);
}

/* ========== MAIN ========== */
static void sig_handler(int s) { (void)s; running = 0; }

int main(int argc, char **argv) {
    if(argc < 3) {
        printf("Usage: %s <config> <wan_index>\n", argv[0]);
        printf("Example: %s config/server1.conf 0\n", argv[0]);
        return 1;
    }

    /* Setup */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    libbpf_set_print(NULL);

    /* Load config */
    if(load_config(argv[1], atoi(argv[2])) < 0) return 1;

    printf("\n=== AF_XDP Tunnel ===\n");
    printf("LOCAL:  %s -> CLIENT %02x:%02x:%02x:%02x:%02x:%02x\n",
           local_if, client_mac[0],client_mac[1],client_mac[2],client_mac[3],client_mac[4],client_mac[5]);
    printf("WAN:    %s -> PEER   %02x:%02x:%02x:%02x:%02x:%02x\n",
           wan_if, peer_mac[0],peer_mac[1],peer_mac[2],peer_mac[3],peer_mac[4],peer_mac[5]);
    printf("\n");

    /* Setup XSK */
    if(setup_xsk(&local_xsk, local_if, 1) < 0) {
        fprintf(stderr, "Failed to setup LOCAL XSK\n");
        return 1;
    }
    if(setup_xsk(&wan_xsk, wan_if, 0) < 0) {
        fprintf(stderr, "Failed to setup WAN XSK\n");
        cleanup_xsk(&local_xsk);
        return 1;
    }

    printf("\nRunning... (Ctrl+C to stop)\n");
    printf("  LOCAL RX -> rewrite MAC -> WAN TX\n");
    printf("  WAN RX   -> rewrite MAC -> LOCAL TX\n\n");

    /* Main loop */
    struct pollfd fds[2] = {
        {.fd = xsk_socket__fd(local_xsk.sock), .events = POLLIN},
        {.fd = xsk_socket__fd(wan_xsk.sock), .events = POLLIN}
    };

    while(running) {
        poll(fds, 2, 100);
        forward(&local_xsk, &wan_xsk, wan_mac, peer_mac);
        forward(&wan_xsk, &local_xsk, local_mac, client_mac);
    }

    printf("\nShutdown...\n");
    cleanup_xsk(&local_xsk);
    cleanup_xsk(&wan_xsk);

    return 0;
}
