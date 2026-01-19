#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <poll.h>
#include <time.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define FRAMES 4096
#define FSIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH  64
#define MAX_WAN 4

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

static volatile int running = 1;

/* Configuration */
static char local_if[32];
static char wan_if[MAX_WAN][32];
static char wan_peer_ip[MAX_WAN][32];
static uint8_t local_mac[6];
static uint8_t client_mac[6];
static uint8_t wan_mac[MAX_WAN][6];
static uint8_t wan_peer_mac[MAX_WAN][6];
static int num_wan = 0;
static uint32_t local_net = 0;
static uint32_t local_mask = 0;

/* XSK for LOCAL */
struct xsk_info {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buf;
    struct bpf_object *bpf_obj;
    int xsks_map_fd;
    char ifname[32];
};

static struct xsk_info local_xsk;
static struct xsk_info wan_xsk;

/* Stats */
static uint64_t local_rx_cnt = 0, local_tx_cnt = 0;
static uint64_t wan_rx_cnt = 0, wan_tx_cnt = 0;

/* Suppress libbpf errors (error 524) */
static int silent_print(enum libbpf_print_level level, const char *fmt, va_list args) {
    (void)level; (void)fmt; (void)args;
    return 0;
}

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void sig_handler(int s) {
    (void)s;
    running = 0;
}

static int get_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int parse_mac(const char *str, uint8_t *mac) {
    unsigned int m[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = m[i];
    return 0;
}

static int parse_cidr(const char *str, uint32_t *net, uint32_t *mask) {
    char ip[32];
    int prefix = 24;
    strncpy(ip, str, sizeof(ip) - 1);
    char *slash = strchr(ip, '/');
    if (slash) {
        *slash = 0;
        prefix = atoi(slash + 1);
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;
    *net = ntohl(addr.s_addr);
    *mask = prefix ? (~0U << (32 - prefix)) : 0;
    return 0;
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256], key[32], v1[64], v2[64], v3[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v1[0] = v2[0] = v3[0] = 0;
        sscanf(line, "%s %s %s %s", key, v1, v2, v3);

        if (!strcmp(key, "local")) {
            strncpy(local_if, v1, sizeof(local_if) - 1);
            get_mac(v1, local_mac);
        } else if (!strcmp(key, "localnet")) {
            parse_cidr(v1, &local_net, &local_mask);
        } else if (!strcmp(key, "client")) {
            parse_mac(v1, client_mac);
        } else if (!strcmp(key, "wan") && num_wan < MAX_WAN) {
            strncpy(wan_if[num_wan], v1, sizeof(wan_if[0]) - 1);
            strncpy(wan_peer_ip[num_wan], v2, sizeof(wan_peer_ip[0]) - 1);
            get_mac(v1, wan_mac[num_wan]);
            if (v3[0]) parse_mac(v3, wan_peer_mac[num_wan]);
            num_wan++;
        }
    }
    fclose(f);
    return (local_if[0] && num_wan > 0) ? 0 : -1;
}

/*
 * Setup XSK exactly like recv.c (which works)
 * is_local: if true, configure filter for local network
 */
static int setup_xsk(struct xsk_info *info, const char *ifname, int is_local) {
    strncpy(info->ifname, ifname, sizeof(info->ifname) - 1);

    printf("[%s] Setting up XSK...\n", ifname);

    /* 1. Load BPF object and get xsks_map fd */
    info->bpf_obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (!info->bpf_obj) {
        fprintf(stderr, "[%s] Failed to open xdp_kern.o\n", ifname);
        return -1;
    }

    if (bpf_object__load(info->bpf_obj)) {
        fprintf(stderr, "[%s] Failed to load BPF object\n", ifname);
        return -1;
    }

    info->xsks_map_fd = bpf_object__find_map_fd_by_name(info->bpf_obj, "xsks_map");
    if (info->xsks_map_fd < 0) {
        fprintf(stderr, "[%s] xsks_map not found\n", ifname);
        return -1;
    }
    printf("[%s] BPF loaded, xsks_map fd=%d\n", ifname, info->xsks_map_fd);

    /* Configure local network filter (only for LOCAL interface) */
    if (is_local && local_net && local_mask) {
        int config_fd = bpf_object__find_map_fd_by_name(info->bpf_obj, "config");
        if (config_fd >= 0) {
            __u32 k0 = 0, k1 = 1;
            bpf_map_update_elem(config_fd, &k0, &local_net, 0);
            bpf_map_update_elem(config_fd, &k1, &local_mask, 0);
            printf("[%s] Filter: local_net=0x%08x mask=0x%08x\n", ifname, local_net, local_mask);
            printf("[%s] -> Packets to local net: PASS, others: REDIRECT\n", ifname);
        }
    }

    /* 2. Allocate UMEM */
    if (posix_memalign(&info->buf, getpagesize(), FRAMES * FSIZE)) {
        fprintf(stderr, "[%s] memalign failed\n", ifname);
        return -1;
    }

    struct xsk_umem_config ucfg = {
        .fill_size = FRAMES,
        .comp_size = FRAMES,
        .frame_size = FSIZE,
    };

    if (xsk_umem__create(&info->umem, info->buf, FRAMES * FSIZE,
                         &info->fq, &info->cq, &ucfg)) {
        fprintf(stderr, "[%s] umem create failed\n", ifname);
        return -1;
    }
    printf("[%s] UMEM created\n", ifname);

    /* 3. Fill ring with all frames */
    __u32 idx;
    if (xsk_ring_prod__reserve(&info->fq, FRAMES, &idx) != FRAMES) {
        fprintf(stderr, "[%s] fill ring reserve failed\n", ifname);
        return -1;
    }
    for (int i = 0; i < FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&info->fq, idx + i) = i * FSIZE;
    }
    xsk_ring_prod__submit(&info->fq, FRAMES);
    printf("[%s] Fill ring initialized with %d frames\n", ifname, FRAMES);

    /* 4. Create XSK socket - EXACTLY like recv.c */
    struct xsk_socket_config xcfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = XDP_COPY,
    };

    int ret = xsk_socket__create_shared(&info->xsk, ifname, 0, info->umem,
                                        &info->rx, &info->tx,
                                        &info->fq, &info->cq, &xcfg);
    if (ret) {
        if (-ret == ENOTSUPP) {
            printf("[%s] XDP not supported, skipping\n", ifname);
            return -1;
        }
        fprintf(stderr, "[%s] xsk_socket__create_shared failed: %d\n", ifname, ret);
        return -1;
    }
    printf("[%s] XSK socket created, fd=%d\n", ifname, xsk_socket__fd(info->xsk));

    /* 5. Update xsks_map with socket fd */
    int fd = xsk_socket__fd(info->xsk);
    int key = 0;
    if (bpf_map_update_elem(info->xsks_map_fd, &key, &fd, 0)) {
        fprintf(stderr, "[%s] map update failed\n", ifname);
        return -1;
    }
    printf("[%s] Socket registered in xsks_map\n", ifname);

    return 0;
}

static void cleanup_xsk(struct xsk_info *info) {
    if (info->xsk) xsk_socket__delete(info->xsk);
    if (info->umem) xsk_umem__delete(info->umem);
    if (info->buf) free(info->buf);
    if (info->bpf_obj) bpf_object__close(info->bpf_obj);
}

/*
 * Forward packet: change MAC and send to other interface
 */
static int forward_packet(struct xsk_info *src, struct xsk_info *dst,
                          uint8_t *src_mac, uint8_t *dst_mac,
                          uint64_t *rx_cnt, uint64_t *tx_cnt) {
    __u32 rx_idx = 0;
    unsigned int n = xsk_ring_cons__peek(&src->rx, BATCH, &rx_idx);
    if (!n) return 0;

    /* Drain completion ring on destination */
    __u32 comp_idx;
    unsigned int done = xsk_ring_cons__peek(&dst->cq, FRAMES, &comp_idx);
    if (done > 0) xsk_ring_cons__release(&dst->cq, done);

    int forwarded = 0;

    for (unsigned int i = 0; i < n; i++) {
        struct xdp_desc *d = (struct xdp_desc *)xsk_ring_cons__rx_desc(&src->rx, rx_idx + i);
        uint8_t *pkt = xsk_umem__get_data(src->buf, d->addr);
        uint32_t len = d->len;

        (*rx_cnt)++;

        /* Print first few packets for debug */
        if (*rx_cnt <= 3) {
            struct ethhdr *eth = (struct ethhdr *)pkt;
            printf("[%s] RX #%lu: len=%u proto=0x%04x\n",
                   src->ifname, *rx_cnt, len, ntohs(eth->h_proto));
            if (ntohs(eth->h_proto) == ETH_P_IP && len >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                struct iphdr *ip = (struct iphdr *)(eth + 1);
                char sip[16], dip[16];
                inet_ntop(AF_INET, &ip->saddr, sip, sizeof(sip));
                inet_ntop(AF_INET, &ip->daddr, dip, sizeof(dip));
                printf("    IP: %s -> %s\n", sip, dip);
            }
        }

        /* Rewrite MAC addresses */
        struct ethhdr *eth = (struct ethhdr *)pkt;
        memcpy(eth->h_source, src_mac, 6);
        memcpy(eth->h_dest, dst_mac, 6);

        /* Send via destination TX ring */
        __u32 tx_idx;
        if (xsk_ring_prod__reserve(&dst->tx, 1, &tx_idx) == 1) {
            /* Copy packet to destination UMEM */
            /* Use simple addressing: frame index based on tx count */
            __u64 addr = ((*tx_cnt) % 256) * FSIZE;
            uint8_t *frame = xsk_umem__get_data(dst->buf, addr);
            memcpy(frame, pkt, len);

            struct xdp_desc *td = xsk_ring_prod__tx_desc(&dst->tx, tx_idx);
            td->addr = addr;
            td->len = len;

            xsk_ring_prod__submit(&dst->tx, 1);

            /* Kick TX */
            if (xsk_ring_prod__needs_wakeup(&dst->tx)) {
                sendto(xsk_socket__fd(dst->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            }

            (*tx_cnt)++;
            forwarded++;

            if (*tx_cnt <= 3) {
                printf("    -> [%s] TX #%lu OK\n", dst->ifname, *tx_cnt);
            }
        }
    }

    /* Return RX buffers to fill ring */
    __u32 fq_idx;
    if (xsk_ring_prod__reserve(&src->fq, n, &fq_idx) == n) {
        for (unsigned int i = 0; i < n; i++) {
            struct xdp_desc *d = (struct xdp_desc *)xsk_ring_cons__rx_desc(&src->rx, rx_idx + i);
            *xsk_ring_prod__fill_addr(&src->fq, fq_idx + i) = d->addr & ~(FSIZE - 1);
        }
        xsk_ring_prod__submit(&src->fq, n);
    }
    xsk_ring_cons__release(&src->rx, n);

    return forwarded;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("AF_XDP Tunnel\n");
        printf("Usage: %s <config_file> <wan_index>\n", argv[0]);
        printf("Example: %s config/server1.conf 1\n", argv[0]);
        return 1;
    }

    /* Suppress libbpf error messages */
    libbpf_set_print(silent_print);

    /* Setup */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) die("setrlimit");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load config */
    printf("=== AF_XDP Tunnel ===\n\n");
    printf("[CONFIG] Loading %s\n", argv[1]);
    if (load_config(argv[1]) < 0) die("config");

    int wan_idx = atoi(argv[2]);
    if (wan_idx >= num_wan) {
        fprintf(stderr, "Invalid WAN index %d (max %d)\n", wan_idx, num_wan - 1);
        return 1;
    }

    printf("  LOCAL: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", local_if,
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    printf("  CLIENT: %02x:%02x:%02x:%02x:%02x:%02x\n",
           client_mac[0], client_mac[1], client_mac[2],
           client_mac[3], client_mac[4], client_mac[5]);
    printf("  WAN[%d]: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", wan_idx, wan_if[wan_idx],
           wan_mac[wan_idx][0], wan_mac[wan_idx][1], wan_mac[wan_idx][2],
           wan_mac[wan_idx][3], wan_mac[wan_idx][4], wan_mac[wan_idx][5]);
    printf("  PEER: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", wan_peer_ip[wan_idx],
           wan_peer_mac[wan_idx][0], wan_peer_mac[wan_idx][1], wan_peer_mac[wan_idx][2],
           wan_peer_mac[wan_idx][3], wan_peer_mac[wan_idx][4], wan_peer_mac[wan_idx][5]);
    printf("\n");

    /* Setup XSK for LOCAL (with filter) */
    printf("[SETUP LOCAL]\n");
    if (setup_xsk(&local_xsk, local_if, 1) < 0) {
        fprintf(stderr, "Failed to setup LOCAL XSK\n");
        return 1;
    }

    /* Setup XSK for WAN (no filter - redirect all) */
    printf("\n[SETUP WAN]\n");
    if (setup_xsk(&wan_xsk, wan_if[wan_idx], 0) < 0) {
        fprintf(stderr, "Failed to setup WAN XSK\n");
        cleanup_xsk(&local_xsk);
        return 1;
    }

    printf("\n[RUNNING]\n");
    printf("  LOCAL RX -> WAN TX (src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x)\n",
           wan_mac[wan_idx][0], wan_mac[wan_idx][1], wan_mac[wan_idx][2],
           wan_mac[wan_idx][3], wan_mac[wan_idx][4], wan_mac[wan_idx][5],
           wan_peer_mac[wan_idx][0], wan_peer_mac[wan_idx][1], wan_peer_mac[wan_idx][2],
           wan_peer_mac[wan_idx][3], wan_peer_mac[wan_idx][4], wan_peer_mac[wan_idx][5]);
    printf("  WAN RX -> LOCAL TX (src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x)\n",
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5],
           client_mac[0], client_mac[1], client_mac[2],
           client_mac[3], client_mac[4], client_mac[5]);
    printf("  Press Ctrl+C to stop\n\n");

    /* Main loop */
    struct pollfd fds[2];
    fds[0].fd = xsk_socket__fd(local_xsk.xsk);
    fds[0].events = POLLIN;
    fds[1].fd = xsk_socket__fd(wan_xsk.xsk);
    fds[1].events = POLLIN;

    time_t last_stats = time(NULL);

    while (running) {
        poll(fds, 2, 100);

        /* LOCAL RX -> WAN TX */
        forward_packet(&local_xsk, &wan_xsk,
                       wan_mac[wan_idx], wan_peer_mac[wan_idx],
                       &local_rx_cnt, &wan_tx_cnt);

        /* WAN RX -> LOCAL TX */
        forward_packet(&wan_xsk, &local_xsk,
                       local_mac, client_mac,
                       &wan_rx_cnt, &local_tx_cnt);

        /* Print stats every 3 seconds */
        time_t now = time(NULL);
        if (now - last_stats >= 3) {
            printf("Stats: LOCAL_RX=%lu WAN_TX=%lu | WAN_RX=%lu LOCAL_TX=%lu\n",
                   local_rx_cnt, wan_tx_cnt, wan_rx_cnt, local_tx_cnt);
            last_stats = now;
        }
    }

    printf("\n[SHUTDOWN]\n");
    printf("Final: LOCAL_RX=%lu WAN_TX=%lu | WAN_RX=%lu LOCAL_TX=%lu\n",
           local_rx_cnt, wan_tx_cnt, wan_rx_cnt, local_tx_cnt);

    cleanup_xsk(&local_xsk);
    cleanup_xsk(&wan_xsk);

    printf("Done.\n");
    return 0;
}
