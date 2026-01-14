#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/if_arp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES  4096
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define MAX_WAN     3
#define WINDOW_SIZE 65536

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

// Config
static char local_if[32];
static int local_ifindex;
static uint32_t remote_net, remote_mask;
static int num_wan = 0;
static char wan_if[MAX_WAN][32];
static int wan_ifindex[MAX_WAN];
static int wan_fd[MAX_WAN];
static uint8_t wan_src_mac[MAX_WAN][6];
static uint8_t wan_dst_mac[MAX_WAN][6];
static int local_fd;
static uint8_t local_mac[6];

// BPF objects per interface
static struct bpf_object *local_obj;
static struct bpf_object *wan_obj[MAX_WAN];

// AF_XDP for local
static struct xsk_socket *local_xsk;
static struct xsk_ring_cons local_rx;
static struct xsk_ring_prod local_fq;
static struct xsk_umem *local_umem;
static void *local_buffer;

// AF_XDP for WANs
static struct xsk_socket *wan_xsk[MAX_WAN];
static struct xsk_ring_cons wan_rx[MAX_WAN];
static struct xsk_ring_prod wan_fq[MAX_WAN];
static struct xsk_umem *wan_umem[MAX_WAN];
static void *wan_buffer[MAX_WAN];

// Flow table
static struct { uint32_t bytes; int wan; } flow_table[10000];

static int get_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_peer_mac(const char *ifname, const char *ip, uint8_t *mac) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W1 -I %s %s >/dev/null 2>&1", ifname, ip);
    system(cmd);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct arpreq q = {0};
    ((struct sockaddr_in*)&q.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &((struct sockaddr_in*)&q.arp_pa)->sin_addr);
    strncpy(q.arp_dev, ifname, 15);
    int ret = ioctl(fd, SIOCGARP, &q);
    close(fd);
    if (!ret) memcpy(mac, q.arp_ha.sa_data, 6);
    return ret;
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256], key[32], v1[64], v2[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v2[0] = 0;
        int n = sscanf(line, "%s %s %s", key, v1, v2);
        if (n < 2) continue;
        if (!strcmp(key, "local")) {
            strcpy(local_if, v1);
            local_ifindex = if_nametoindex(v1);
            get_mac(v1, local_mac);
        } else if (!strcmp(key, "remote")) {
            char *sl = strchr(v1, '/');
            int pfx = 24;
            if (sl) { *sl = 0; pfx = atoi(sl+1); }
            remote_net = ntohl(inet_addr(v1));
            remote_mask = 0xFFFFFFFF << (32 - pfx);
        } else if (!strcmp(key, "wan") && num_wan < MAX_WAN) {
            strcpy(wan_if[num_wan], v1);
            wan_ifindex[num_wan] = if_nametoindex(v1);
            get_mac(v1, wan_src_mac[num_wan]);
            if (v2[0]) get_peer_mac(v1, v2, wan_dst_mac[num_wan]);
            num_wan++;
        }
    }
    fclose(f);
    return num_wan > 0 ? 0 : -1;
}

static int create_raw_socket(const char *ifname, int ifindex) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(fd, (struct sockaddr*)&sll, sizeof(sll));
    return fd;
}

static int setup_xsk(const char *ifname, int xsk_map_fd,
                     struct xsk_socket **xsk, struct xsk_ring_cons *rx,
                     struct xsk_ring_prod *fq, struct xsk_umem **umem, void **buffer) {
    posix_memalign(buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE);

    struct xsk_umem_config ucfg = { .fill_size = NUM_FRAMES, .comp_size = NUM_FRAMES, .frame_size = FRAME_SIZE };
    struct xsk_ring_cons comp;
    xsk_umem__create(umem, *buffer, NUM_FRAMES * FRAME_SIZE, fq, &comp, &ucfg);

    struct xsk_socket_config xcfg = {
        .rx_size = NUM_FRAMES, .tx_size = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    };
    struct xsk_ring_prod tx;
    if (xsk_socket__create(xsk, ifname, 0, *umem, rx, &tx, &xcfg) < 0) return -1;

    int fd = xsk_socket__fd(*xsk);
    uint32_t idx = 0;
    bpf_map_update_elem(xsk_map_fd, &idx, &fd, BPF_ANY);

    uint32_t fidx;
    xsk_ring_prod__reserve(fq, NUM_FRAMES, &fidx);
    for (uint32_t i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(fq, fidx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(fq, NUM_FRAMES);

    return 0;
}

static int attach_xdp(const char *bpf_path, int ifindex, uint32_t direction,
                      struct bpf_object **obj_out, int *xsk_map_fd) {
    struct bpf_object *obj = bpf_object__open_file(bpf_path, NULL);
    if (libbpf_get_error(obj)) return -1;
    if (bpf_object__load(obj)) { bpf_object__close(obj); return -1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_to_user");
    int cfg_map = bpf_object__find_map_fd_by_name(obj, "config");
    *xsk_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    if (!prog || cfg_map < 0 || *xsk_map_fd < 0) { bpf_object__close(obj); return -1; }

    uint32_t k = 0, v = remote_net;
    bpf_map_update_elem(cfg_map, &k, &v, BPF_ANY);
    k = 1; v = remote_mask;
    bpf_map_update_elem(cfg_map, &k, &v, BPF_ANY);
    k = 2; v = direction;
    bpf_map_update_elem(cfg_map, &k, &v, BPF_ANY);

    if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(prog), 0) < 0) {
        bpf_object__close(obj);
        return -1;
    }

    *obj_out = obj;
    return 0;
}

static int select_wan(uint8_t *pkt, int len) {
    struct iphdr *ip = (struct iphdr*)(pkt + 14);
    uint32_t h = (ip->saddr ^ ip->daddr) % 10000;
    flow_table[h].bytes += ntohs(ip->tot_len);
    if (flow_table[h].bytes >= WINDOW_SIZE) {
        flow_table[h].wan = (flow_table[h].wan + 1) % num_wan;
        flow_table[h].bytes = 0;
    }
    return flow_table[h].wan;
}

static void process_local_rx(void) {
    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&local_rx, 64, &idx);
    if (rcvd == 0) return;

    for (uint32_t i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&local_rx, idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&local_rx, idx + i)->len;
        uint8_t *pkt = xsk_umem__get_data(local_buffer, addr);

        int w = select_wan(pkt, len);
        memcpy(pkt, wan_dst_mac[w], 6);
        memcpy(pkt + 6, wan_src_mac[w], 6);

        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = wan_ifindex[w];
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, wan_dst_mac[w], 6);
        sendto(wan_fd[w], pkt, len, 0, (struct sockaddr*)&sll, sizeof(sll));

        uint32_t fidx;
        if (xsk_ring_prod__reserve(&local_fq, 1, &fidx)) {
            *xsk_ring_prod__fill_addr(&local_fq, fidx) = addr;
            xsk_ring_prod__submit(&local_fq, 1);
        }
    }
    xsk_ring_cons__release(&local_rx, rcvd);
}

static void process_wan_rx(int w) {
    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&wan_rx[w], 64, &idx);
    if (rcvd == 0) return;

    for (uint32_t i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&wan_rx[w], idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&wan_rx[w], idx + i)->len;
        uint8_t *pkt = xsk_umem__get_data(wan_buffer[w], addr);

        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = local_ifindex;
        sendto(local_fd, pkt, len, 0, (struct sockaddr*)&sll, sizeof(sll));

        uint32_t fidx;
        if (xsk_ring_prod__reserve(&wan_fq[w], 1, &fidx)) {
            *xsk_ring_prod__fill_addr(&wan_fq[w], fidx) = addr;
            xsk_ring_prod__submit(&wan_fq[w], 1);
        }
    }
    xsk_ring_cons__release(&wan_rx[w], rcvd);
}

static void cleanup(void) {
    if (local_ifindex) bpf_set_link_xdp_fd(local_ifindex, -1, 0);
    if (local_xsk) xsk_socket__delete(local_xsk);
    if (local_umem) xsk_umem__delete(local_umem);
    if (local_buffer) free(local_buffer);
    if (local_obj) bpf_object__close(local_obj);

    for (int i = 0; i < num_wan; i++) {
        if (wan_ifindex[i]) bpf_set_link_xdp_fd(wan_ifindex[i], -1, 0);
        if (wan_xsk[i]) xsk_socket__delete(wan_xsk[i]);
        if (wan_umem[i]) xsk_umem__delete(wan_umem[i]);
        if (wan_buffer[i]) free(wan_buffer[i]);
        if (wan_obj[i]) bpf_object__close(wan_obj[i]);
        if (wan_fd[i] > 0) close(wan_fd[i]);
    }
    if (local_fd > 0) close(local_fd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <config> [bpf.o]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (load_config(argv[1]) < 0) {
        fprintf(stderr, "Config error\n");
        return 1;
    }

    const char *bpf_path = argc >= 3 ? argv[2] : "./tunnel.bpf.o";

    local_fd = create_raw_socket(local_if, local_ifindex);
    for (int i = 0; i < num_wan; i++)
        wan_fd[i] = create_raw_socket(wan_if[i], wan_ifindex[i]);

    int local_xsk_map;
    if (attach_xdp(bpf_path, local_ifindex, 0, &local_obj, &local_xsk_map) < 0) {
        cleanup();
        return 1;
    }

    setup_xsk(local_if, local_xsk_map, &local_xsk, &local_rx,
              &local_fq, &local_umem, &local_buffer);

    for (int i = 0; i < num_wan; i++) {
        int wan_xsk_map;
        attach_xdp(bpf_path, wan_ifindex[i], 1, &wan_obj[i], &wan_xsk_map);
        setup_xsk(wan_if[i], wan_xsk_map, &wan_xsk[i],
                  &wan_rx[i], &wan_fq[i], &wan_umem[i], &wan_buffer[i]);
    }

    while (running) {
        process_local_rx();
        for (int i = 0; i < num_wan; i++)
            process_wan_rx(i);
        usleep(100);
    }

    cleanup();
    return 0;
}

