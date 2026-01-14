/*
 * tunnel_main.c - XDP Tunnel with AES Encryption + Load Balancing
 *
 * Luồng:
 *   TX: XDP bắt packet → AF_XDP → mã hóa AES → load balance → gửi ra WAN
 *   RX: XDP bắt packet → AF_XDP → giải mã AES → gửi vào LAN
 *
 * Compile:
 *   gcc -O2 -DAES256=1 tunnel_main.c tiny-AES-c/aes.c -o tunnel_main -lbpf -lxdp -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <poll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

// tiny-AES-c
#include "tiny-AES-c/aes.h"

// ============================================================================
//                              CONFIG
// ============================================================================

#define NUM_FRAMES      4096
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      64
#define MAX_WAN         3
#define WINDOW_SIZE     65536  // 64KB per WAN

// AES Key - THAY ĐỔI KEY NÀY
static uint8_t AES_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static uint8_t AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// ============================================================================
//                              STRUCTURES
// ============================================================================

static volatile int running = 1;

struct xsk_info {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct wan_info {
    char name[32];
    int ifindex;
    int raw_fd;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    char peer_ip[32];
};

struct flow_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

struct flow_state {
    int current_wan;
    uint32_t bytes_in_window;
};

struct config {
    char local_name[32];
    int local_ifindex;
    int local_raw_fd;
    uint8_t local_mac[6];
    uint32_t remote_net;
    uint32_t remote_mask;
    int num_wan;
    struct wan_info wan[MAX_WAN];
    struct xsk_info *local_xsk;
    struct xsk_info *wan_xsk[MAX_WAN];
};

static struct config cfg;
static struct bpf_object *bpf_obj;
static struct AES_ctx aes_ctx;

// Simple flow table (hash map simulation)
#define FLOW_TABLE_SIZE 10000
static struct flow_state flow_table[FLOW_TABLE_SIZE];

// ============================================================================
//                         HELPER FUNCTIONS
// ============================================================================

static void sig_handler(int sig) { (void)sig; running = 0; }

static uint32_t flow_hash(struct flow_key *key) {
    uint32_t h = key->saddr ^ key->daddr ^ ((uint32_t)key->sport << 16 | key->dport);
    return h % FLOW_TABLE_SIZE;
}

static int get_mac(const char *ifname, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_peer_mac(const char *ifname, const char *ip, uint8_t *mac) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W1 -I %s %s >/dev/null 2>&1", ifname, ip);
    system(cmd);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct arpreq q = {0};
    ((struct sockaddr_in*)&q.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &((struct sockaddr_in*)&q.arp_pa)->sin_addr);
    strncpy(q.arp_dev, ifname, sizeof(q.arp_dev) - 1);
    int ret = ioctl(fd, SIOCGARP, &q);
    close(fd);
    if (!ret) memcpy(mac, q.arp_ha.sa_data, 6);
    return ret;
}

static int create_raw_socket(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(ifname);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    return fd;
}

// ============================================================================
//                         AES ENCRYPTION
// ============================================================================

static int pad_pkcs7(uint8_t *buf, int len, int max_len) {
    int pad = 16 - (len % 16);
    if (len + pad > max_len) return -1;
    for (int i = 0; i < pad; i++) buf[len + i] = pad;
    return len + pad;
}

static int unpad_pkcs7(uint8_t *buf, int len) {
    if (len == 0) return 0;
    int pad = buf[len - 1];
    if (pad > 16 || pad > len) return len;
    return len - pad;
}

/*
 * encrypt_packet - Hook mã hóa packet
 *
 * Khi ENABLE_ENCRYPTION=1: Mã hóa payload bằng AES-CBC
 * Khi không định nghĩa: Pass-through (copy nguyên packet)
 *
 * Params:
 *   pkt - Packet gốc (Ethernet + IP + payload)
 *   len - Độ dài packet
 *   out - Buffer output
 *
 * Return: Độ dài packet sau xử lý
 */
static int encrypt_packet(uint8_t *pkt, int len, uint8_t *out) {
#ifdef ENABLE_ENCRYPTION
    if (len < 34) { memcpy(out, pkt, len); return len; }

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    int ip_hdr_len = ip->ihl * 4;
    int hdr_len = sizeof(struct ethhdr) + ip_hdr_len;

    // Copy headers
    memcpy(out, pkt, hdr_len);

    // Encrypt payload
    int payload_len = len - hdr_len;
    if (payload_len > 0) {
        uint8_t temp[2048];
        memcpy(temp, pkt + hdr_len, payload_len);
        int padded = pad_pkcs7(temp, payload_len, sizeof(temp));
        if (padded < 0) { memcpy(out, pkt, len); return len; }

        AES_ctx_set_iv(&aes_ctx, AES_IV);
        AES_CBC_encrypt_buffer(&aes_ctx, temp, padded);
        memcpy(out + hdr_len, temp, padded);

        // Update IP length
        struct iphdr *out_ip = (struct iphdr *)(out + sizeof(struct ethhdr));
        out_ip->tot_len = htons(ip_hdr_len + padded);
        out_ip->check = 0;
        uint32_t sum = 0;
        uint16_t *p = (uint16_t *)out_ip;
        for (int i = 0; i < ip_hdr_len/2; i++) sum += p[i];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        out_ip->check = ~sum;

        return hdr_len + padded;
    }
    return len;
#else
    // Pass-through: Copy nguyên packet, không mã hóa
    memcpy(out, pkt, len);
    return len;
#endif
}

/*
 * decrypt_packet - Hook giải mã packet
 *
 * Khi ENABLE_ENCRYPTION=1: Giải mã payload bằng AES-CBC
 * Khi không định nghĩa: Pass-through (copy nguyên packet)
 *
 * Params:
 *   pkt - Packet đã mã hóa (Ethernet + IP + encrypted payload)
 *   len - Độ dài packet
 *   out - Buffer output
 *
 * Return: Độ dài packet sau xử lý
 */
static int decrypt_packet(uint8_t *pkt, int len, uint8_t *out) {
#ifdef ENABLE_ENCRYPTION
    if (len < 34) { memcpy(out, pkt, len); return len; }

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    int ip_hdr_len = ip->ihl * 4;
    int hdr_len = sizeof(struct ethhdr) + ip_hdr_len;

    // Copy headers
    memcpy(out, pkt, hdr_len);

    // Decrypt payload
    int payload_len = len - hdr_len;
    if (payload_len > 0 && payload_len % 16 == 0) {
        uint8_t temp[2048];
        memcpy(temp, pkt + hdr_len, payload_len);

        AES_ctx_set_iv(&aes_ctx, AES_IV);
        AES_CBC_decrypt_buffer(&aes_ctx, temp, payload_len);
        int unpadded = unpad_pkcs7(temp, payload_len);
        memcpy(out + hdr_len, temp, unpadded);

        // Update IP length
        struct iphdr *out_ip = (struct iphdr *)(out + sizeof(struct ethhdr));
        out_ip->tot_len = htons(ip_hdr_len + unpadded);
        out_ip->check = 0;
        uint32_t sum = 0;
        uint16_t *p = (uint16_t *)out_ip;
        for (int i = 0; i < ip_hdr_len/2; i++) sum += p[i];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        out_ip->check = ~sum;

        return hdr_len + unpadded;
    }
    memcpy(out + hdr_len, pkt + hdr_len, payload_len);
    return len;
#else
    // Pass-through: Copy nguyên packet, không giải mã
    memcpy(out, pkt, len);
    return len;
#endif
}

// ============================================================================
//                         LOAD BALANCING
// ============================================================================

static int select_wan(uint8_t *pkt, int len) {
    if (len < 34) return 0;

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    int ip_hdr_len = ip->ihl * 4;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    // Get ports if TCP/UDP
    if (ip->protocol == IPPROTO_TCP && len >= (int)(sizeof(struct ethhdr) + ip_hdr_len + 4)) {
        uint16_t *ports = (uint16_t *)(pkt + sizeof(struct ethhdr) + ip_hdr_len);
        key.sport = ports[0];
        key.dport = ports[1];
    } else if (ip->protocol == IPPROTO_UDP && len >= (int)(sizeof(struct ethhdr) + ip_hdr_len + 4)) {
        uint16_t *ports = (uint16_t *)(pkt + sizeof(struct ethhdr) + ip_hdr_len);
        key.sport = ports[0];
        key.dport = ports[1];
    }

    uint32_t h = flow_hash(&key);
    struct flow_state *state = &flow_table[h];

    int payload_len = ntohs(ip->tot_len);
    state->bytes_in_window += payload_len;

    if (state->bytes_in_window >= WINDOW_SIZE) {
        state->current_wan = (state->current_wan + 1) % cfg.num_wan;
        state->bytes_in_window = 0;
    }

    return state->current_wan;
}

// ============================================================================
//                         AF_XDP SETUP
// ============================================================================

static struct xsk_info *create_xsk(const char *ifname, int queue, int map_fd) {
    struct xsk_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;

    if (posix_memalign(&xsk->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        free(xsk);
        return NULL;
    }

    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };

    if (xsk_umem__create(&xsk->umem, xsk->buffer, NUM_FRAMES * FRAME_SIZE,
                         &xsk->fq, &xsk->cq, &umem_cfg)) {
        free(xsk->buffer);
        free(xsk);
        return NULL;
    }

    struct xsk_socket_config xsk_cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_USE_NEED_WAKEUP,
    };

    if (xsk_socket__create(&xsk->xsk, ifname, queue, xsk->umem, &xsk->rx, &xsk->tx, &xsk_cfg)) {
        xsk_umem__delete(xsk->umem);
        free(xsk->buffer);
        free(xsk);
        return NULL;
    }

    int fd = xsk_socket__fd(xsk->xsk);
    bpf_map_update_elem(map_fd, &queue, &fd, BPF_ANY);

    // Fill ring
    uint32_t idx;
    xsk_ring_prod__reserve(&xsk->fq, NUM_FRAMES, &idx);
    for (uint32_t i = 0; i < NUM_FRAMES; i++)
        *xsk_ring_prod__fill_addr(&xsk->fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&xsk->fq, NUM_FRAMES);

    return xsk;
}

static void destroy_xsk(struct xsk_info *xsk) {
    if (!xsk) return;
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(xsk->umem);
    free(xsk->buffer);
    free(xsk);
}

// ============================================================================
//                         PACKET PROCESSING
// ============================================================================

// Process TX: LAN → encrypt → load balance → WAN
static void process_tx(void) {
    if (!cfg.local_xsk) return;

    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&cfg.local_xsk->rx, BATCH_SIZE, &idx);
    if (rcvd == 0) return;

    static uint8_t out[4096];

    for (uint32_t i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&cfg.local_xsk->rx, idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&cfg.local_xsk->rx, idx + i)->len;
        uint8_t *pkt = xsk_umem__get_data(cfg.local_xsk->buffer, addr);

        // 1. Mã hóa packet
        int enc_len = encrypt_packet(pkt, len, out);

        // 2. Load balance chọn WAN
        int wan_idx = select_wan(pkt, len);
        struct wan_info *wan = &cfg.wan[wan_idx];

        // 3. Set MAC và gửi ra WAN
        struct ethhdr *eth = (struct ethhdr *)out;
        memcpy(eth->h_source, wan->src_mac, 6);
        memcpy(eth->h_dest, wan->dst_mac, 6);

        send(wan->raw_fd, out, enc_len, 0);

        // Return frame
        uint32_t fq_idx;
        if (xsk_ring_prod__reserve(&cfg.local_xsk->fq, 1, &fq_idx)) {
            *xsk_ring_prod__fill_addr(&cfg.local_xsk->fq, fq_idx) = addr;
            xsk_ring_prod__submit(&cfg.local_xsk->fq, 1);
        }
    }
    xsk_ring_cons__release(&cfg.local_xsk->rx, rcvd);
}

// Process RX: WAN → decrypt → LAN
static void process_rx(int wan_idx) {
    struct xsk_info *xsk = cfg.wan_xsk[wan_idx];
    if (!xsk) return;

    uint32_t idx = 0;
    uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx);
    if (rcvd == 0) return;

    static uint8_t out[4096];

    for (uint32_t i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx + i)->len;
        uint8_t *pkt = xsk_umem__get_data(xsk->buffer, addr);

        // 1. Giải mã packet
        int dec_len = decrypt_packet(pkt, len, out);

        // 2. Gửi vào LAN
        // TODO: Set MAC đúng cho destination trong LAN
        send(cfg.local_raw_fd, out, dec_len, 0);

        // Return frame
        uint32_t fq_idx;
        if (xsk_ring_prod__reserve(&xsk->fq, 1, &fq_idx)) {
            *xsk_ring_prod__fill_addr(&xsk->fq, fq_idx) = addr;
            xsk_ring_prod__submit(&xsk->fq, 1);
        }
    }
    xsk_ring_cons__release(&xsk->rx, rcvd);
}

// ============================================================================
//                         CONFIG LOADER
// ============================================================================

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    memset(&cfg, 0, sizeof(cfg));
    char line[256], key[32], v1[64], v2[64];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v2[0] = 0;
        int n = sscanf(line, "%31s %63s %63s", key, v1, v2);
        if (n < 2) continue;

        if (!strcmp(key, "local")) {
            strncpy(cfg.local_name, v1, 31);
            cfg.local_ifindex = if_nametoindex(v1);
            get_mac(v1, cfg.local_mac);
        } else if (!strcmp(key, "remote")) {
            char buf[64]; strncpy(buf, v1, 63);
            char *sl = strchr(buf, '/');
            int pfx = 24;
            if (sl) { *sl = 0; pfx = atoi(sl + 1); }
            cfg.remote_net = ntohl(inet_addr(buf));
            cfg.remote_mask = pfx ? (0xFFFFFFFF << (32 - pfx)) : 0;
        } else if (!strcmp(key, "wan") && cfg.num_wan < MAX_WAN) {
            struct wan_info *w = &cfg.wan[cfg.num_wan++];
            strncpy(w->name, v1, 31);
            w->ifindex = if_nametoindex(v1);
            get_mac(v1, w->src_mac);
            if (n >= 3) {
                strncpy(w->peer_ip, v2, 31);
                get_peer_mac(v1, v2, w->dst_mac);
            }
        }
    }
    fclose(f);
    return cfg.num_wan > 0 ? 0 : -1;
}

// ============================================================================
//                              MAIN
// ============================================================================

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <config> <bpf.o>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load config
    if (load_config(argv[1]) < 0) {
        fprintf(stderr, "Config error\n");
        return 1;
    }

    printf("========================================\n");
#ifdef ENABLE_ENCRYPTION
    printf("  XDP Tunnel + AES-%d + Load Balancer\n", AES_KEYLEN * 8);
#else
    printf("  XDP Tunnel + Load Balancer (No Encryption)\n");
#endif
    printf("========================================\n");
    printf("Local: %s\n", cfg.local_name);
    printf("Remote: %u.%u.%u.%u/%d\n",
           (cfg.remote_net>>24)&0xff, (cfg.remote_net>>16)&0xff,
           (cfg.remote_net>>8)&0xff, cfg.remote_net&0xff,
           __builtin_popcount(cfg.remote_mask));
    printf("WANs: %d\n", cfg.num_wan);
    for (int i = 0; i < cfg.num_wan; i++)
        printf("  [%d] %s -> %s\n", i, cfg.wan[i].name, cfg.wan[i].peer_ip);
#ifdef ENABLE_ENCRYPTION
    printf("Encryption: AES-%d-CBC ENABLED\n", AES_KEYLEN * 8);
#else
    printf("Encryption: DISABLED (pass-through)\n");
#endif
    printf("\n");

#ifdef ENABLE_ENCRYPTION
    // Init AES context
    AES_init_ctx_iv(&aes_ctx, AES_KEY, AES_IV);
#endif

    // Load BPF
    bpf_obj = bpf_object__open_file(argv[2], NULL);
    if (libbpf_get_error(bpf_obj)) { fprintf(stderr, "BPF open error\n"); return 1; }
    if (bpf_object__load(bpf_obj)) { fprintf(stderr, "BPF load error\n"); return 1; }

    int xsk_map = bpf_object__find_map_fd_by_name(bpf_obj, "xsks_map");
    int cfg_map = bpf_object__find_map_fd_by_name(bpf_obj, "config");
    struct bpf_program *prog_tx = bpf_object__find_program_by_name(bpf_obj, "xdp_tx");
    struct bpf_program *prog_rx = bpf_object__find_program_by_name(bpf_obj, "xdp_rx");

    if (xsk_map < 0 || cfg_map < 0 || !prog_tx || !prog_rx) {
        fprintf(stderr, "BPF map/program not found\n");
        return 1;
    }

    // Update config map
    uint32_t k, v;
    k = 1; v = cfg.remote_net;  bpf_map_update_elem(cfg_map, &k, &v, BPF_ANY);
    k = 2; v = cfg.remote_mask; bpf_map_update_elem(cfg_map, &k, &v, BPF_ANY);

    // Create raw sockets
    cfg.local_raw_fd = create_raw_socket(cfg.local_name);
    for (int i = 0; i < cfg.num_wan; i++)
        cfg.wan[i].raw_fd = create_raw_socket(cfg.wan[i].name);

    // Attach XDP and create AF_XDP sockets
    if (bpf_xdp_attach(cfg.local_ifindex, bpf_program__fd(prog_tx), 0, NULL) < 0) {
        fprintf(stderr, "XDP attach failed: %s\n", cfg.local_name);
        return 1;
    }
    cfg.local_xsk = create_xsk(cfg.local_name, 0, xsk_map);
    printf("XDP + AF_XDP: %s (local)\n", cfg.local_name);

    for (int i = 0; i < cfg.num_wan; i++) {
        if (bpf_xdp_attach(cfg.wan[i].ifindex, bpf_program__fd(prog_rx), 0, NULL) < 0) {
            fprintf(stderr, "XDP attach failed: %s\n", cfg.wan[i].name);
        } else {
            cfg.wan_xsk[i] = create_xsk(cfg.wan[i].name, 0, xsk_map);
            printf("XDP + AF_XDP: %s (wan)\n", cfg.wan[i].name);
        }
    }

    printf("\nRunning... Ctrl+C to stop\n\n");

    // Main loop
    while (running) {
        process_tx();
        for (int i = 0; i < cfg.num_wan; i++)
            process_rx(i);
        usleep(100);  // Small delay to reduce CPU
    }

    // Cleanup
    printf("\nStopping...\n");
    bpf_xdp_detach(cfg.local_ifindex, 0, NULL);
    destroy_xsk(cfg.local_xsk);
    for (int i = 0; i < cfg.num_wan; i++) {
        bpf_xdp_detach(cfg.wan[i].ifindex, 0, NULL);
        destroy_xsk(cfg.wan_xsk[i]);
    }
    bpf_object__close(bpf_obj);
    printf("Done.\n");
    return 0;
}

