// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel Loader - TCP/UDP (Refactored)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef bpf_xdp_attach
#define bpf_xdp_attach(ifindex, fd, flags, opts) bpf_set_link_xdp_fd(ifindex, fd, flags)
#define bpf_xdp_detach(ifindex, flags, opts) bpf_set_link_xdp_fd(ifindex, -1, flags)
#endif

#define MAX_WAN 3

// ==================== Data Structures ====================

struct wan_info {
    char iface[32];
    __u32 ifindex;
    __u8 my_mac[6];
    __u8 peer_mac[6];
    char peer_ip[32];
    int active;  // For future health check
};

struct tunnel_config {
    char local_iface[32];
    __u32 local_ifindex;
    __u8 local_mac[6];
    __u32 remote_net;
    __u32 remote_mask;
    int nwan;
    struct wan_info wan[MAX_WAN];
};

struct bpf_context {
    struct bpf_object *obj;
    int config_fd;
    int macs_fd;
    int arp_fd;
    int tx_fd;
    int rx_fd;
};

// ==================== Global State ====================

static volatile int g_running = 1;
static struct tunnel_config g_cfg = {0};
static struct bpf_context g_bpf = {0};

// ==================== Signal Handler ====================

void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

// ==================== MAC Utilities ====================

int get_iface_mac(const char *iface, __u8 *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    if (ret < 0) return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int resolve_peer_mac(const char *iface, const char *peer_ip, __u8 *mac) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 -I %s %s >/dev/null 2>&1", iface, peer_ip);
    system(cmd);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct arpreq req = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, peer_ip, &sin->sin_addr);
    strncpy(req.arp_dev, iface, sizeof(req.arp_dev) - 1);

    int ret = ioctl(fd, SIOCGARP, &req);
    close(fd);

    if (ret < 0) return -1;
    memcpy(mac, req.arp_ha.sa_data, 6);
    return 0;
}

__u64 mac_to_u64(const __u8 *mac) {
    return ((__u64)mac[0]) | ((__u64)mac[1] << 8) | ((__u64)mac[2] << 16) |
           ((__u64)mac[3] << 24) | ((__u64)mac[4] << 32) | ((__u64)mac[5] << 40);
}

void print_mac(const __u8 *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ==================== Config Parser ====================

static int parse_cidr(const char *s, __u32 *ip, __u32 *mask) {
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    *ip = ntohl(inet_addr(buf));
    *mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    return 0;
}

static int parse_local(const char *val) {
    strncpy(g_cfg.local_iface, val, sizeof(g_cfg.local_iface) - 1);
    g_cfg.local_ifindex = if_nametoindex(val);
    return get_iface_mac(val, g_cfg.local_mac);
}

static int parse_remote(const char *val) {
    return parse_cidr(val, &g_cfg.remote_net, &g_cfg.remote_mask);
}

static int parse_wan(const char *iface, const char *peer_ip) {
    if (g_cfg.nwan >= MAX_WAN) return -1;

    struct wan_info *wan = &g_cfg.wan[g_cfg.nwan];
    strncpy(wan->iface, iface, sizeof(wan->iface) - 1);
    wan->ifindex = if_nametoindex(iface);
    wan->active = 1;
    get_iface_mac(iface, wan->my_mac);

    if (peer_ip && strlen(peer_ip) > 0) {
        strncpy(wan->peer_ip, peer_ip, sizeof(wan->peer_ip) - 1);
        resolve_peer_mac(iface, peer_ip, wan->peer_mac);
    }

    g_cfg.nwan++;
    return 0;
}

int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[32], val1[64], val2[64] = {0};
        int n = sscanf(line, "%31s %63s %63s", key, val1, val2);
        if (n < 2) continue;

        if (!strcmp(key, "local")) {
            parse_local(val1);
        } else if (!strcmp(key, "remote")) {
            parse_remote(val1);
        } else if (!strcmp(key, "wan")) {
            parse_wan(val1, n >= 3 ? val2 : NULL);
        }
    }

    fclose(f);
    return (g_cfg.nwan > 0) ? 0 : -1;
}

// ==================== Config Display ====================

void print_config(void) {
    printf("=== XDP Tunnel (TCP/UDP) ===\n");
    printf("Local: %s (ifindex=%d)\n", g_cfg.local_iface, g_cfg.local_ifindex);
    printf("  MAC: ");
    print_mac(g_cfg.local_mac);
    printf("\n");

    printf("Remote: %d.%d.%d.%d/%d\n",
           (g_cfg.remote_net >> 24) & 0xFF,
           (g_cfg.remote_net >> 16) & 0xFF,
           (g_cfg.remote_net >> 8) & 0xFF,
           g_cfg.remote_net & 0xFF,
           __builtin_popcount(g_cfg.remote_mask));

    printf("WANs: %d\n", g_cfg.nwan);

    for (int i = 0; i < g_cfg.nwan; i++) {
        struct wan_info *wan = &g_cfg.wan[i];
        printf("[WAN %d] %s (ifindex=%d)\n", i, wan->iface, wan->ifindex);
        printf("  My MAC:   ");
        print_mac(wan->my_mac);
        printf("\n");
        printf("  Peer IP:  %s\n", wan->peer_ip);
        printf("  Peer MAC: ");
        print_mac(wan->peer_mac);
        printf("\n");
    }
}

// ==================== BPF Loading ====================

int bpf_load_object(const char *bpf_file) {
    g_bpf.obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(g_bpf.obj)) {
        fprintf(stderr, "Error: Failed to open %s\n", bpf_file);
        return -1;
    }

    if (bpf_object__load(g_bpf.obj)) {
        fprintf(stderr, "Error: Failed to load BPF object\n");
        bpf_object__close(g_bpf.obj);
        g_bpf.obj = NULL;
        return -1;
    }

    return 0;
}

int bpf_find_maps(void) {
    g_bpf.config_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "config");
    g_bpf.macs_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "macs");
    g_bpf.arp_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "arp_cache");

    if (g_bpf.config_fd < 0) {
        fprintf(stderr, "Error: config map not found\n");
        return -1;
    }
    if (g_bpf.macs_fd < 0) {
        fprintf(stderr, "Error: macs map not found\n");
        return -1;
    }

    return 0;
}

int bpf_find_programs(void) {
    struct bpf_program *tx_prog = bpf_object__find_program_by_name(g_bpf.obj, "xdp_tx");
    struct bpf_program *rx_prog = bpf_object__find_program_by_name(g_bpf.obj, "xdp_rx");

    if (!tx_prog || !rx_prog) {
        fprintf(stderr, "Error: XDP programs not found\n");
        return -1;
    }

    g_bpf.tx_fd = bpf_program__fd(tx_prog);
    g_bpf.rx_fd = bpf_program__fd(rx_prog);

    return 0;
}

// ==================== BPF Map Population ====================

int populate_config_map(void) {
    __u32 key, val;

    key = 0; val = g_cfg.nwan;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);

    key = 1; val = g_cfg.remote_net;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);

    key = 2; val = g_cfg.remote_mask;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);

    key = 3; val = g_cfg.local_ifindex;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);

    for (int i = 0; i < g_cfg.nwan; i++) {
        key = 4 + i;
        val = g_cfg.wan[i].ifindex;
        bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);
    }

    return 0;
}

int populate_macs_map(void) {
    __u32 key;
    __u64 mac_val;

    // WAN source MACs (0, 1, 2)
    for (int i = 0; i < g_cfg.nwan; i++) {
        key = i;
        mac_val = mac_to_u64(g_cfg.wan[i].my_mac);
        bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);
    }

    // WAN dest MACs (3, 4, 5)
    for (int i = 0; i < g_cfg.nwan; i++) {
        key = i + MAX_WAN;
        mac_val = mac_to_u64(g_cfg.wan[i].peer_mac);
        bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);
    }

    // Local MAC (6)
    key = 6;
    mac_val = mac_to_u64(g_cfg.local_mac);
    bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);

    return 0;
}

// ==================== XDP Attach/Detach ====================

void xdp_detach_all(void) {
    if (g_cfg.local_ifindex > 0)
        bpf_xdp_detach(g_cfg.local_ifindex, 0, NULL);

    for (int i = 0; i < g_cfg.nwan; i++) {
        if (g_cfg.wan[i].ifindex > 0)
            bpf_xdp_detach(g_cfg.wan[i].ifindex, 0, NULL);
    }
}

int xdp_attach_local(void) {
    if (bpf_xdp_attach(g_cfg.local_ifindex, g_bpf.tx_fd, 0, NULL) < 0) {
        fprintf(stderr, "Error: Failed to attach to %s: %s\n",
                g_cfg.local_iface, strerror(errno));
        return -1;
    }
    printf("Attached TX to %s\n", g_cfg.local_iface);
    return 0;
}

int xdp_attach_wans(void) {
    for (int i = 0; i < g_cfg.nwan; i++) {
        if (bpf_xdp_attach(g_cfg.wan[i].ifindex, g_bpf.rx_fd, 0, NULL) < 0) {
            fprintf(stderr, "Error: Failed to attach to %s: %s\n",
                    g_cfg.wan[i].iface, strerror(errno));
            return -1;
        }
        printf("Attached RX to %s\n", g_cfg.wan[i].iface);
    }
    return 0;
}

// ==================== ARP Thread ====================

void *arp_update_thread(void *arg) {
    (void)arg;

    if (g_bpf.arp_fd < 0) return NULL;

    while (g_running) {
        FILE *fp = fopen("/proc/net/arp", "r");
        if (!fp) {
            sleep(2);
            continue;
        }

        char line[256];
        fgets(line, sizeof(line), fp);  // Skip header

        while (fgets(line, sizeof(line), fp)) {
            char ip_str[32], hw[16], flags[16], mac_str[32], mask[16], iface[32];

            if (sscanf(line, "%31s %15s %15s %31s %15s %31s",
                       ip_str, hw, flags, mac_str, mask, iface) != 6)
                continue;

            int f = (int)strtol(flags, NULL, 16);
            if (!(f & 0x02)) continue;
            if (strcmp(iface, g_cfg.local_iface) != 0) continue;

            __u32 ip = ntohl(inet_addr(ip_str));
            unsigned int mb[6];
            if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                       &mb[0], &mb[1], &mb[2], &mb[3], &mb[4], &mb[5]) == 6) {
                __u64 mac = 0;
                for (int i = 0; i < 6; i++)
                    mac |= ((__u64)mb[i]) << (i * 8);
                bpf_map_update_elem(g_bpf.arp_fd, &ip, &mac, BPF_ANY);
            }
        }

        fclose(fp);
        sleep(2);
    }

    return NULL;
}

// ==================== Cleanup ====================

void cleanup(void) {
    xdp_detach_all();
    if (g_bpf.obj) {
        bpf_object__close(g_bpf.obj);
        g_bpf.obj = NULL;
    }
}

// ==================== Main ====================

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <config.conf> [tunnel.bpf.o]\n", argv[0]);
        return 1;
    }

    const char *config_file = argv[1];
    const char *bpf_file = (argc >= 3) ? argv[2] : "./tunnel.bpf.o";

    // Setup signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Load configuration
    if (load_config(config_file) < 0) {
        fprintf(stderr, "Error: Failed to load config: %s\n", config_file);
        return 1;
    }
    print_config();

    // Load BPF object
    if (bpf_load_object(bpf_file) < 0) {
        return 1;
    }

    // Find maps and programs
    if (bpf_find_maps() < 0 || bpf_find_programs() < 0) {
        cleanup();
        return 1;
    }

    // Populate maps
    populate_config_map();
    populate_macs_map();

    // Attach XDP programs
    if (xdp_attach_local() < 0) {
        cleanup();
        return 1;
    }

    if (xdp_attach_wans() < 0) {
        cleanup();
        return 1;
    }

    // Start ARP update thread
    pthread_t arp_tid;
    pthread_create(&arp_tid, NULL, arp_update_thread, NULL);

    printf("\nXDP Tunnel (TCP/UDP) running. Ctrl+C to stop.\n");

    // Main loop
    while (g_running) {
        sleep(1);
    }

    // Shutdown
    printf("\nShutting down...\n");
    pthread_join(arp_tid, NULL);
    cleanup();
    printf("Done.\n");

    return 0;
}
