// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel Loader - TCP/UDP
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

static volatile int running = 1;
static struct bpf_object *obj = NULL;

struct tunnel_config {
    char local_iface[32];
    __u32 local_ifindex;
    __u8 local_mac[6];
    __u32 remote_net;
    __u32 remote_mask;
    int nwan;
    struct {
        char iface[32];
        __u32 ifindex;
        __u8 my_mac[6];
        __u8 peer_mac[6];
        char peer_ip[32];
    } wan[MAX_WAN];
};

static struct tunnel_config cfg;

void handle_signal(int sig) { running = 0; }

int get_mac(const char *iface, __u8 *mac) {
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

int get_peer_mac(const char *iface, const char *peer_ip, __u8 *mac) {
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

__u64 mac_to_u64(__u8 *mac) {
    return ((__u64)mac[0]) | ((__u64)mac[1] << 8) | ((__u64)mac[2] << 16) |
           ((__u64)mac[3] << 24) | ((__u64)mac[4] << 32) | ((__u64)mac[5] << 40);
}

int parse_cidr(const char *s, __u32 *ip, __u32 *mask) {
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) { *slash = 0; prefix = atoi(slash + 1); }
    *ip = ntohl(inet_addr(buf));
    *mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    return 0;
}

int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[32], val1[64], val2[64];
        int n = sscanf(line, "%31s %63s %63s", key, val1, val2);
        if (n < 2) continue;

        if (!strcmp(key, "local")) {
            strncpy(cfg.local_iface, val1, sizeof(cfg.local_iface) - 1);
            cfg.local_ifindex = if_nametoindex(val1);
            get_mac(val1, cfg.local_mac);
        }
        else if (!strcmp(key, "remote")) {
            parse_cidr(val1, &cfg.remote_net, &cfg.remote_mask);
        }
        else if (!strcmp(key, "wan") && cfg.nwan < MAX_WAN) {
            strncpy(cfg.wan[cfg.nwan].iface, val1, sizeof(cfg.wan[cfg.nwan].iface) - 1);
            cfg.wan[cfg.nwan].ifindex = if_nametoindex(val1);
            get_mac(val1, cfg.wan[cfg.nwan].my_mac);
            if (n >= 3) {
                strncpy(cfg.wan[cfg.nwan].peer_ip, val2, sizeof(cfg.wan[cfg.nwan].peer_ip) - 1);
                get_peer_mac(val1, val2, cfg.wan[cfg.nwan].peer_mac);
            }
            cfg.nwan++;
        }
    }
    fclose(f);
    return (cfg.nwan > 0) ? 0 : -1;
}

void print_mac(__u8 *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void detach_all() {
    if (cfg.local_ifindex > 0)
        bpf_xdp_detach(cfg.local_ifindex, 0, NULL);
    for (int i = 0; i < cfg.nwan; i++)
        if (cfg.wan[i].ifindex > 0)
            bpf_xdp_detach(cfg.wan[i].ifindex, 0, NULL);
}

void *arp_thread(void *arg) {
    int arp_fd = bpf_object__find_map_fd_by_name(obj, "arp_cache");
    if (arp_fd < 0) return NULL;

    while (running) {
        FILE *fp = fopen("/proc/net/arp", "r");
        if (!fp) { sleep(2); continue; }

        char line[256];
        fgets(line, sizeof(line), fp);

        while (fgets(line, sizeof(line), fp)) {
            char ip_str[32], hw[16], flags[16], mac_str[32], mask[16], iface[32];
            if (sscanf(line, "%31s %15s %15s %31s %15s %31s",
                      ip_str, hw, flags, mac_str, mask, iface) != 6)
                continue;

            int f = (int)strtol(flags, NULL, 16);
            if (!(f & 0x02)) continue;
            if (strcmp(iface, cfg.local_iface) != 0) continue;

            __u32 ip = ntohl(inet_addr(ip_str));
            unsigned int mb[6];
            if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                      &mb[0], &mb[1], &mb[2], &mb[3], &mb[4], &mb[5]) == 6) {
                __u64 mac = 0;
                for (int i = 0; i < 6; i++)
                    mac |= ((__u64)mb[i]) << (i * 8);
                bpf_map_update_elem(arp_fd, &ip, &mac, BPF_ANY);
            }
        }
        fclose(fp);
        sleep(2);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <config.conf> [tunnel.bpf.o]\n", argv[0]);
        return 1;
    }

    const char *bpf_file = (argc >= 3) ? argv[2] : "./tunnel.bpf.o";

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (load_config(argv[1]) < 0) {
        fprintf(stderr, "Error: Failed to load config: %s\n", argv[1]);
        return 1;
    }

    printf("=== XDP Tunnel (TCP/UDP) ===\n");
    printf("Local: %s (ifindex=%d)\n", cfg.local_iface, cfg.local_ifindex);
    printf("  MAC: "); print_mac(cfg.local_mac); printf("\n");
    printf("Remote: %d.%d.%d.%d/%d\n",
           (cfg.remote_net >> 24) & 0xFF, (cfg.remote_net >> 16) & 0xFF,
           (cfg.remote_net >> 8) & 0xFF, cfg.remote_net & 0xFF,
           __builtin_popcount(cfg.remote_mask));
    printf("WANs: %d\n", cfg.nwan);

    for (int i = 0; i < cfg.nwan; i++) {
        printf("[WAN %d] %s (ifindex=%d)\n", i, cfg.wan[i].iface, cfg.wan[i].ifindex);
        printf("  My MAC:   "); print_mac(cfg.wan[i].my_mac); printf("\n");
        printf("  Peer IP:  %s\n", cfg.wan[i].peer_ip);
        printf("  Peer MAC: "); print_mac(cfg.wan[i].peer_mac); printf("\n");
    }

    obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error: Failed to open %s\n", bpf_file);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error: Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    int config_fd = bpf_object__find_map_fd_by_name(obj, "config");
    if (config_fd < 0) {
        fprintf(stderr, "Error: config map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    __u32 key, val;
    key = 0; val = cfg.nwan;
    bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);
    key = 1; val = cfg.remote_net;
    bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);
    key = 2; val = cfg.remote_mask;
    bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);
    key = 3; val = cfg.local_ifindex;
    bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);

    for (int i = 0; i < cfg.nwan; i++) {
        key = 4 + i;
        val = cfg.wan[i].ifindex;
        bpf_map_update_elem(config_fd, &key, &val, BPF_ANY);
    }

    int macs_fd = bpf_object__find_map_fd_by_name(obj, "macs");
    if (macs_fd < 0) {
        fprintf(stderr, "Error: macs map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    __u64 mac_val;
    for (int i = 0; i < cfg.nwan; i++) {
        key = i;
        mac_val = mac_to_u64(cfg.wan[i].my_mac);
        bpf_map_update_elem(macs_fd, &key, &mac_val, BPF_ANY);
    }
    for (int i = 0; i < cfg.nwan; i++) {
        key = i + MAX_WAN;
        mac_val = mac_to_u64(cfg.wan[i].peer_mac);
        bpf_map_update_elem(macs_fd, &key, &mac_val, BPF_ANY);
    }
    key = 6;
    mac_val = mac_to_u64(cfg.local_mac);
    bpf_map_update_elem(macs_fd, &key, &mac_val, BPF_ANY);

    struct bpf_program *tx_prog = bpf_object__find_program_by_name(obj, "xdp_tx");
    struct bpf_program *rx_prog = bpf_object__find_program_by_name(obj, "xdp_rx");

    if (!tx_prog || !rx_prog) {
        fprintf(stderr, "Error: XDP programs not found\n");
        bpf_object__close(obj);
        return 1;
    }

    int tx_fd = bpf_program__fd(tx_prog);
    int rx_fd = bpf_program__fd(rx_prog);

    if (bpf_xdp_attach(cfg.local_ifindex, tx_fd, 0, NULL) < 0) {
        fprintf(stderr, "Error: Failed to attach to %s: %s\n",
                cfg.local_iface, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("Attached TX to %s\n", cfg.local_iface);

    for (int i = 0; i < cfg.nwan; i++) {
        if (bpf_xdp_attach(cfg.wan[i].ifindex, rx_fd, 0, NULL) < 0) {
            fprintf(stderr, "Error: Failed to attach to %s: %s\n",
                    cfg.wan[i].iface, strerror(errno));
            detach_all();
            bpf_object__close(obj);
            return 1;
        }
        printf("Attached RX to %s\n", cfg.wan[i].iface);
    }

    pthread_t arp_tid;
    pthread_create(&arp_tid, NULL, arp_thread, NULL);

    printf("\nXDP Tunnel (TCP/UDP) running. Ctrl+C to stop.\n");

    while (running) sleep(1);

    printf("\nShutting down...\n");
    pthread_join(arp_tid, NULL);
    detach_all();
    bpf_object__close(obj);
    printf("Done.\n");

    return 0;
}
