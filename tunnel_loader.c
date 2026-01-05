// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel Loader - Load Balancer with Dynamic WAN Failover & Sync
// Features:
// - Dynamic reload when WAN goes down/up
// - Handshake protocol between 2 servers for WAN sync
// - Health check via ping
// - Control messages via UDP port 9999
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
#define CONTROL_PORT 9999
#define HEALTH_CHECK_INTERVAL 2
#define PING_TIMEOUT 1
#define PING_FAIL_THRESHOLD 2
#define HANDSHAKE_TIMEOUT 5

// WAN states
enum wan_state {
    WAN_DOWN = 0,
    WAN_WAITING = 1,
    WAN_CONFIRMED = 2,
    WAN_UP = 3
};

// Message types
enum msg_type {
    MSG_WAN_DOWN = 0,
    MSG_WAN_READY = 1,
    MSG_WAN_CONFIRM = 2,
    MSG_WAN_ACTIVE = 3
};

struct wan_info {
    char iface[32];
    __u32 ifindex;
    __u8 my_mac[6];
    __u8 peer_mac[6];
    char peer_ip[32];
    char my_ip[32];
    enum wan_state state;
    int ping_fail_count;
    int local_ready;
    int peer_ready;
    int local_confirmed;
    int peer_confirmed;
    int local_active;
    int peer_active;
    time_t waiting_since;
};

struct tunnel_config {
    char local_iface[32];
    __u32 local_ifindex;
    __u8 local_mac[6];
    __u32 remote_net;
    __u32 remote_mask;
    int total_wan;
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

struct control_msg {
    char magic[4];
    uint8_t type;
    char wan_peer_ip[32];
};

static volatile int g_running = 1;
static struct tunnel_config g_cfg = {0};
static struct bpf_context g_bpf = {0};
static char g_bpf_file[256] = {0};
static int g_reload_pipe[2] = {-1, -1};
static int g_control_sock = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int sig) { (void)sig; g_running = 0; }

// ==================== Utility Functions ====================

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

int get_iface_ip(const char *iface, char *ip_str, size_t len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    if (ret < 0) return -1;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip_str, len);
    return 0;
}

int check_iface_up(const char *iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    close(fd);
    if (ret < 0) return 0;
    return (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
}

int ping_peer(const char *iface, const char *peer_ip) {
    if (!peer_ip || strlen(peer_ip) == 0) return 1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d -I %s %s >/dev/null 2>&1",
             PING_TIMEOUT, iface, peer_ip);
    int ret = system(cmd);
    return (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) ? 1 : 0;
}

int resolve_peer_mac(const char *iface, const char *peer_ip, __u8 *mac) {
    ping_peer(iface, peer_ip);
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
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* state_str(enum wan_state s) {
    switch(s) {
        case WAN_DOWN: return "DOWN";
        case WAN_WAITING: return "WAITING";
        case WAN_CONFIRMED: return "CONFIRMED";
        case WAN_UP: return "UP";
        default: return "?";
    }
}

void trigger_reload(void) {
    char c = 'R';
    write(g_reload_pipe[1], &c, 1);
}

// ==================== Control Socket ====================

int init_control_socket(void) {
    g_control_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_control_sock < 0) return -1;

    int reuse = 1;
    setsockopt(g_control_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONTROL_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_control_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_control_sock);
        g_control_sock = -1;
        return -1;
    }
    return 0;
}

int send_control_via_active_wan(struct control_msg *msg) {
    int sent = 0;
    for (int i = 0; i < g_cfg.total_wan; i++) {
        if (g_cfg.wan[i].state != WAN_UP) continue;
        if (strlen(g_cfg.wan[i].peer_ip) == 0) continue;

        struct sockaddr_in peer_addr = {0};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(CONTROL_PORT);
        inet_pton(AF_INET, g_cfg.wan[i].peer_ip, &peer_addr.sin_addr);

        if (sendto(g_control_sock, msg, sizeof(*msg), 0,
                   (struct sockaddr *)&peer_addr, sizeof(peer_addr)) > 0) {
            printf("  -> sent via WAN%d (%s) to %s\n", i, g_cfg.wan[i].iface, g_cfg.wan[i].peer_ip);
            sent++;
        }
    }
    return sent;
}

void notify_peer_wan_status(int wan_idx, uint8_t type) {
    struct control_msg msg = {0};
    memcpy(msg.magic, "XDPC", 4);
    msg.type = type;
    strncpy(msg.wan_peer_ip, g_cfg.wan[wan_idx].peer_ip, sizeof(msg.wan_peer_ip) - 1);

    const char *type_str = (type == MSG_WAN_DOWN) ? "DOWN" :
                           (type == MSG_WAN_READY) ? "READY" :
                           (type == MSG_WAN_CONFIRM) ? "CONFIRM" : "ACTIVE";

    printf("[SYNC] Notify peer: WAN%d %s\n", wan_idx, type_str);

    int sent = send_control_via_active_wan(&msg);

    if (type != MSG_WAN_DOWN && strlen(g_cfg.wan[wan_idx].peer_ip) > 0) {
        struct sockaddr_in peer_addr = {0};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(CONTROL_PORT);
        inet_pton(AF_INET, g_cfg.wan[wan_idx].peer_ip, &peer_addr.sin_addr);
        sendto(g_control_sock, &msg, sizeof(msg), 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
        printf("  -> also sent directly via WAN%d\n", wan_idx);
        sent++;
    }

    if (sent == 0) printf("  -> NO ROUTE! Peer will detect via ping.\n");
}

int find_wan_by_my_ip(const char *ip) {
    for (int i = 0; i < g_cfg.total_wan; i++)
        if (strcmp(g_cfg.wan[i].my_ip, ip) == 0) return i;
    return -1;
}

int find_wan_by_peer_ip(const char *ip) {
    for (int i = 0; i < g_cfg.total_wan; i++)
        if (strcmp(g_cfg.wan[i].peer_ip, ip) == 0) return i;
    return -1;
}

// ==================== XDP Functions ====================

void xdp_detach_all(void) {
    if (g_cfg.local_ifindex > 0)
        bpf_xdp_detach(g_cfg.local_ifindex, 0, NULL);
    for (int i = 0; i < g_cfg.total_wan; i++)
        if (g_cfg.wan[i].ifindex > 0)
            bpf_xdp_detach(g_cfg.wan[i].ifindex, 0, NULL);
}

void cleanup_bpf(void) {
    xdp_detach_all();
    if (g_bpf.obj) {
        bpf_object__close(g_bpf.obj);
        g_bpf.obj = NULL;
    }
    g_bpf.config_fd = g_bpf.macs_fd = g_bpf.arp_fd = -1;
}

int do_full_reload(void) {
    printf("\n========================================\n");
    printf("[RELOAD] Starting...\n");

    cleanup_bpf();
    usleep(100000);

    int active_count = 0;
    int active_idx[MAX_WAN];

    printf("[RELOAD] WAN status:\n");

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_cfg.total_wan; i++) {
        printf("  WAN%d (%s): %s\n", i, g_cfg.wan[i].iface, state_str(g_cfg.wan[i].state));
        if (g_cfg.wan[i].state == WAN_UP) {
            active_idx[active_count] = i;
            active_count++;
        }
    }
    pthread_mutex_unlock(&g_lock);

    printf("[RELOAD] Active WANs: %d\n", active_count);
    if (active_count == 0) {
        printf("[RELOAD] No active WAN!\n");
        printf("========================================\n\n");
        return -1;
    }

    g_bpf.obj = bpf_object__open_file(g_bpf_file, NULL);
    if (libbpf_get_error(g_bpf.obj)) {
        g_bpf.obj = NULL;
        return -1;
    }
    if (bpf_object__load(g_bpf.obj)) {
        bpf_object__close(g_bpf.obj);
        g_bpf.obj = NULL;
        return -1;
    }

    g_bpf.config_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "config");
    g_bpf.macs_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "macs");
    g_bpf.arp_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "arp_cache");

    struct bpf_program *tx = bpf_object__find_program_by_name(g_bpf.obj, "xdp_tx");
    struct bpf_program *rx = bpf_object__find_program_by_name(g_bpf.obj, "xdp_rx");

    if (!tx || !rx || g_bpf.config_fd < 0 || g_bpf.macs_fd < 0) {
        cleanup_bpf();
        return -1;
    }
    g_bpf.tx_fd = bpf_program__fd(tx);
    g_bpf.rx_fd = bpf_program__fd(rx);

    __u32 key, val;
    key = 0; val = active_count;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);
    key = 1; val = g_cfg.remote_net;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);
    key = 2; val = g_cfg.remote_mask;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);
    key = 3; val = g_cfg.local_ifindex;
    bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);

    for (int i = 0; i < active_count; i++) {
        key = 4 + i;
        val = g_cfg.wan[active_idx[i]].ifindex;
        bpf_map_update_elem(g_bpf.config_fd, &key, &val, BPF_ANY);
    }

    __u64 mac_val;
    for (int i = 0; i < active_count; i++) {
        int idx = active_idx[i];
        key = i;
        mac_val = mac_to_u64(g_cfg.wan[idx].my_mac);
        bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);
        key = i + MAX_WAN;
        mac_val = mac_to_u64(g_cfg.wan[idx].peer_mac);
        bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);
    }
    key = 6;
    mac_val = mac_to_u64(g_cfg.local_mac);
    bpf_map_update_elem(g_bpf.macs_fd, &key, &mac_val, BPF_ANY);

    if (bpf_xdp_attach(g_cfg.local_ifindex, g_bpf.tx_fd, 0, NULL) < 0) {
        cleanup_bpf();
        return -1;
    }
    printf("[RELOAD] TX -> %s\n", g_cfg.local_iface);

    for (int i = 0; i < active_count; i++) {
        int idx = active_idx[i];
        if (bpf_xdp_attach(g_cfg.wan[idx].ifindex, g_bpf.rx_fd, 0, NULL) < 0) {
            cleanup_bpf();
            return -1;
        }
        printf("[RELOAD] RX -> %s\n", g_cfg.wan[idx].iface);
    }

    printf("[RELOAD] Done! nwan=%d (per-window load balancing)\n", active_count);
    printf("========================================\n\n");
    return 0;
}

// ==================== Config ====================

static int parse_cidr(const char *s, __u32 *ip, __u32 *mask) {
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    *ip = ntohl(inet_addr(buf));
    *mask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
    return 0;
}

int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    memset(&g_cfg, 0, sizeof(g_cfg));

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char key[32], val1[64], val2[64] = {0};
        int n = sscanf(line, "%31s %63s %63s", key, val1, val2);
        if (n < 2) continue;

        if (!strcmp(key, "local")) {
            strncpy(g_cfg.local_iface, val1, sizeof(g_cfg.local_iface) - 1);
            g_cfg.local_ifindex = if_nametoindex(val1);
            get_iface_mac(val1, g_cfg.local_mac);
        } else if (!strcmp(key, "remote")) {
            parse_cidr(val1, &g_cfg.remote_net, &g_cfg.remote_mask);
        } else if (!strcmp(key, "wan") && g_cfg.total_wan < MAX_WAN) {
            struct wan_info *wan = &g_cfg.wan[g_cfg.total_wan];
            strncpy(wan->iface, val1, sizeof(wan->iface) - 1);
            wan->ifindex = if_nametoindex(val1);
            wan->state = WAN_DOWN;
            wan->local_ready = wan->peer_ready = 0;
            get_iface_mac(val1, wan->my_mac);
            get_iface_ip(val1, wan->my_ip, sizeof(wan->my_ip));
            if (n >= 3) {
                strncpy(wan->peer_ip, val2, sizeof(wan->peer_ip) - 1);
                resolve_peer_mac(val1, val2, wan->peer_mac);
            }
            g_cfg.total_wan++;
        }
    }
    fclose(f);
    return (g_cfg.total_wan > 0) ? 0 : -1;
}

void print_config(void) {
    printf("=== XDP Tunnel - Per-Window Load Balancing ===\n");
    printf("Local: %s MAC: ", g_cfg.local_iface);
    print_mac(g_cfg.local_mac);
    printf("\nRemote: %d.%d.%d.%d/%d\n",
           (g_cfg.remote_net >> 24) & 0xFF, (g_cfg.remote_net >> 16) & 0xFF,
           (g_cfg.remote_net >> 8) & 0xFF, g_cfg.remote_net & 0xFF,
           __builtin_popcount(g_cfg.remote_mask));
    printf("Control port: %d, Handshake timeout: %ds\n", CONTROL_PORT, HANDSHAKE_TIMEOUT);
    printf("Load balancing: TCP window chunks (64KB)\n");
    printf("WANs:\n");
    for (int i = 0; i < g_cfg.total_wan; i++) {
        printf("  [%d] %s (%s) <-> %s\n", i, g_cfg.wan[i].iface, g_cfg.wan[i].my_ip, g_cfg.wan[i].peer_ip);
    }
    printf("\n");
}

// ==================== Message Handlers ====================

void reset_wan_flags(int wan_idx) {
    g_cfg.wan[wan_idx].local_ready = g_cfg.wan[wan_idx].peer_ready = 0;
    g_cfg.wan[wan_idx].local_confirmed = g_cfg.wan[wan_idx].peer_confirmed = 0;
    g_cfg.wan[wan_idx].local_active = g_cfg.wan[wan_idx].peer_active = 0;
    g_cfg.wan[wan_idx].ping_fail_count = 0;
}

void handle_wan_down(int wan_idx) {
    if (g_cfg.wan[wan_idx].state == WAN_DOWN) return;
    printf("[STATE] WAN%d: %s -> DOWN\n", wan_idx, state_str(g_cfg.wan[wan_idx].state));
    g_cfg.wan[wan_idx].state = WAN_DOWN;
    reset_wan_flags(wan_idx);
}

void handle_wan_ready(int wan_idx) {
    int local_ok = check_iface_up(g_cfg.wan[wan_idx].iface) &&
                   ping_peer(g_cfg.wan[wan_idx].iface, g_cfg.wan[wan_idx].peer_ip);

    if (!local_ok) {
        printf("[STATE] WAN%d: Peer READY but local NOT ready\n", wan_idx);
        return;
    }

    g_cfg.wan[wan_idx].peer_ready = 1;
    printf("[STATE] WAN%d: Received READY (local_ready=%d, peer_ready=%d)\n",
           wan_idx, g_cfg.wan[wan_idx].local_ready, g_cfg.wan[wan_idx].peer_ready);

    if (!g_cfg.wan[wan_idx].local_ready) {
        g_cfg.wan[wan_idx].local_ready = 1;
        g_cfg.wan[wan_idx].state = WAN_WAITING;
        g_cfg.wan[wan_idx].waiting_since = time(NULL);
        pthread_mutex_unlock(&g_lock);
        notify_peer_wan_status(wan_idx, MSG_WAN_READY);
        pthread_mutex_lock(&g_lock);
    }

    if (g_cfg.wan[wan_idx].local_ready && g_cfg.wan[wan_idx].peer_ready &&
        !g_cfg.wan[wan_idx].local_confirmed) {
        g_cfg.wan[wan_idx].local_confirmed = 1;
        printf("[STATE] WAN%d: Both READY -> sending CONFIRM\n", wan_idx);
        pthread_mutex_unlock(&g_lock);
        notify_peer_wan_status(wan_idx, MSG_WAN_CONFIRM);
        pthread_mutex_lock(&g_lock);
    }
}

void handle_wan_confirm(int wan_idx) {
    g_cfg.wan[wan_idx].peer_confirmed = 1;
    printf("[STATE] WAN%d: Received CONFIRM (local_confirmed=%d, peer_confirmed=%d)\n",
           wan_idx, g_cfg.wan[wan_idx].local_confirmed, g_cfg.wan[wan_idx].peer_confirmed);

    if (g_cfg.wan[wan_idx].local_ready && g_cfg.wan[wan_idx].peer_ready &&
        !g_cfg.wan[wan_idx].local_confirmed) {
        g_cfg.wan[wan_idx].local_confirmed = 1;
        pthread_mutex_unlock(&g_lock);
        notify_peer_wan_status(wan_idx, MSG_WAN_CONFIRM);
        pthread_mutex_lock(&g_lock);
    }

    if (g_cfg.wan[wan_idx].local_confirmed && g_cfg.wan[wan_idx].peer_confirmed &&
        g_cfg.wan[wan_idx].state != WAN_CONFIRMED && g_cfg.wan[wan_idx].state != WAN_UP) {
        printf("[STATE] WAN%d: Both CONFIRMED -> send ACTIVE\n", wan_idx);
        g_cfg.wan[wan_idx].state = WAN_CONFIRMED;
        g_cfg.wan[wan_idx].local_active = 1;
        g_cfg.wan[wan_idx].waiting_since = time(NULL);
        pthread_mutex_unlock(&g_lock);
        notify_peer_wan_status(wan_idx, MSG_WAN_ACTIVE);
        pthread_mutex_lock(&g_lock);
    }
}

void handle_wan_active(int wan_idx) {
    g_cfg.wan[wan_idx].peer_active = 1;
    printf("[STATE] WAN%d: Received ACTIVE (local_active=%d, peer_active=%d)\n",
           wan_idx, g_cfg.wan[wan_idx].local_active, g_cfg.wan[wan_idx].peer_active);

    if (g_cfg.wan[wan_idx].local_confirmed && g_cfg.wan[wan_idx].peer_ready &&
        !g_cfg.wan[wan_idx].local_active) {
        g_cfg.wan[wan_idx].local_active = 1;
        g_cfg.wan[wan_idx].state = WAN_CONFIRMED;
        pthread_mutex_unlock(&g_lock);
        notify_peer_wan_status(wan_idx, MSG_WAN_ACTIVE);
        pthread_mutex_lock(&g_lock);
    }

    if (g_cfg.wan[wan_idx].local_active && g_cfg.wan[wan_idx].peer_active &&
        g_cfg.wan[wan_idx].state != WAN_UP) {
        printf("[STATE] WAN%d: Both ACTIVE -> UP! Reloading XDP...\n", wan_idx);
        g_cfg.wan[wan_idx].state = WAN_UP;
        pthread_mutex_unlock(&g_lock);
        trigger_reload();
        pthread_mutex_lock(&g_lock);
    }
}

// ==================== Threads ====================

void *control_receiver_thread(void *arg) {
    (void)arg;
    printf("[SYNC] Receiver started on port %d\n", CONTROL_PORT);

    char buf[256];
    struct sockaddr_in from_addr;
    socklen_t from_len;

    while (g_running) {
        from_len = sizeof(from_addr);
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_control_sock, &fds);

        struct timeval tv = {1, 0};
        if (select(g_control_sock + 1, &fds, NULL, NULL, &tv) <= 0) continue;

        ssize_t n = recvfrom(g_control_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from_addr, &from_len);
        if (n < (ssize_t)sizeof(struct control_msg)) continue;

        struct control_msg *msg = (struct control_msg *)buf;
        if (memcmp(msg->magic, "XDPC", 4) != 0) continue;

        int wan_idx = find_wan_by_my_ip(msg->wan_peer_ip);
        if (wan_idx < 0) wan_idx = find_wan_by_peer_ip(msg->wan_peer_ip);
        if (wan_idx < 0) continue;

        char from_ip[32];
        inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, sizeof(from_ip));

        const char *msg_type_str = (msg->type == MSG_WAN_DOWN) ? "DOWN" :
                                   (msg->type == MSG_WAN_READY) ? "READY" :
                                   (msg->type == MSG_WAN_CONFIRM) ? "CONFIRM" : "ACTIVE";

        printf("[SYNC] From %s: %s for WAN%d\n", from_ip, msg_type_str, wan_idx);

        pthread_mutex_lock(&g_lock);
        enum wan_state old_state = g_cfg.wan[wan_idx].state;

        switch (msg->type) {
            case MSG_WAN_DOWN:
                handle_wan_down(wan_idx);
                if (old_state != WAN_DOWN) {
                    pthread_mutex_unlock(&g_lock);
                    trigger_reload();
                    pthread_mutex_lock(&g_lock);
                }
                break;
            case MSG_WAN_READY:  handle_wan_ready(wan_idx); break;
            case MSG_WAN_CONFIRM: handle_wan_confirm(wan_idx); break;
            case MSG_WAN_ACTIVE: handle_wan_active(wan_idx); break;
        }
        pthread_mutex_unlock(&g_lock);
    }
    return NULL;
}

void *health_check_thread(void *arg) {
    (void)arg;
    printf("[HEALTH] Started (interval=%ds)\n", HEALTH_CHECK_INTERVAL);
    sleep(3);

    while (g_running) {
        sleep(HEALTH_CHECK_INTERVAL);
        if (!g_running) break;

        int need_reload = 0;
        time_t now = time(NULL);

        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_cfg.total_wan; i++) {
            int iface_up = check_iface_up(g_cfg.wan[i].iface);
            int ping_ok = (iface_up && strlen(g_cfg.wan[i].peer_ip) > 0) ?
                          ping_peer(g_cfg.wan[i].iface, g_cfg.wan[i].peer_ip) : 0;
            int local_ok = iface_up && ping_ok;

            switch (g_cfg.wan[i].state) {
                case WAN_UP:
                    if (!local_ok) {
                        g_cfg.wan[i].ping_fail_count++;
                        if (g_cfg.wan[i].ping_fail_count >= PING_FAIL_THRESHOLD) {
                            printf("[HEALTH] WAN%d: UP -> DOWN (ping fail)\n", i);
                            g_cfg.wan[i].state = WAN_DOWN;
                            reset_wan_flags(i);
                            need_reload = 1;
                            pthread_mutex_unlock(&g_lock);
                            notify_peer_wan_status(i, MSG_WAN_DOWN);
                            pthread_mutex_lock(&g_lock);
                        }
                    } else {
                        g_cfg.wan[i].ping_fail_count = 0;
                    }
                    break;

                case WAN_DOWN:
                    if (local_ok) {
                        printf("[HEALTH] WAN%d: Local ready, starting handshake\n", i);
                        g_cfg.wan[i].state = WAN_WAITING;
                        g_cfg.wan[i].local_ready = 1;
                        g_cfg.wan[i].waiting_since = now;
                        pthread_mutex_unlock(&g_lock);
                        notify_peer_wan_status(i, MSG_WAN_READY);
                        pthread_mutex_lock(&g_lock);
                    }
                    break;

                case WAN_WAITING:
                    if (!local_ok) {
                        printf("[HEALTH] WAN%d: WAITING -> DOWN\n", i);
                        g_cfg.wan[i].state = WAN_DOWN;
                        reset_wan_flags(i);
                        need_reload = 1;
                        pthread_mutex_unlock(&g_lock);
                        notify_peer_wan_status(i, MSG_WAN_DOWN);
                        pthread_mutex_lock(&g_lock);
                    } else if (now - g_cfg.wan[i].waiting_since > HANDSHAKE_TIMEOUT) {
                        printf("[HEALTH] WAN%d: Handshake timeout, retry\n", i);
                        g_cfg.wan[i].waiting_since = now;
                        pthread_mutex_unlock(&g_lock);
                        notify_peer_wan_status(i, MSG_WAN_READY);
                        pthread_mutex_lock(&g_lock);
                    }
                    break;

                case WAN_CONFIRMED:
                    if (!local_ok) {
                        printf("[HEALTH] WAN%d: CONFIRMED -> DOWN\n", i);
                        g_cfg.wan[i].state = WAN_DOWN;
                        reset_wan_flags(i);
                        need_reload = 1;
                        pthread_mutex_unlock(&g_lock);
                        notify_peer_wan_status(i, MSG_WAN_DOWN);
                        pthread_mutex_lock(&g_lock);
                    } else if (now - g_cfg.wan[i].waiting_since > HANDSHAKE_TIMEOUT) {
                        printf("[HEALTH] WAN%d: ACTIVE timeout, retry\n", i);
                        g_cfg.wan[i].waiting_since = now;
                        pthread_mutex_unlock(&g_lock);
                        notify_peer_wan_status(i, MSG_WAN_ACTIVE);
                        pthread_mutex_lock(&g_lock);
                    }
                    break;
            }
        }
        pthread_mutex_unlock(&g_lock);
        if (need_reload) trigger_reload();
    }
    return NULL;
}

void *arp_update_thread(void *arg) {
    (void)arg;
    while (g_running) {
        if (g_bpf.arp_fd < 0) { sleep(2); continue; }

        FILE *fp = fopen("/proc/net/arp", "r");
        if (!fp) { sleep(2); continue; }

        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            char ip_str[32], hw[16], flags[16], mac_str[32], mask[16], iface[32];
            if (sscanf(line, "%31s %15s %15s %31s %15s %31s",
                       ip_str, hw, flags, mac_str, mask, iface) != 6) continue;
            if (!(strtol(flags, NULL, 16) & 0x02)) continue;
            if (strcmp(iface, g_cfg.local_iface) != 0) continue;

            __u32 ip = ntohl(inet_addr(ip_str));
            unsigned int mb[6];
            if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                       &mb[0], &mb[1], &mb[2], &mb[3], &mb[4], &mb[5]) == 6) {
                __u64 mac = 0;
                for (int j = 0; j < 6; j++) mac |= ((__u64)mb[j]) << (j * 8);
                bpf_map_update_elem(g_bpf.arp_fd, &ip, &mac, BPF_ANY);
            }
        }
        fclose(fp);
        sleep(2);
    }
    return NULL;
}

void initial_handshake(void) {
    printf("[INIT] Starting handshake (4-way: READY -> READY -> CONFIRM -> ACTIVE)\n");

    for (int i = 0; i < g_cfg.total_wan; i++) {
        reset_wan_flags(i);

        int iface_up = check_iface_up(g_cfg.wan[i].iface);
        int ping_ok = (iface_up && strlen(g_cfg.wan[i].peer_ip) > 0) ?
                      ping_peer(g_cfg.wan[i].iface, g_cfg.wan[i].peer_ip) : 0;

        if (iface_up && ping_ok) {
            printf("[INIT] WAN%d: Local ready, sending READY\n", i);
            g_cfg.wan[i].state = WAN_WAITING;
            g_cfg.wan[i].local_ready = 1;
            g_cfg.wan[i].waiting_since = time(NULL);
            notify_peer_wan_status(i, MSG_WAN_READY);
        } else {
            printf("[INIT] WAN%d: Not ready (iface=%d, ping=%d)\n", i, iface_up, ping_ok);
            g_cfg.wan[i].state = WAN_DOWN;
        }
    }

    printf("[INIT] Waiting for peer (%ds)...\n", HANDSHAKE_TIMEOUT);
    sleep(HANDSHAKE_TIMEOUT);

    pthread_mutex_lock(&g_lock);
    int up_count = 0;
    for (int i = 0; i < g_cfg.total_wan; i++) {
        printf("[INIT] WAN%d: %s\n", i, state_str(g_cfg.wan[i].state));
        if (g_cfg.wan[i].state == WAN_UP) up_count++;
    }
    pthread_mutex_unlock(&g_lock);
    printf("[INIT] %d WANs ready\n\n", up_count);
}

// ==================== Main ====================

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <config.conf> [tunnel.bpf.o]\n", argv[0]);
        return 1;
    }

    strncpy(g_bpf_file, argc >= 3 ? argv[2] : "./tunnel.bpf.o", sizeof(g_bpf_file) - 1);

    if (pipe(g_reload_pipe) < 0) return 1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (load_config(argv[1]) < 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }
    print_config();

    if (init_control_socket() < 0) {
        fprintf(stderr, "Failed to init control socket\n");
        return 1;
    }

    pthread_t control_tid;
    pthread_create(&control_tid, NULL, control_receiver_thread, NULL);

    initial_handshake();

    if (do_full_reload() < 0) {
        printf("No WAN ready yet, waiting...\n");
    }

    pthread_t arp_tid, health_tid;
    pthread_create(&arp_tid, NULL, arp_update_thread, NULL);
    pthread_create(&health_tid, NULL, health_check_thread, NULL);

    printf("XDP Tunnel running (per-window LB). Ctrl+C to stop.\n\n");

    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_reload_pipe[0], &fds);

        struct timeval tv = {1, 0};
        if (select(g_reload_pipe[0] + 1, &fds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(g_reload_pipe[0], &fds)) {
                char c;
                read(g_reload_pipe[0], &c, 1);
                do_full_reload();
            }
        }
    }

    printf("\nShutting down...\n");
    pthread_join(arp_tid, NULL);
    pthread_join(health_tid, NULL);
    pthread_join(control_tid, NULL);
    cleanup_bpf();
    if (g_control_sock >= 0) close(g_control_sock);
    close(g_reload_pipe[0]);
    close(g_reload_pipe[1]);
    printf("Done.\n");
    return 0;
}

