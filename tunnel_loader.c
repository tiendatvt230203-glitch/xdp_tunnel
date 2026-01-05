// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel Loader - Compact Version
// 4-way handshake: READY -> READY -> CONFIRM -> ACTIVE
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

#define MAX_WAN 3
#define CTRL_PORT 9999
#define CHK_INTERVAL 2
#define PING_TIMEOUT 1
#define PING_FAIL_MAX 2
#define HS_TIMEOUT 5

enum { WAN_DOWN=0, WAN_WAITING, WAN_CONFIRMED, WAN_UP };
enum { MSG_DOWN=0, MSG_READY, MSG_CONFIRM, MSG_ACTIVE };

struct wan_t {
    char iface[32], peer_ip[32], my_ip[32];
    __u32 ifindex;
    __u8 my_mac[6], peer_mac[6];
    int state, ping_fail;
    int l_ready, p_ready, l_conf, p_conf, l_active, p_active;
    time_t wait_since;
};

struct cfg_t {
    char local_iface[32];
    __u32 local_ifindex, remote_net, remote_mask;
    __u8 local_mac[6];
    int nwan;
    struct wan_t wan[MAX_WAN];
};

struct bpf_t {
    struct bpf_object *obj;
    int cfg_fd, mac_fd, arp_fd, tx_fd, rx_fd;
};

struct msg_t { char magic[4]; uint8_t type; char wan_ip[32]; };

static volatile int g_run = 1;
static struct cfg_t g_cfg = {0};
static struct bpf_t g_bpf = {0};
static char g_bpf_file[256];
static int g_pipe[2], g_sock = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void sig_handler(int s) { (void)s; g_run = 0; }
static void trigger_reload(void) { write(g_pipe[1], "R", 1); }

static __u64 mac2u64(const __u8 *m) {
    return (__u64)m[0] | ((__u64)m[1]<<8) | ((__u64)m[2]<<16) |
           ((__u64)m[3]<<24) | ((__u64)m[4]<<32) | ((__u64)m[5]<<40);
}

static void u64mac(__u8 *d, __u64 m) {
    for(int i=0; i<6; i++) d[i] = m >> (i*8);
}

static int get_mac(const char *iface, __u8 *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int r = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    if (r == 0) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return r;
}

static int get_ip(const char *iface, char *ip, size_t len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int r = ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    if (r == 0) inet_ntop(AF_INET, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, ip, len);
    return r;
}

static int iface_up(const char *iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    int r = ioctl(fd, SIOCGIFFLAGS, &ifr);
    close(fd);
    return (r == 0) && (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
}

static int ping_ok(const char *iface, const char *ip) {
    if (!ip || !ip[0]) return 1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W%d -I %s %s >/dev/null 2>&1", PING_TIMEOUT, iface, ip);
    int r = system(cmd);
    return WIFEXITED(r) && WEXITSTATUS(r) == 0;
}

static int resolve_mac(const char *iface, const char *ip, __u8 *mac) {
    ping_ok(iface, ip);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct arpreq req = {0};
    ((struct sockaddr_in*)&req.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &((struct sockaddr_in*)&req.arp_pa)->sin_addr);
    strncpy(req.arp_dev, iface, sizeof(req.arp_dev)-1);
    int r = ioctl(fd, SIOCGARP, &req);
    close(fd);
    if (r == 0) memcpy(mac, req.arp_ha.sa_data, 6);
    return r;
}

static int find_wan_by_ip(const char *ip, int by_peer) {
    for (int i = 0; i < g_cfg.nwan; i++)
        if (strcmp(by_peer ? g_cfg.wan[i].peer_ip : g_cfg.wan[i].my_ip, ip) == 0) return i;
    return -1;
}

static void reset_wan(int i) {
    struct wan_t *w = &g_cfg.wan[i];
    w->l_ready = w->p_ready = w->l_conf = w->p_conf = w->l_active = w->p_active = w->ping_fail = 0;
}

// ==================== Control Socket ====================

static int init_sock(void) {
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) return -1;
    int opt = 1;
    setsockopt(g_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(CTRL_PORT) };
    return bind(g_sock, (struct sockaddr*)&addr, sizeof(addr));
}

static void send_msg(int idx, int type) {
    struct msg_t msg = {{'X','D','P','C'}, type};
    strncpy(msg.wan_ip, g_cfg.wan[idx].peer_ip, sizeof(msg.wan_ip)-1);

    // Gửi qua tất cả WAN UP
    for (int i = 0; i < g_cfg.nwan; i++) {
        if (g_cfg.wan[i].state != WAN_UP || !g_cfg.wan[i].peer_ip[0]) continue;
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(CTRL_PORT) };
        inet_pton(AF_INET, g_cfg.wan[i].peer_ip, &a.sin_addr);
        sendto(g_sock, &msg, sizeof(msg), 0, (struct sockaddr*)&a, sizeof(a));
    }
    // Gửi trực tiếp qua WAN đang test (cho READY/CONFIRM/ACTIVE)
    if (type != MSG_DOWN && g_cfg.wan[idx].peer_ip[0]) {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(CTRL_PORT) };
        inet_pton(AF_INET, g_cfg.wan[idx].peer_ip, &a.sin_addr);
        sendto(g_sock, &msg, sizeof(msg), 0, (struct sockaddr*)&a, sizeof(a));
    }
}

// ==================== XDP ====================

static void detach_all(void) {
    if (g_cfg.local_ifindex) bpf_set_link_xdp_fd(g_cfg.local_ifindex, -1, 0);
    for (int i = 0; i < g_cfg.nwan; i++)
        if (g_cfg.wan[i].ifindex) bpf_set_link_xdp_fd(g_cfg.wan[i].ifindex, -1, 0);
}

static void cleanup_bpf(void) {
    detach_all();
    if (g_bpf.obj) { bpf_object__close(g_bpf.obj); g_bpf.obj = NULL; }
    g_bpf.cfg_fd = g_bpf.mac_fd = g_bpf.arp_fd = -1;
}

static int reload_xdp(void) {
    cleanup_bpf();
    usleep(100000);

    int cnt = 0, idx[MAX_WAN];
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_cfg.nwan; i++)
        if (g_cfg.wan[i].state == WAN_UP) idx[cnt++] = i;
    pthread_mutex_unlock(&g_lock);

    if (cnt == 0) { printf("[XDP] No active WAN\n"); return -1; }

    g_bpf.obj = bpf_object__open_file(g_bpf_file, NULL);
    if (libbpf_get_error(g_bpf.obj)) { g_bpf.obj = NULL; return -1; }
    if (bpf_object__load(g_bpf.obj)) { bpf_object__close(g_bpf.obj); g_bpf.obj = NULL; return -1; }

    g_bpf.cfg_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "config");
    g_bpf.mac_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "macs");
    g_bpf.arp_fd = bpf_object__find_map_fd_by_name(g_bpf.obj, "arp_cache");

    struct bpf_program *tx = bpf_object__find_program_by_name(g_bpf.obj, "xdp_tx");
    struct bpf_program *rx = bpf_object__find_program_by_name(g_bpf.obj, "xdp_rx");
    if (!tx || !rx || g_bpf.cfg_fd < 0 || g_bpf.mac_fd < 0) { cleanup_bpf(); return -1; }

    g_bpf.tx_fd = bpf_program__fd(tx);
    g_bpf.rx_fd = bpf_program__fd(rx);

    __u32 k, v;
    k=0; v=cnt; bpf_map_update_elem(g_bpf.cfg_fd, &k, &v, BPF_ANY);
    k=1; v=g_cfg.remote_net; bpf_map_update_elem(g_bpf.cfg_fd, &k, &v, BPF_ANY);
    k=2; v=g_cfg.remote_mask; bpf_map_update_elem(g_bpf.cfg_fd, &k, &v, BPF_ANY);
    k=3; v=g_cfg.local_ifindex; bpf_map_update_elem(g_bpf.cfg_fd, &k, &v, BPF_ANY);

    for (int i = 0; i < cnt; i++) {
        k = 4+i; v = g_cfg.wan[idx[i]].ifindex;
        bpf_map_update_elem(g_bpf.cfg_fd, &k, &v, BPF_ANY);
    }

    __u64 mac;
    for (int i = 0; i < cnt; i++) {
        k = i; mac = mac2u64(g_cfg.wan[idx[i]].my_mac);
        bpf_map_update_elem(g_bpf.mac_fd, &k, &mac, BPF_ANY);
        k = i + MAX_WAN; mac = mac2u64(g_cfg.wan[idx[i]].peer_mac);
        bpf_map_update_elem(g_bpf.mac_fd, &k, &mac, BPF_ANY);
    }
    k = 6; mac = mac2u64(g_cfg.local_mac);
    bpf_map_update_elem(g_bpf.mac_fd, &k, &mac, BPF_ANY);

    if (bpf_set_link_xdp_fd(g_cfg.local_ifindex, g_bpf.tx_fd, 0) < 0) { cleanup_bpf(); return -1; }
    for (int i = 0; i < cnt; i++)
        if (bpf_set_link_xdp_fd(g_cfg.wan[idx[i]].ifindex, g_bpf.rx_fd, 0) < 0) { cleanup_bpf(); return -1; }

    printf("[XDP] Reloaded, nwan=%d\n", cnt);
    return 0;
}

// ==================== Config ====================

static int load_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(&g_cfg, 0, sizeof(g_cfg));

    char line[256], key[32], v1[64], v2[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        v2[0] = 0;
        int n = sscanf(line, "%31s %63s %63s", key, v1, v2);
        if (n < 2) continue;

        if (!strcmp(key, "local")) {
            strncpy(g_cfg.local_iface, v1, sizeof(g_cfg.local_iface)-1);
            g_cfg.local_ifindex = if_nametoindex(v1);
            get_mac(v1, g_cfg.local_mac);
        } else if (!strcmp(key, "remote")) {
            char buf[64]; strncpy(buf, v1, sizeof(buf)-1);
            char *sl = strchr(buf, '/');
            int pfx = 24;
            if (sl) { *sl = 0; pfx = atoi(sl+1); }
            g_cfg.remote_net = ntohl(inet_addr(buf));
            g_cfg.remote_mask = pfx ? (0xFFFFFFFF << (32-pfx)) : 0;
        } else if (!strcmp(key, "wan") && g_cfg.nwan < MAX_WAN) {
            struct wan_t *w = &g_cfg.wan[g_cfg.nwan++];
            strncpy(w->iface, v1, sizeof(w->iface)-1);
            w->ifindex = if_nametoindex(v1);
            w->state = WAN_DOWN;
            get_mac(v1, w->my_mac);
            get_ip(v1, w->my_ip, sizeof(w->my_ip));
            if (n >= 3) {
                strncpy(w->peer_ip, v2, sizeof(w->peer_ip)-1);
                resolve_mac(v1, v2, w->peer_mac);
            }
        }
    }
    fclose(f);
    return g_cfg.nwan > 0 ? 0 : -1;
}

// ==================== Handlers ====================

static void handle_down(int i) {
    if (g_cfg.wan[i].state == WAN_DOWN) return;
    printf("[WAN%d] -> DOWN\n", i);
    g_cfg.wan[i].state = WAN_DOWN;
    reset_wan(i);
}

static void handle_ready(int i) {
    struct wan_t *w = &g_cfg.wan[i];
    if (!iface_up(w->iface) || !ping_ok(w->iface, w->peer_ip)) return;

    w->p_ready = 1;
    if (!w->l_ready) {
        w->l_ready = 1;
        w->state = WAN_WAITING;
        w->wait_since = time(NULL);
        pthread_mutex_unlock(&g_lock);
        send_msg(i, MSG_READY);
        pthread_mutex_lock(&g_lock);
    }
    if (w->l_ready && w->p_ready && !w->l_conf) {
        w->l_conf = 1;
        pthread_mutex_unlock(&g_lock);
        send_msg(i, MSG_CONFIRM);
        pthread_mutex_lock(&g_lock);
    }
}

static void handle_confirm(int i) {
    struct wan_t *w = &g_cfg.wan[i];
    w->p_conf = 1;
    if (w->l_ready && w->p_ready && !w->l_conf) {
        w->l_conf = 1;
        pthread_mutex_unlock(&g_lock);
        send_msg(i, MSG_CONFIRM);
        pthread_mutex_lock(&g_lock);
    }
    if (w->l_conf && w->p_conf && w->state != WAN_CONFIRMED && w->state != WAN_UP) {
        w->state = WAN_CONFIRMED;
        w->l_active = 1;
        w->wait_since = time(NULL);
        pthread_mutex_unlock(&g_lock);
        send_msg(i, MSG_ACTIVE);
        pthread_mutex_lock(&g_lock);
    }
}

static void handle_active(int i) {
    struct wan_t *w = &g_cfg.wan[i];
    w->p_active = 1;
    if (w->l_conf && w->p_conf && !w->l_active) {
        w->l_active = 1;
        w->state = WAN_CONFIRMED;
        pthread_mutex_unlock(&g_lock);
        send_msg(i, MSG_ACTIVE);
        pthread_mutex_lock(&g_lock);
    }
    if (w->l_active && w->p_active && w->state != WAN_UP) {
        printf("[WAN%d] -> UP\n", i);
        w->state = WAN_UP;
        pthread_mutex_unlock(&g_lock);
        trigger_reload();
        pthread_mutex_lock(&g_lock);
    }
}

// ==================== Threads ====================

static void *ctrl_thread(void *arg) {
    (void)arg;
    char buf[256];
    while (g_run) {
        fd_set fds; FD_ZERO(&fds); FD_SET(g_sock, &fds);
        struct timeval tv = {1, 0};
        if (select(g_sock+1, &fds, NULL, NULL, &tv) <= 0) continue;

        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        if (recvfrom(g_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen) < (ssize_t)sizeof(struct msg_t)) continue;

        struct msg_t *m = (struct msg_t*)buf;
        if (memcmp(m->magic, "XDPC", 4)) continue;

        int idx = find_wan_by_ip(m->wan_ip, 0);
        if (idx < 0) idx = find_wan_by_ip(m->wan_ip, 1);
        if (idx < 0) continue;

        pthread_mutex_lock(&g_lock);
        int old = g_cfg.wan[idx].state;
        switch (m->type) {
            case MSG_DOWN: handle_down(idx); if (old != WAN_DOWN) { pthread_mutex_unlock(&g_lock); trigger_reload(); pthread_mutex_lock(&g_lock); } break;
            case MSG_READY: handle_ready(idx); break;
            case MSG_CONFIRM: handle_confirm(idx); break;
            case MSG_ACTIVE: handle_active(idx); break;
        }
        pthread_mutex_unlock(&g_lock);
    }
    return NULL;
}

static void *health_thread(void *arg) {
    (void)arg;
    sleep(3);
    while (g_run) {
        sleep(CHK_INTERVAL);
        if (!g_run) break;

        int need_reload = 0;
        time_t now = time(NULL);
        pthread_mutex_lock(&g_lock);

        for (int i = 0; i < g_cfg.nwan; i++) {
            struct wan_t *w = &g_cfg.wan[i];
            int ok = iface_up(w->iface) && ping_ok(w->iface, w->peer_ip);

            switch (w->state) {
            case WAN_UP:
                if (!ok && ++w->ping_fail >= PING_FAIL_MAX) {
                    printf("[WAN%d] ping fail -> DOWN\n", i);
                    w->state = WAN_DOWN; reset_wan(i); need_reload = 1;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_DOWN); pthread_mutex_lock(&g_lock);
                } else if (ok) w->ping_fail = 0;
                break;
            case WAN_DOWN:
                if (ok) {
                    printf("[WAN%d] ready, handshake\n", i);
                    w->state = WAN_WAITING; w->l_ready = 1; w->wait_since = now;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_READY); pthread_mutex_lock(&g_lock);
                }
                break;
            case WAN_WAITING:
                if (!ok) {
                    w->state = WAN_DOWN; reset_wan(i); need_reload = 1;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_DOWN); pthread_mutex_lock(&g_lock);
                } else if (now - w->wait_since > HS_TIMEOUT) {
                    w->wait_since = now;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_READY); pthread_mutex_lock(&g_lock);
                }
                break;
            case WAN_CONFIRMED:
                if (!ok) {
                    w->state = WAN_DOWN; reset_wan(i); need_reload = 1;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_DOWN); pthread_mutex_lock(&g_lock);
                } else if (now - w->wait_since > HS_TIMEOUT) {
                    w->wait_since = now;
                    pthread_mutex_unlock(&g_lock); send_msg(i, MSG_ACTIVE); pthread_mutex_lock(&g_lock);
                }
                break;
            }
        }
        pthread_mutex_unlock(&g_lock);
        if (need_reload) trigger_reload();
    }
    return NULL;
}

static void *arp_thread(void *arg) {
    (void)arg;
    while (g_run) {
        if (g_bpf.arp_fd < 0) { sleep(2); continue; }
        FILE *fp = fopen("/proc/net/arp", "r");
        if (!fp) { sleep(2); continue; }

        char line[256];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            char ip[32], hw[16], fl[16], mac[32], msk[16], iface[32];
            if (sscanf(line, "%31s %15s %15s %31s %15s %31s", ip, hw, fl, mac, msk, iface) != 6) continue;
            if (!(strtol(fl, NULL, 16) & 0x02) || strcmp(iface, g_cfg.local_iface)) continue;

            __u32 ipn = ntohl(inet_addr(ip));
            unsigned m[6];
            if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                __u64 mv = 0;
                for (int j = 0; j < 6; j++) mv |= ((__u64)m[j]) << (j*8);
                bpf_map_update_elem(g_bpf.arp_fd, &ipn, &mv, BPF_ANY);
            }
        }
        fclose(fp);
        sleep(2);
    }
    return NULL;
}

// ==================== Main ====================

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <config> [bpf.o]\n", argv[0]); return 1; }
    strncpy(g_bpf_file, argc >= 3 ? argv[2] : "./tunnel.bpf.o", sizeof(g_bpf_file)-1);
    if (pipe(g_pipe) < 0) return 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (load_config(argv[1]) < 0) { fprintf(stderr, "Config error\n"); return 1; }
    if (init_sock() < 0) { fprintf(stderr, "Socket error\n"); return 1; }

    printf("=== XDP Tunnel ===\nLocal: %s, WANs: %d, Port: %d\n", g_cfg.local_iface, g_cfg.nwan, CTRL_PORT);

    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, ctrl_thread, NULL);

    // Initial handshake
    for (int i = 0; i < g_cfg.nwan; i++) {
        reset_wan(i);
        if (iface_up(g_cfg.wan[i].iface) && ping_ok(g_cfg.wan[i].iface, g_cfg.wan[i].peer_ip)) {
            g_cfg.wan[i].state = WAN_WAITING;
            g_cfg.wan[i].l_ready = 1;
            g_cfg.wan[i].wait_since = time(NULL);
            send_msg(i, MSG_READY);
        }
    }
    sleep(HS_TIMEOUT);
    reload_xdp();

    pthread_create(&t2, NULL, arp_thread, NULL);
    pthread_create(&t3, NULL, health_thread, NULL);

    printf("Running... Ctrl+C to stop\n");
    while (g_run) {
        fd_set fds; FD_ZERO(&fds); FD_SET(g_pipe[0], &fds);
        struct timeval tv = {1, 0};
        if (select(g_pipe[0]+1, &fds, NULL, NULL, &tv) > 0 && FD_ISSET(g_pipe[0], &fds)) {
            char c; read(g_pipe[0], &c, 1);
            reload_xdp();
        }
    }

    printf("\nShutting down...\n");
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t1, NULL);
    cleanup_bpf();
    if (g_sock >= 0) close(g_sock);
    close(g_pipe[0]); close(g_pipe[1]);
    return 0;
}
