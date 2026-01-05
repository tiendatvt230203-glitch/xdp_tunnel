// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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
#define CHK_INT 2
#define PING_TO 1
#define PING_FAIL 2
#define HS_TO 5

enum { DOWN=0, WAITING, CONFIRMED, UP };
enum { MSG_DOWN=0, MSG_READY, MSG_CONFIRM, MSG_ACTIVE };

struct wan_t {
    char iface[32], peer[32], myip[32];
    __u32 ifidx; __u8 mymac[6], peermac[6];
    int state, pfail, lr, pr, lc, pc, la, pa;
    time_t since;
};

struct cfg_t {
    char local[32]; __u32 lidx, rnet, rmask; __u8 lmac[6];
    int nwan; struct wan_t wan[MAX_WAN];
};

struct bpf_t { struct bpf_object *obj; int cfg, mac, arp, tx, rx; };
struct msg_t { char magic[4]; uint8_t type; char ip[32]; };

static volatile int run = 1;
static struct cfg_t C = {0};
static struct bpf_t B = {0};
static char bpf_file[256];
static int pfd[2], sock = -1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void sig(int s) { (void)s; run = 0; }
static void reload(void) { write(pfd[1], "R", 1); }
static __u64 m2u(const __u8 *m) { return (__u64)m[0]|((__u64)m[1]<<8)|((__u64)m[2]<<16)|((__u64)m[3]<<24)|((__u64)m[4]<<32)|((__u64)m[5]<<40); }

static int getmac(const char *f, __u8 *m) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return -1;
    struct ifreq r = {0}; strncpy(r.ifr_name, f, IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFHWADDR, &r); close(fd);
    if (!ret) memcpy(m, r.ifr_hwaddr.sa_data, 6); return ret;
}

static int getip(const char *f, char *ip, size_t l) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return -1;
    struct ifreq r = {0}; strncpy(r.ifr_name, f, IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFADDR, &r); close(fd);
    if (!ret) inet_ntop(AF_INET, &((struct sockaddr_in*)&r.ifr_addr)->sin_addr, ip, l); return ret;
}

static int ifup(const char *f) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return 0;
    struct ifreq r = {0}; strncpy(r.ifr_name, f, IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFFLAGS, &r); close(fd);
    return !ret && (r.ifr_flags & IFF_UP) && (r.ifr_flags & IFF_RUNNING);
}

static int pingok(const char *f, const char *ip) {
    if (!ip || !ip[0]) return 1;
    char cmd[256]; snprintf(cmd, sizeof(cmd), "ping -c1 -W%d -I %s %s >/dev/null 2>&1", PING_TO, f, ip);
    int r = system(cmd); return WIFEXITED(r) && !WEXITSTATUS(r);
}

static int getpeermac(const char *f, const char *ip, __u8 *m) {
    pingok(f, ip);
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return -1;
    struct arpreq q = {0}; ((struct sockaddr_in*)&q.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &((struct sockaddr_in*)&q.arp_pa)->sin_addr);
    strncpy(q.arp_dev, f, sizeof(q.arp_dev)-1);
    int ret = ioctl(fd, SIOCGARP, &q); close(fd);
    if (!ret) memcpy(m, q.arp_ha.sa_data, 6); return ret;
}

static int findwan(const char *ip, int peer) {
    for (int i=0; i<C.nwan; i++) if (!strcmp(peer ? C.wan[i].peer : C.wan[i].myip, ip)) return i;
    return -1;
}

static void reset(int i) { C.wan[i].lr=C.wan[i].pr=C.wan[i].lc=C.wan[i].pc=C.wan[i].la=C.wan[i].pa=C.wan[i].pfail=0; }

static void detach(void) {
    if (C.lidx) bpf_set_link_xdp_fd(C.lidx, -1, 0);
    for (int i=0; i<C.nwan; i++) if (C.wan[i].ifidx) bpf_set_link_xdp_fd(C.wan[i].ifidx, -1, 0);
}

static void cleanup(void) { detach(); if (B.obj) { bpf_object__close(B.obj); B.obj=NULL; } B.cfg=B.mac=B.arp=-1; }

static int xdp_reload(void) {
    cleanup(); usleep(100000);
    int cnt=0, idx[MAX_WAN];
    pthread_mutex_lock(&lock);
    for (int i=0; i<C.nwan; i++) if (C.wan[i].state==UP) idx[cnt++]=i;
    pthread_mutex_unlock(&lock);
    if (!cnt) return -1;

    B.obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(B.obj)) { B.obj=NULL; return -1; }
    if (bpf_object__load(B.obj)) { bpf_object__close(B.obj); B.obj=NULL; return -1; }

    B.cfg = bpf_object__find_map_fd_by_name(B.obj, "config");
    B.mac = bpf_object__find_map_fd_by_name(B.obj, "macs");
    B.arp = bpf_object__find_map_fd_by_name(B.obj, "arp_cache");
    struct bpf_program *tx = bpf_object__find_program_by_name(B.obj, "xdp_tx");
    struct bpf_program *rx = bpf_object__find_program_by_name(B.obj, "xdp_rx");
    if (!tx || !rx || B.cfg<0 || B.mac<0) { cleanup(); return -1; }
    B.tx = bpf_program__fd(tx); B.rx = bpf_program__fd(rx);

    __u32 k, v;
    k=0; v=cnt; bpf_map_update_elem(B.cfg, &k, &v, BPF_ANY);
    k=1; v=C.rnet; bpf_map_update_elem(B.cfg, &k, &v, BPF_ANY);
    k=2; v=C.rmask; bpf_map_update_elem(B.cfg, &k, &v, BPF_ANY);
    k=3; v=C.lidx; bpf_map_update_elem(B.cfg, &k, &v, BPF_ANY);
    for (int i=0; i<cnt; i++) { k=4+i; v=C.wan[idx[i]].ifidx; bpf_map_update_elem(B.cfg, &k, &v, BPF_ANY); }

    __u64 mac;
    for (int i=0; i<cnt; i++) {
        k=i; mac=m2u(C.wan[idx[i]].mymac); bpf_map_update_elem(B.mac, &k, &mac, BPF_ANY);
        k=i+MAX_WAN; mac=m2u(C.wan[idx[i]].peermac); bpf_map_update_elem(B.mac, &k, &mac, BPF_ANY);
    }
    k=6; mac=m2u(C.lmac); bpf_map_update_elem(B.mac, &k, &mac, BPF_ANY);

    if (bpf_set_link_xdp_fd(C.lidx, B.tx, 0) < 0) { cleanup(); return -1; }
    for (int i=0; i<cnt; i++) if (bpf_set_link_xdp_fd(C.wan[idx[i]].ifidx, B.rx, 0) < 0) { cleanup(); return -1; }
    return 0;
}

static int loadcfg(const char *p) {
    FILE *f = fopen(p, "r"); if (!f) return -1;
    memset(&C, 0, sizeof(C));
    char line[256], key[32], v1[64], v2[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0]=='#' || line[0]=='\n') continue;
        v2[0]=0; int n = sscanf(line, "%31s %63s %63s", key, v1, v2); if (n<2) continue;
        if (!strcmp(key, "local")) {
            strncpy(C.local, v1, sizeof(C.local)-1);
            C.lidx = if_nametoindex(v1); getmac(v1, C.lmac);
        } else if (!strcmp(key, "remote")) {
            char buf[64]; strncpy(buf, v1, sizeof(buf)-1);
            char *sl = strchr(buf, '/'); int pfx = 24;
            if (sl) { *sl=0; pfx=atoi(sl+1); }
            C.rnet = ntohl(inet_addr(buf));
            C.rmask = pfx ? (0xFFFFFFFF << (32-pfx)) : 0;
        } else if (!strcmp(key, "wan") && C.nwan < MAX_WAN) {
            struct wan_t *w = &C.wan[C.nwan++];
            strncpy(w->iface, v1, sizeof(w->iface)-1);
            w->ifidx = if_nametoindex(v1); w->state = DOWN;
            getmac(v1, w->mymac); getip(v1, w->myip, sizeof(w->myip));
            if (n>=3) { strncpy(w->peer, v2, sizeof(w->peer)-1); getpeermac(v1, v2, w->peermac); }
        }
    }
    fclose(f); return C.nwan > 0 ? 0 : -1;
}

static void sendmsg(int i, int type) {
    struct msg_t m = {{'X','D','P','C'}, type}; strncpy(m.ip, C.wan[i].peer, sizeof(m.ip)-1);
    for (int j=0; j<C.nwan; j++) {
        if (C.wan[j].state != UP || !C.wan[j].peer[0]) continue;
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(CTRL_PORT)};
        inet_pton(AF_INET, C.wan[j].peer, &a.sin_addr);
        sendto(sock, &m, sizeof(m), 0, (struct sockaddr*)&a, sizeof(a));
    }
    if (type != MSG_DOWN && C.wan[i].peer[0]) {
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(CTRL_PORT)};
        inet_pton(AF_INET, C.wan[i].peer, &a.sin_addr);
        sendto(sock, &m, sizeof(m), 0, (struct sockaddr*)&a, sizeof(a));
    }
}

static void h_down(int i) { if (C.wan[i].state==DOWN) return; C.wan[i].state=DOWN; reset(i); }

static void h_ready(int i) {
    if (!ifup(C.wan[i].iface) || !pingok(C.wan[i].iface, C.wan[i].peer)) return;
    C.wan[i].pr = 1;
    if (!C.wan[i].lr) { C.wan[i].lr=1; C.wan[i].state=WAITING; C.wan[i].since=time(NULL); pthread_mutex_unlock(&lock); sendmsg(i, MSG_READY); pthread_mutex_lock(&lock); }
    if (C.wan[i].lr && C.wan[i].pr && !C.wan[i].lc) { C.wan[i].lc=1; pthread_mutex_unlock(&lock); sendmsg(i, MSG_CONFIRM); pthread_mutex_lock(&lock); }
}

static void h_confirm(int i) {
    C.wan[i].pc = 1;
    if (C.wan[i].lr && C.wan[i].pr && !C.wan[i].lc) { C.wan[i].lc=1; pthread_mutex_unlock(&lock); sendmsg(i, MSG_CONFIRM); pthread_mutex_lock(&lock); }
    if (C.wan[i].lc && C.wan[i].pc && C.wan[i].state!=CONFIRMED && C.wan[i].state!=UP) {
        C.wan[i].state=CONFIRMED; C.wan[i].la=1; C.wan[i].since=time(NULL);
        pthread_mutex_unlock(&lock); sendmsg(i, MSG_ACTIVE); pthread_mutex_lock(&lock);
    }
}

static void h_active(int i) {
    C.wan[i].pa = 1;
    if (C.wan[i].lc && C.wan[i].pr && !C.wan[i].la) { C.wan[i].la=1; C.wan[i].state=CONFIRMED; pthread_mutex_unlock(&lock); sendmsg(i, MSG_ACTIVE); pthread_mutex_lock(&lock); }
    if (C.wan[i].la && C.wan[i].pa && C.wan[i].state!=UP) { C.wan[i].state=UP; pthread_mutex_unlock(&lock); reload(); pthread_mutex_lock(&lock); }
}

static void *ctrl_th(void *arg) {
    (void)arg; char buf[256]; struct sockaddr_in from; socklen_t flen;
    while (run) {
        fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
        struct timeval tv = {1, 0}; if (select(sock+1, &fds, NULL, NULL, &tv) <= 0) continue;
        flen = sizeof(from);
        if (recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen) < (ssize_t)sizeof(struct msg_t)) continue;
        struct msg_t *m = (struct msg_t*)buf;
        if (memcmp(m->magic, "XDPC", 4)) continue;
        int idx = findwan(m->ip, 0); if (idx<0) idx = findwan(m->ip, 1); if (idx<0) continue;
        pthread_mutex_lock(&lock);
        int old = C.wan[idx].state;
        switch (m->type) {
            case MSG_DOWN: h_down(idx); if (old!=DOWN) { pthread_mutex_unlock(&lock); reload(); pthread_mutex_lock(&lock); } break;
            case MSG_READY: h_ready(idx); break;
            case MSG_CONFIRM: h_confirm(idx); break;
            case MSG_ACTIVE: h_active(idx); break;
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

static void *health_th(void *arg) {
    (void)arg; sleep(3);
    while (run) {
        sleep(CHK_INT); if (!run) break;
        int need = 0; time_t now = time(NULL);
        pthread_mutex_lock(&lock);
        for (int i=0; i<C.nwan; i++) {
            int ok = ifup(C.wan[i].iface) && pingok(C.wan[i].iface, C.wan[i].peer);
            switch (C.wan[i].state) {
                case UP:
                    if (!ok && ++C.wan[i].pfail >= PING_FAIL) { C.wan[i].state=DOWN; reset(i); need=1; pthread_mutex_unlock(&lock); sendmsg(i, MSG_DOWN); pthread_mutex_lock(&lock); }
                    else if (ok) C.wan[i].pfail=0;
                    break;
                case DOWN:
                    if (ok) { C.wan[i].state=WAITING; C.wan[i].lr=1; C.wan[i].since=now; pthread_mutex_unlock(&lock); sendmsg(i, MSG_READY); pthread_mutex_lock(&lock); }
                    break;
                case WAITING:
                    if (!ok) { C.wan[i].state=DOWN; reset(i); need=1; pthread_mutex_unlock(&lock); sendmsg(i, MSG_DOWN); pthread_mutex_lock(&lock); }
                    else if (now - C.wan[i].since > HS_TO) { C.wan[i].since=now; pthread_mutex_unlock(&lock); sendmsg(i, MSG_READY); pthread_mutex_lock(&lock); }
                    break;
                case CONFIRMED:
                    if (!ok) { C.wan[i].state=DOWN; reset(i); need=1; pthread_mutex_unlock(&lock); sendmsg(i, MSG_DOWN); pthread_mutex_lock(&lock); }
                    else if (now - C.wan[i].since > HS_TO) { C.wan[i].since=now; pthread_mutex_unlock(&lock); sendmsg(i, MSG_ACTIVE); pthread_mutex_lock(&lock); }
                    break;
            }
        }
        pthread_mutex_unlock(&lock);
        if (need) reload();
    }
    return NULL;
}

static void *arp_th(void *arg) {
    (void)arg;
    while (run) {
        if (B.arp < 0) { sleep(2); continue; }
        FILE *fp = fopen("/proc/net/arp", "r"); if (!fp) { sleep(2); continue; }
        char line[256]; fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            char ip[32], hw[16], fl[16], mac[32], msk[16], iface[32];
            if (sscanf(line, "%31s %15s %15s %31s %15s %31s", ip, hw, fl, mac, msk, iface) != 6) continue;
            if (!(strtol(fl, NULL, 16) & 0x02) || strcmp(iface, C.local)) continue;
            __u32 ipn = ntohl(inet_addr(ip)); unsigned m[6];
            if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                __u64 mv = 0; for (int j=0; j<6; j++) mv |= ((__u64)m[j]) << (j*8);
                bpf_map_update_elem(B.arp, &ipn, &mv, BPF_ANY);
            }
        }
        fclose(fp); sleep(2);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <config> [bpf.o]\n", argv[0]); return 1; }
    strncpy(bpf_file, argc >= 3 ? argv[2] : "./tunnel.bpf.o", sizeof(bpf_file)-1);
    if (pipe(pfd) < 0) return 1;
    signal(SIGINT, sig); signal(SIGTERM, sig);
    if (loadcfg(argv[1]) < 0) { fprintf(stderr, "Config error\n"); return 1; }

    sock = socket(AF_INET, SOCK_DGRAM, 0); if (sock < 0) return 1;
    int opt = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(CTRL_PORT)};
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) return 1;

    pthread_t t1; pthread_create(&t1, NULL, ctrl_th, NULL);
    for (int i=0; i<C.nwan; i++) {
        reset(i);
        if (ifup(C.wan[i].iface) && pingok(C.wan[i].iface, C.wan[i].peer)) {
            C.wan[i].state=WAITING; C.wan[i].lr=1; C.wan[i].since=time(NULL); sendmsg(i, MSG_READY);
        }
    }
    sleep(HS_TO); xdp_reload();

    pthread_t t2, t3;
    pthread_create(&t2, NULL, arp_th, NULL);
    pthread_create(&t3, NULL, health_th, NULL);

    while (run) {
        fd_set fds; FD_ZERO(&fds); FD_SET(pfd[0], &fds);
        struct timeval tv = {1, 0};
        if (select(pfd[0]+1, &fds, NULL, NULL, &tv) > 0 && FD_ISSET(pfd[0], &fds)) { char c; read(pfd[0], &c, 1); xdp_reload(); }
    }

    pthread_join(t2, NULL); pthread_join(t3, NULL); pthread_join(t1, NULL);
    cleanup(); if (sock >= 0) close(sock); close(pfd[0]); close(pfd[1]);
    return 0;
}

