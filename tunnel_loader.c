// Simple XDP Tunnel Loader - Per-window load balancing test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef bpf_xdp_attach
#define bpf_xdp_attach(ifindex, fd, flags, opts) bpf_set_link_xdp_fd(ifindex, fd, flags)
#define bpf_xdp_detach(ifindex, flags, opts) bpf_set_link_xdp_fd(ifindex, -1, flags)
#endif

#define MAX_WAN 3

struct wan_t { char iface[32]; __u32 ifidx; __u8 mymac[6], peermac[6]; char peer[32]; };
struct cfg_t { char local[32]; __u32 lidx, rnet, rmask; __u8 lmac[6]; int nwan; struct wan_t wan[MAX_WAN]; };

static volatile int run = 1;
static struct cfg_t C;
static struct bpf_object *obj;
static int cfg_fd, mac_fd, arp_fd;

static void sig(int s) { (void)s; run = 0; }
static __u64 m2u(__u8 *m) { return (__u64)m[0]|((__u64)m[1]<<8)|((__u64)m[2]<<16)|((__u64)m[3]<<24)|((__u64)m[4]<<32)|((__u64)m[5]<<40); }

static int getmac(const char *f, __u8 *m) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return -1;
    struct ifreq r = {0}; strncpy(r.ifr_name, f, IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFHWADDR, &r); close(fd);
    if (!ret) memcpy(m, r.ifr_hwaddr.sa_data, 6); return ret;
}

static int getpeermac(const char *f, const char *ip, __u8 *m) {
    char cmd[128]; snprintf(cmd, sizeof(cmd), "ping -c1 -W1 -I %s %s >/dev/null 2>&1", f, ip);
    (void)system(cmd);
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd<0) return -1;
    struct arpreq q = {0}; ((struct sockaddr_in*)&q.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &((struct sockaddr_in*)&q.arp_pa)->sin_addr);
    strncpy(q.arp_dev, f, sizeof(q.arp_dev)-1);
    int ret = ioctl(fd, SIOCGARP, &q); close(fd);
    if (!ret) memcpy(m, q.arp_ha.sa_data, 6); return ret;
}

static int loadcfg(const char *p) {
    FILE *f = fopen(p, "r"); if (!f) return -1;
    memset(&C, 0, sizeof(C));
    char line[256], key[32], v1[64], v2[64];
    while (fgets(line, sizeof(line), f)) {
        if (line[0]=='#' || line[0]=='\n') continue;
        v2[0]=0; int n = sscanf(line, "%31s %63s %63s", key, v1, v2); if (n<2) continue;
        if (!strcmp(key, "local")) {
            strncpy(C.local, v1, 31); C.lidx = if_nametoindex(v1); getmac(v1, C.lmac);
        } else if (!strcmp(key, "remote")) {
            char buf[64]; strncpy(buf, v1, 63);
            char *sl = strchr(buf, '/'); int pfx = 24; if (sl) { *sl=0; pfx=atoi(sl+1); }
            C.rnet = ntohl(inet_addr(buf)); C.rmask = pfx ? (0xFFFFFFFF << (32-pfx)) : 0;
        } else if (!strcmp(key, "wan") && C.nwan < MAX_WAN) {
            struct wan_t *w = &C.wan[C.nwan++];
            strncpy(w->iface, v1, 31); w->ifidx = if_nametoindex(v1); getmac(v1, w->mymac);
            if (n>=3) { strncpy(w->peer, v2, 31); getpeermac(v1, v2, w->peermac); }
        }
    }
    fclose(f); return C.nwan > 0 ? 0 : -1;
}

static void detach(void) {
    if (C.lidx) bpf_xdp_detach(C.lidx, 0, NULL);
    for (int i=0; i<C.nwan; i++) if (C.wan[i].ifidx) bpf_xdp_detach(C.wan[i].ifidx, 0, NULL);
}

static int load_xdp(const char *file) {
    obj = bpf_object__open_file(file, NULL);
    if (libbpf_get_error(obj)) { obj=NULL; return -1; }
    if (bpf_object__load(obj)) { bpf_object__close(obj); obj=NULL; return -1; }

    cfg_fd = bpf_object__find_map_fd_by_name(obj, "config");
    mac_fd = bpf_object__find_map_fd_by_name(obj, "macs");
    arp_fd = bpf_object__find_map_fd_by_name(obj, "arp_cache");
    struct bpf_program *tx = bpf_object__find_program_by_name(obj, "xdp_tx");
    struct bpf_program *rx = bpf_object__find_program_by_name(obj, "xdp_rx");
    if (!tx || !rx || cfg_fd<0 || mac_fd<0) return -1;

    __u32 k, v; __u64 m;
    k=0; v=C.nwan; bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);
    k=1; v=C.rnet; bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);
    k=2; v=C.rmask; bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);
    k=3; v=C.lidx; bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);

    for (int i=0; i<C.nwan; i++) {
        k=4+i; v=C.wan[i].ifidx; bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY);
        k=i; m=m2u(C.wan[i].mymac); bpf_map_update_elem(mac_fd, &k, &m, BPF_ANY);
        k=i+MAX_WAN; m=m2u(C.wan[i].peermac); bpf_map_update_elem(mac_fd, &k, &m, BPF_ANY);
    }
    k=6; m=m2u(C.lmac); bpf_map_update_elem(mac_fd, &k, &m, BPF_ANY);

    if (bpf_xdp_attach(C.lidx, bpf_program__fd(tx), 0, NULL) < 0) return -1;
    printf("TX -> %s\n", C.local);
    for (int i=0; i<C.nwan; i++) {
        if (bpf_xdp_attach(C.wan[i].ifidx, bpf_program__fd(rx), 0, NULL) < 0) return -1;
        printf("RX -> %s (%s)\n", C.wan[i].iface, C.wan[i].peer);
    }
    printf("Loaded: %d WANs, per-window LB\n", C.nwan);
    return 0;
}

static void update_arp(void) {
    FILE *fp = fopen("/proc/net/arp", "r"); if (!fp) return;
    char line[256]; (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        char ip[32], hw[16], fl[16], mac[32], msk[16], iface[32];
        if (sscanf(line, "%31s %15s %15s %31s %15s %31s", ip, hw, fl, mac, msk, iface) != 6) continue;
        if (!(strtol(fl, NULL, 16) & 0x02) || strcmp(iface, C.local)) continue;
        __u32 ipn = ntohl(inet_addr(ip)); unsigned mb[6];
        if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &mb[0],&mb[1],&mb[2],&mb[3],&mb[4],&mb[5]) == 6) {
            __u64 mv = 0; for (int j=0; j<6; j++) mv |= ((__u64)mb[j]) << (j*8);
            bpf_map_update_elem(arp_fd, &ipn, &mv, BPF_ANY);
        }
    }
    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <config> [bpf.o]\n", argv[0]); return 1; }
    signal(SIGINT, sig); signal(SIGTERM, sig);

    if (loadcfg(argv[1]) < 0) { fprintf(stderr, "Config error\n"); return 1; }
    printf("Local: %s, Remote: %u.%u.%u.%u/%d, WANs: %d\n", C.local,
        (C.rnet>>24)&0xff, (C.rnet>>16)&0xff, (C.rnet>>8)&0xff, C.rnet&0xff,
        __builtin_popcount(C.rmask), C.nwan);

    if (load_xdp(argc >= 3 ? argv[2] : "./tunnel.bpf.o") < 0) {
        fprintf(stderr, "XDP load failed\n"); detach(); return 1;
    }

    printf("Running... Ctrl+C to stop\n");
    while (run) { update_arp(); sleep(2); }

    printf("Stopping...\n");
    detach();
    if (obj) bpf_object__close(obj);
    return 0;
}
