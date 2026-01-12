// tunnel_v4_fixed.c - minimal split/reassemble + RR LB + fixed peer MAC
// Usage: ./tunnel_v4_fixed <lan_if> <tun1> [tun2]

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define MAX_TUN 4
#define MAX_PKT 4096
#define SPLIT_TH 1000
#define TUN_ETYPE 0x88B5
#define MAGIC 0x53504C54
#define REASM_SLOTS 128

struct hdr {
    uint32_t magic;
    uint16_t id;
    uint8_t  part;   // 0/1
    uint8_t  total;  // 1 or 2
} __attribute__((packed));

struct tun {
    char name[16];
    int fd;
    int ifidx;
    uint8_t peer[6]; // fixed peer mac
};

static int lan_fd = -1, lan_ifidx = 0;
static struct tun tuns[MAX_TUN];
static int tun_cnt = 0;
static int rr = 0;
static uint16_t msg_id = 1;
static volatile int run = 1;

struct reasm_slot {
    uint16_t id;
    uint8_t buf[2][MAX_PKT];
    int len[2];
};
static struct reasm_slot reasm[REASM_SLOTS];

static void stop(int s){ (void)s; run = 0; }

static int ifidx(const char *n){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq i; memset(&i, 0, sizeof(i));
    strncpy(i.ifr_name, n, IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFINDEX, &i) < 0) { close(s); return -1; }
    close(s);
    return i.ifr_ifindex;
}

static int rawsock(int ifidx){
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll s; memset(&s, 0, sizeof(s));
    s.sll_family = AF_PACKET;
    s.sll_protocol = htons(ETH_P_ALL);
    s.sll_ifindex = ifidx;
    if (bind(fd,(void*)&s,sizeof(s)) < 0) { close(fd); return -1; }
    return fd;
}

static void send_raw(int fd, int ifidx, const uint8_t dst[6], const void *buf, int len){
    struct sockaddr_ll s; memset(&s, 0, sizeof(s));
    s.sll_family = AF_PACKET;
    s.sll_ifindex = ifidx;
    s.sll_halen = 6;
    memcpy(s.sll_addr, dst, 6);
    (void)sendto(fd, buf, len, 0, (void*)&s, sizeof(s));
}

// --------- CONFIG PEER MAC (HARDCODE) ----------
static void set_peer_macs_hardcode(void) {
    // Map đúng như bạn đưa:
    // Server01: ne_tunnel1 00:00:00:1d:14:da  -> peer = Server02 ne_tunnel1 00:00:00:b7:d5:8e
    // Server01: ne_tunnel2 00:00:00:57:3b:8c  -> peer = Server02 ne_tunnel2 00:00:00:19:4a:61
    // Server02: ne_tunnel1 00:00:00:b7:d5:8e  -> peer = Server01 ne_tunnel1 00:00:00:1d:14:da
    // Server02: ne_tunnel2 00:00:00:19:4a:61  -> peer = Server01 ne_tunnel2 00:00:00:57:3b:8c

    for (int i = 0; i < tun_cnt; i++) {
        if (!strcmp(tuns[i].name, "ne_tunnel1")) {
            // Bạn chạy cùng binary ở cả 2 server => peer tùy phía.
            // Cách đơn giản: dùng argv order để set tay theo host.
            // Ở đây set DEFAULT = broadcast, rồi bạn sửa đúng theo server.
            // --- SỬA Ở ĐÂY ---
            // Ví dụ Server01:
            // uint8_t peer[6] = {0x00,0x00,0x00,0xb7,0xd5,0x8e};
            // Ví dụ Server02:
            // uint8_t peer[6] = {0x00,0x00,0x00,0x1d,0x14,0xda};

            uint8_t peer[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // TODO set đúng
            memcpy(tuns[i].peer, peer, 6);
        } else if (!strcmp(tuns[i].name, "ne_tunnel2")) {
            // Ví dụ Server01:
            // uint8_t peer[6] = {0x00,0x00,0x00,0x19,0x4a,0x61};
            // Ví dụ Server02:
            // uint8_t peer[6] = {0x00,0x00,0x00,0x57,0x3b,0x8c};

            uint8_t peer[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // TODO set đúng
            memcpy(tuns[i].peer, peer, 6);
        } else {
            memset(tuns[i].peer, 0xff, 6);
        }

        printf("[PEER] %s peer=%02x:%02x:%02x:%02x:%02x:%02x\n",
               tuns[i].name,
               tuns[i].peer[0], tuns[i].peer[1], tuns[i].peer[2],
               tuns[i].peer[3], tuns[i].peer[4], tuns[i].peer[5]);
    }
}

// ---------- LAN -> TUN ----------
static void lan_rx(const uint8_t *frame, int len){
    if (len < ETH_HLEN) return;

    int t = rr++ % tun_cnt;
    printf("[LAN->TUN] len=%d via %s\n", len, tuns[t].name);

    uint8_t out[MAX_PKT];
    struct ethhdr *e = (void*)out;
    struct hdr *h = (void*)(out + ETH_HLEN);

    memcpy(e->h_dest, tuns[t].peer, 6);
    memset(e->h_source, 0x02, 6);
    e->h_proto = htons(TUN_ETYPE);

    if (len <= SPLIT_TH) {
        h->magic = htonl(MAGIC);
        h->id = htons(msg_id++);
        h->part = 0;
        h->total = 1;

        memcpy(out + ETH_HLEN + sizeof(*h), frame, len);
        send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer,
                 out, ETH_HLEN + (int)sizeof(*h) + len);
        return;
    }

    int half = len / 2;
    uint16_t id = msg_id++;

    h->magic = htonl(MAGIC);
    h->id = htons(id);
    h->total = 2;

    h->part = 0;
    memcpy(out + ETH_HLEN + sizeof(*h), frame, half);
    send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer,
             out, ETH_HLEN + (int)sizeof(*h) + half);

    h->part = 1;
    memcpy(out + ETH_HLEN + sizeof(*h), frame + half, len - half);
    send_raw(tuns[t].fd, tuns[t].ifidx, tuns[t].peer,
             out, ETH_HLEN + (int)sizeof(*h) + (len - half));
}

// ---------- TUN -> LAN ----------
static void tun_rx(const uint8_t *pkt, int len, int tidx){
    if (len < ETH_HLEN + (int)sizeof(struct hdr)) return;

    const struct ethhdr *e = (const void*)pkt;
    if (ntohs(e->h_proto) != TUN_ETYPE) return;

    const struct hdr *h = (const void*)(pkt + ETH_HLEN);
    if (ntohl(h->magic) != MAGIC) return;

    int total = h->total;
    int part  = h->part;
    uint16_t id = ntohs(h->id);

    int plen = len - ETH_HLEN - (int)sizeof(*h);
    const uint8_t *payload = pkt + ETH_HLEN + sizeof(*h);

    printf("[TUN->LAN] tun=%s id=%u part=%d/%d plen=%d\n",
           tuns[tidx].name, id, part, total, plen);

    // payload chứa FULL frame gốc => dst MAC = payload[0..5]
    if (plen < 6) return;

    if (total == 1) {
        const uint8_t *dst = payload; // 6 bytes đầu = dst mac của frame gốc
        send_raw(lan_fd, lan_ifidx, dst, payload, plen);
        return;
    }

    if (total != 2 || part > 1) return;

    int slot = id % REASM_SLOTS;
    struct reasm_slot *r = &reasm[slot];

    if (r->id != id) {
        r->id = id;
        r->len[0] = r->len[1] = 0;
    }

    if (plen > MAX_PKT) return;
    if (r->len[part] == 0) {
        memcpy(r->buf[part], payload, plen);
        r->len[part] = plen;
    }

    if (r->len[0] && r->len[1]) {
        uint8_t out[MAX_PKT * 2];
        int outlen = r->len[0] + r->len[1];
        memcpy(out, r->buf[0], r->len[0]);
        memcpy(out + r->len[0], r->buf[1], r->len[1]);

        const uint8_t *dst = out; // dst mac = 6 bytes đầu của frame gốc
        printf("[TUN->LAN] reassembled len=%d -> LAN\n", outlen);

        send_raw(lan_fd, lan_ifidx, dst, out, outlen);

        r->len[0] = r->len[1] = 0;
    }
}

static void *lan_loop(void *x){
    (void)x;
    uint8_t b[MAX_PKT];
    while(run){
        ssize_t n = recv(lan_fd, b, sizeof(b), 0);
        if (n <= 0) continue;

        // skip frames we injected (dummy src 0x02)
        if (n >= ETH_HLEN && ((struct ethhdr*)b)->h_source[0] == 0x02) continue;

        lan_rx(b, (int)n);
    }
    return NULL;
}

static void *tun_loop(void *x){
    (void)x;
    struct pollfd p[MAX_TUN];
    uint8_t b[MAX_PKT];

    for(int i=0;i<tun_cnt;i++){ p[i].fd=tuns[i].fd; p[i].events=POLLIN; }

    while(run){
        if (poll(p, tun_cnt, 100) <= 0) continue;

        for(int i=0;i<tun_cnt;i++){
            if (!(p[i].revents & POLLIN)) continue;

            ssize_t n = recv(tuns[i].fd, b, sizeof(b), 0);
            if (n <= 0) continue;

            if (n >= ETH_HLEN && ((struct ethhdr*)b)->h_source[0] == 0x02) continue;

            // FIX #1: dùng length thật
            tun_rx(b, (int)n, i);
        }
    }
    return NULL;
}

int main(int c,char**v){
    if (c < 3) {
        printf("Usage: %s <lan_if> <tun1> [tun2...]\n", v[0]);
        return 1;
    }

    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    lan_ifidx = ifidx(v[1]);
    if (lan_ifidx < 0) { printf("Bad lan if\n"); return 1; }

    lan_fd = rawsock(lan_ifidx);
    if (lan_fd < 0) { printf("LAN rawsock fail\n"); return 1; }
    printf("[INIT] LAN=%s ifidx=%d\n", v[1], lan_ifidx);

    for(int i=2;i<c && tun_cnt<MAX_TUN;i++){
        strncpy(tuns[tun_cnt].name, v[i], 15);
        tuns[tun_cnt].ifidx = ifidx(v[i]);
        if (tuns[tun_cnt].ifidx < 0) { printf("Bad tun %s\n", v[i]); continue; }

        tuns[tun_cnt].fd = rawsock(tuns[tun_cnt].ifidx);
        if (tuns[tun_cnt].fd < 0) { printf("Tun rawsock fail %s\n", v[i]); continue; }

        tun_cnt++;
    }
    if (!tun_cnt) { printf("No tunnels\n"); return 1; }

    // FIX #3: set peer MAC fixed (bạn sửa TODO cho đúng theo Server01/02)
    set_peer_macs_hardcode();

    pthread_t a,b;
    pthread_create(&a, 0, lan_loop, 0);
    pthread_create(&b, 0, tun_loop, 0);

    printf("[RUN] RR LB across %d tunnels, split>%d\n", tun_cnt, SPLIT_TH);
    while(run) sleep(1);

    pthread_join(a,0);
    pthread_join(b,0);
    return 0;
}

