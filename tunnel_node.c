// tunnel_node.c - Bidirectional encrypted tunnel with AF_XDP
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/if_xdp.h>
#include <arpa/inet.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "tunnel.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE 32

// XSK context
struct xsk_ctx {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx, fq;
    struct xsk_ring_cons cq;
    void *umem_area;
    uint32_t frames[NUM_FRAMES];
    uint32_t frame_cnt;
    int ifidx;
    char ifname[16];
};

// WAN context
struct wan_ctx {
    struct xsk_ctx xsk;
    uint8_t local_mac[6];
    uint8_t peer_mac[6];
    uint64_t tx_seq;
    uint64_t rx_last_seq;
};

// Globals
static struct xsk_ctx lan_ctx;
static struct wan_ctx wan[MAX_WAN];
static int wan_cnt = 0;
static volatile int run = 1;
static uint8_t key[KEY_SIZE];
static uint8_t node_id[NODE_ID_SIZE];
static uint16_t key_id = 1;

static void sig_handler(int s) { (void)s; run = 0; }

static uint64_t alloc_frame(struct xsk_ctx *ctx) {
    return ctx->frame_cnt ? ctx->frames[--ctx->frame_cnt] : UINT64_MAX;
}

static void free_frame(struct xsk_ctx *ctx, uint64_t f) {
    if (ctx->frame_cnt < NUM_FRAMES) ctx->frames[ctx->frame_cnt++] = f;
}

static void get_mac(const char *ifname, uint8_t *mac) {
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (f) {
        unsigned int m[6];
        if (fscanf(f, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6)
            for (int i = 0; i < 6; i++) mac[i] = m[i];
        fclose(f);
    }
}

// 5-tuple hash
static uint32_t flow_hash(const uint8_t *pkt, int len) {
    if (len < ETH_HLEN + 20) return 0;
    const struct iphdr *ip = (void*)(pkt + ETH_HLEN);
    uint32_t h = ip->saddr ^ ip->daddr ^ ip->protocol;
    int ihl = ip->ihl * 4;
    if (len >= ETH_HLEN + ihl + 4) {
        const uint16_t *p = (void*)(pkt + ETH_HLEN + ihl);
        h ^= (p[0] << 16) | p[1];
    }
    h ^= h >> 16;
    h *= 0x85ebca6b;
    return h;
}

// Nonce
static void build_nonce(uint8_t *nonce, uint8_t path_id, uint64_t seq) {
    memcpy(nonce, node_id, 4);
    nonce[4] = path_id;
    nonce[5] = key_id & 0xff;
    nonce[6] = (seq >> 40) & 0xff;
    nonce[7] = (seq >> 32) & 0xff;
    nonce[8] = (seq >> 24) & 0xff;
    nonce[9] = (seq >> 16) & 0xff;
    nonce[10] = (seq >> 8) & 0xff;
    nonce[11] = seq & 0xff;
}

static int aead_encrypt(const uint8_t *plain, int plen, uint8_t *cipher,
                        const uint8_t *aad, int aad_len, const uint8_t *nonce, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, clen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    EVP_EncryptUpdate(ctx, cipher, &len, plain, plen);
    clen = len;
    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

static int aead_decrypt(const uint8_t *cipher, int clen, uint8_t *plain,
                        const uint8_t *aad, int aad_len, const uint8_t *nonce, const uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, plen = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    EVP_DecryptUpdate(ctx, plain, &len, cipher, clen);
    plen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, plain + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0 ? plen + len : -1;
}

// XSK setup using libxdp
static int xsk_setup(struct xsk_ctx *ctx, const char *ifname) {
    strncpy(ctx->ifname, ifname, 15);
    ctx->ifidx = if_nametoindex(ifname);
    if (!ctx->ifidx) return -1;

    size_t sz = NUM_FRAMES * FRAME_SIZE;
    ctx->umem_area = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
    if (ctx->umem_area == MAP_FAILED) {
        // Fallback to regular pages
        ctx->umem_area = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (ctx->umem_area == MAP_FAILED) return -1;
    }

    struct xsk_umem_config ucfg = {
        .fill_size = 4096,
        .comp_size = 4096,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    if (xsk_umem__create(&ctx->umem, ctx->umem_area, sz, &ctx->fq, &ctx->cq, &ucfg)) {
        munmap(ctx->umem_area, sz);
        return -1;
    }

    for (uint32_t i = 0; i < NUM_FRAMES; i++) ctx->frames[i] = i * FRAME_SIZE;
    ctx->frame_cnt = NUM_FRAMES;

    struct xsk_socket_config xcfg = {
        .rx_size = 4096,
        .tx_size = 4096,
        .libxdp_flags = 0,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP
    };

    int ret = xsk_socket__create(&ctx->xsk, ifname, 0, ctx->umem, &ctx->rx, &ctx->tx, &xcfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create(%s) failed: %d\n", ifname, ret);
        xsk_umem__delete(ctx->umem);
        munmap(ctx->umem_area, sz);
        return -1;
    }

    // Fill the fill queue
    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&ctx->fq, 4096, &idx) == 4096) {
        for (int i = 0; i < 4096; i++)
            *xsk_ring_prod__fill_addr(&ctx->fq, idx + i) = alloc_frame(ctx);
        xsk_ring_prod__submit(&ctx->fq, 4096);
    }

    return 0;
}

static void xsk_cleanup(struct xsk_ctx *ctx) {
    if (ctx->xsk) xsk_socket__delete(ctx->xsk);
    if (ctx->umem) xsk_umem__delete(ctx->umem);
    if (ctx->umem_area) munmap(ctx->umem_area, NUM_FRAMES * FRAME_SIZE);
}

static void xsk_tx(struct xsk_ctx *ctx, const void *data, int len) {
    uint32_t idx_cq;
    unsigned int comp = xsk_ring_cons__peek(&ctx->cq, 64, &idx_cq);
    if (comp) {
        for (unsigned int i = 0; i < comp; i++)
            free_frame(ctx, *xsk_ring_cons__comp_addr(&ctx->cq, idx_cq + i));
        xsk_ring_cons__release(&ctx->cq, comp);
    }

    uint32_t idx_tx;
    if (xsk_ring_prod__reserve(&ctx->tx, 1, &idx_tx) != 1) return;

    uint64_t addr = alloc_frame(ctx);
    if (addr == UINT64_MAX) return;

    memcpy(xsk_umem__get_data(ctx->umem_area, addr), data, len);
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&ctx->tx, idx_tx);
    d->addr = addr;
    d->len = len;
    xsk_ring_prod__submit(&ctx->tx, 1);

    if (xsk_ring_prod__needs_wakeup(&ctx->tx))
        sendto(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void xsk_refill_fq(struct xsk_ctx *ctx, unsigned int n) {
    uint32_t fi = 0;
    unsigned int fr = xsk_prod_nb_free(&ctx->fq, n);
    if (fr && xsk_ring_prod__reserve(&ctx->fq, fr, &fi) == fr) {
        for (unsigned int i = 0; i < fr; i++)
            *xsk_ring_prod__fill_addr(&ctx->fq, fi + i) = alloc_frame(ctx);
        xsk_ring_prod__submit(&ctx->fq, fr);
    }
}

static void load_key(const char *keyfile) {
    FILE *f = fopen(keyfile, "rb");
    if (f) {
        if (fread(key, 1, KEY_SIZE, f) != KEY_SIZE)
            RAND_bytes(key, KEY_SIZE);
        fclose(f);
    } else {
        RAND_bytes(key, KEY_SIZE);
    }
    memcpy(node_id, key, NODE_ID_SIZE);
}

// Check if packet is tunnel frame
static int is_tunnel_frame(const uint8_t *pkt, int len) {
    if (len < ETH_HLEN) return 0;
    struct ethhdr *eth = (void*)pkt;
    return ntohs(eth->h_proto) == TUN_ETYPE;
}

// Check if packet is IP
static int is_ip_frame(const uint8_t *pkt, int len) {
    if (len < ETH_HLEN) return 0;
    struct ethhdr *eth = (void*)pkt;
    return ntohs(eth->h_proto) == ETH_P_IP;
}

// LAN RX thread: receive from LAN -> encrypt -> send to WAN
static void *lan_rx_loop(void *arg) {
    (void)arg;
    uint8_t out[MAX_PKT];

    while (run) {
        uint32_t idx = 0;
        unsigned int n = xsk_ring_cons__peek(&lan_ctx.rx, BATCH_SIZE, &idx);
        if (!n) {
            struct pollfd pfd = {.fd = xsk_socket__fd(lan_ctx.xsk), .events = POLLIN};
            poll(&pfd, 1, 10);
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&lan_ctx.rx, idx + i)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&lan_ctx.rx, idx + i)->len;
            uint8_t *pkt = xsk_umem__get_data(lan_ctx.umem_area, addr);

            // Only process IP packets, skip others
            if (!is_ip_frame(pkt, len)) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            if (len > MAX_INNER_LEN || len < ETH_HLEN) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            uint32_t h = flow_hash(pkt, len);
            int path = h % wan_cnt;
            struct wan_ctx *w = &wan[path];

            struct ethhdr *eth = (void*)out;
            memcpy(eth->h_dest, w->peer_mac, 6);
            memcpy(eth->h_source, w->local_mac, 6);
            eth->h_proto = htons(TUN_ETYPE);

            uint64_t seq = __sync_add_and_fetch(&w->tx_seq, 1);
            struct tun_hdr *hdr = (void*)(out + ETH_HLEN);
            hdr->ver = TUN_VERSION;
            hdr->flags = TUN_FLAG_ENCRYPTED;
            hdr->key_id = htons(key_id);
            hdr->path_id = path;
            hdr->reserved = 0;
            hdr->inner_len = htons(len);
            hdr->seq = htobe64(seq);

            uint8_t nonce[NONCE_SIZE];
            build_nonce(nonce, path, seq);
            uint8_t *cipher = out + ETH_HLEN + TUN_HDR_SIZE;
            uint8_t *tag = cipher + len;

            if (aead_encrypt(pkt, len, cipher, (uint8_t*)hdr, TUN_HDR_SIZE, nonce, tag) < 0) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            int total = ETH_HLEN + TUN_HDR_SIZE + len + TAG_SIZE;
            xsk_tx(&w->xsk, out, total);
            free_frame(&lan_ctx, addr);
        }

        xsk_ring_cons__release(&lan_ctx.rx, n);
        xsk_refill_fq(&lan_ctx, n);
    }
    return NULL;
}

// WAN RX thread: receive from WAN -> decrypt -> send to LAN
static void *wan_rx_loop(void *arg) {
    int path = (int)(intptr_t)arg;
    struct xsk_ctx *ctx = &wan[path].xsk;
    uint8_t plain[MAX_PKT];

    while (run) {
        uint32_t idx = 0;
        unsigned int n = xsk_ring_cons__peek(&ctx->rx, BATCH_SIZE, &idx);
        if (!n) {
            struct pollfd pfd = {.fd = xsk_socket__fd(ctx->xsk), .events = POLLIN};
            poll(&pfd, 1, 10);
            continue;
        }

        for (unsigned int i = 0; i < n; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&ctx->rx, idx + i)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&ctx->rx, idx + i)->len;
            uint8_t *pkt = xsk_umem__get_data(ctx->umem_area, addr);

            // Only process tunnel frames
            if (!is_tunnel_frame(pkt, len)) {
                free_frame(ctx, addr);
                continue;
            }

            if (len < ETH_HLEN + TUN_HDR_SIZE + TAG_SIZE) {
                free_frame(ctx, addr);
                continue;
            }

            struct tun_hdr *hdr = (void*)(pkt + ETH_HLEN);
            if (hdr->ver != TUN_VERSION) {
                free_frame(ctx, addr);
                continue;
            }

            uint64_t seq = be64toh(hdr->seq);
            if (seq <= wan[path].rx_last_seq) {
                free_frame(ctx, addr);
                continue;
            }
            wan[path].rx_last_seq = seq;

            uint16_t inner_len = ntohs(hdr->inner_len);
            int clen = len - ETH_HLEN - TUN_HDR_SIZE - TAG_SIZE;
            if (clen < (int)inner_len || inner_len < ETH_HLEN) {
                free_frame(ctx, addr);
                continue;
            }

            uint8_t *cipher = pkt + ETH_HLEN + TUN_HDR_SIZE;
            uint8_t *tag = cipher + clen;

            uint8_t nonce[NONCE_SIZE];
            build_nonce(nonce, hdr->path_id, seq);

            int plen = aead_decrypt(cipher, clen, plain, (uint8_t*)hdr, TUN_HDR_SIZE, nonce, tag);
            if (plen < 0 || plen < ETH_HLEN) {
                free_frame(ctx, addr);
                continue;
            }

            xsk_tx(&lan_ctx, plain, plen);
            free_frame(ctx, addr);
        }

        xsk_ring_cons__release(&ctx->rx, n);
        xsk_refill_fq(ctx, n);
    }
    return NULL;
}

static void cleanup(void) {
    xsk_cleanup(&lan_ctx);
    for (int i = 0; i < wan_cnt; i++) {
        xsk_cleanup(&wan[i].xsk);
    }
}

// Parse wan@mac format
static int parse_wan_arg(const char *arg, char *ifname, uint8_t *peer_mac) {
    char buf[64];
    strncpy(buf, arg, 63);
    buf[63] = 0;

    char *at = strchr(buf, '@');
    if (!at) return -1;

    *at = 0;
    strncpy(ifname, buf, 15);
    ifname[15] = 0;

    unsigned int m[6];
    if (sscanf(at + 1, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) peer_mac[i] = m[i];
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <lan_if> <wan1@peer_mac1> [wan2@peer_mac2...] [-k keyfile]\n", argv[0]);
        fprintf(stderr, "Example: %s enp7s0 enp4s0@20:7c:14:f8:0d:4d enp5s0@20:7c:14:f8:0d:4e\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *lan_if = argv[1];
    const char *keyfile = "tunnel.key";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i+1 < argc) {
            keyfile = argv[++i];
        } else if (wan_cnt < MAX_WAN && strchr(argv[i], '@')) {
            char ifname[16];
            uint8_t peer_mac[6];
            if (parse_wan_arg(argv[i], ifname, peer_mac) == 0) {
                int ifidx = if_nametoindex(ifname);
                if (ifidx) {
                    memset(&wan[wan_cnt], 0, sizeof(wan[wan_cnt]));
                    wan[wan_cnt].xsk.ifidx = ifidx;
                    strncpy(wan[wan_cnt].xsk.ifname, ifname, 15);
                    get_mac(ifname, wan[wan_cnt].local_mac);
                    memcpy(wan[wan_cnt].peer_mac, peer_mac, 6);
                    wan_cnt++;
                }
            }
        }
    }

    if (wan_cnt == 0) { fprintf(stderr, "No WAN interfaces\n"); return 1; }
    load_key(keyfile);

    printf("Setting up LAN: %s\n", lan_if);

    // Setup LAN
    strncpy(lan_ctx.ifname, lan_if, 15);
    if (xsk_setup(&lan_ctx, lan_if) < 0) {
        fprintf(stderr, "LAN XSK setup failed\n");
        return 1;
    }
    printf("LAN XSK ready\n");

    // Setup WAN
    pthread_t wan_threads[MAX_WAN];

    for (int i = 0; i < wan_cnt; i++) {
        printf("Setting up WAN[%d]: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               i, wan[i].xsk.ifname,
               wan[i].peer_mac[0], wan[i].peer_mac[1], wan[i].peer_mac[2],
               wan[i].peer_mac[3], wan[i].peer_mac[4], wan[i].peer_mac[5]);

        if (xsk_setup(&wan[i].xsk, wan[i].xsk.ifname) < 0) {
            fprintf(stderr, "WAN[%d] XSK setup failed\n", i);
            continue;
        }
        printf("WAN[%d] XSK ready\n", i);
        pthread_create(&wan_threads[i], NULL, wan_rx_loop, (void*)(intptr_t)i);
    }

    // Start LAN RX thread
    pthread_t lan_thread;
    pthread_create(&lan_thread, NULL, lan_rx_loop, NULL);

    printf("Tunnel running. Press Ctrl+C to stop.\n");

    // Wait
    while (run) sleep(1);

    printf("\nShutting down...\n");

    pthread_join(lan_thread, NULL);
    for (int i = 0; i < wan_cnt; i++)
        pthread_join(wan_threads[i], NULL);

    cleanup();
    printf("Done.\n");
    return 0;
}
