// tunnel_node.c - Encrypted tunnel (minimal)
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
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
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
};

// WAN context
struct wan_ctx {
    struct xsk_ctx xsk;
    uint8_t local_mac[6];
    uint8_t peer_mac[6];
    uint64_t tx_seq;
    uint64_t rx_last_seq;  // Simple replay: just track last seq
    struct bpf_object *bpf_obj;
};

// Globals
static struct xsk_ctx lan_ctx;
static struct wan_ctx wan[MAX_WAN];
static int wan_cnt = 0;
static struct bpf_object *lan_bpf_obj = NULL;
static volatile int run = 1;
static int mode = 0;  // 0=send, 1=recv
static uint8_t key[KEY_SIZE];
static uint8_t node_id[NODE_ID_SIZE];
static uint16_t key_id = 1;

static void sig_handler(int s) { (void)s; run = 0; }

// Frame alloc
static uint64_t alloc_frame(struct xsk_ctx *ctx) {
    return ctx->frame_cnt ? ctx->frames[--ctx->frame_cnt] : UINT64_MAX;
}

static void free_frame(struct xsk_ctx *ctx, uint64_t f) {
    if (ctx->frame_cnt < NUM_FRAMES) ctx->frames[ctx->frame_cnt++] = f;
}

// Get MAC from interface
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

// 5-tuple hash for load balancing
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

// Nonce: node_id(4) + path(1) + key_id(1) + seq(6)
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

// AES-256-GCM encrypt
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

// AES-256-GCM decrypt
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

// XSK setup
static int xsk_setup(struct xsk_ctx *ctx, const char *ifname, int map_fd) {
    ctx->ifidx = if_nametoindex(ifname);
    if (!ctx->ifidx) return -1;

    size_t sz = NUM_FRAMES * FRAME_SIZE;
    ctx->umem_area = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ctx->umem_area == MAP_FAILED) return -1;

    struct xsk_umem_config ucfg = {.fill_size=4096, .comp_size=4096, .frame_size=FRAME_SIZE};
    if (xsk_umem__create(&ctx->umem, ctx->umem_area, sz, &ctx->fq, &ctx->cq, &ucfg)) {
        munmap(ctx->umem_area, sz);
        return -1;
    }

    for (uint32_t i = 0; i < NUM_FRAMES; i++) ctx->frames[i] = i * FRAME_SIZE;
    ctx->frame_cnt = NUM_FRAMES;

    struct xsk_socket_config xcfg = {
        .rx_size = 4096, .tx_size = 4096,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP
    };

    if (xsk_socket__create(&ctx->xsk, ifname, 0, ctx->umem, &ctx->rx, &ctx->tx, &xcfg)) {
        xsk_umem__delete(ctx->umem);
        munmap(ctx->umem_area, sz);
        return -1;
    }

    if (map_fd >= 0) {
        int fd = xsk_socket__fd(ctx->xsk);
        uint32_t k = 0;
        bpf_map_update_elem(map_fd, &k, &fd, 0);
    }

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

// TX one packet
static void xsk_tx(struct xsk_ctx *ctx, const void *data, int len) {
    // Complete pending
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

// BPF load and attach
static int load_bpf(const char *ifname, int ifidx, int wan_mode, struct bpf_object **obj) {
    *obj = bpf_object__open_file("tunnel.bpf.o", NULL);
    if (libbpf_get_error(*obj)) return -1;
    if (bpf_object__load(*obj)) { bpf_object__close(*obj); return -1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(*obj, "xdp_prog");
    if (!prog) { bpf_object__close(*obj); return -1; }

    struct bpf_map *mode_map = bpf_object__find_map_by_name(*obj, "mode_map");
    if (mode_map) {
        uint32_t k = 0, v = wan_mode;
        bpf_map_update_elem(bpf_map__fd(mode_map), &k, &v, 0);
    }

    if (bpf_set_link_xdp_fd(ifidx, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE) < 0) {
        bpf_object__close(*obj);
        return -1;
    }
    return 0;
}

// Load key
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

// Sender loop: LAN RX -> encrypt -> WAN TX
static void *sender_loop(void *arg) {
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

            // MTU guard
            if (len > MAX_INNER_LEN || len < ETH_HLEN) {
                free_frame(&lan_ctx, addr);
                continue;
            }

            // Pick WAN path by flow hash
            uint32_t h = flow_hash(pkt, len);
            int path = h % wan_cnt;
            struct wan_ctx *w = &wan[path];

            // Build L2 header
            struct ethhdr *eth = (void*)out;
            memcpy(eth->h_dest, w->peer_mac, 6);
            memcpy(eth->h_source, w->local_mac, 6);
            eth->h_proto = htons(TUN_ETYPE);

            // Build tunnel header
            uint64_t seq = __sync_add_and_fetch(&w->tx_seq, 1);
            struct tun_hdr *hdr = (void*)(out + ETH_HLEN);
            hdr->ver = TUN_VERSION;
            hdr->flags = TUN_FLAG_ENCRYPTED;
            hdr->key_id = htons(key_id);
            hdr->path_id = path;
            hdr->reserved = 0;
            hdr->inner_len = htons(len);
            hdr->seq = htobe64(seq);

            // Encrypt
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

// Receiver loop: WAN RX -> decrypt -> LAN TX
static void *receiver_loop(void *arg) {
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

            if (len < ETH_HLEN + TUN_HDR_SIZE + TAG_SIZE) {
                free_frame(ctx, addr);
                continue;
            }

            struct ethhdr *eth = (void*)pkt;
            if (ntohs(eth->h_proto) != TUN_ETYPE) {
                free_frame(ctx, addr);
                continue;
            }

            struct tun_hdr *hdr = (void*)(pkt + ETH_HLEN);
            if (hdr->ver != TUN_VERSION) {
                free_frame(ctx, addr);
                continue;
            }

            uint64_t seq = be64toh(hdr->seq);

            // Simple replay check
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

// Cleanup
static void cleanup(void) {
    xsk_cleanup(&lan_ctx);
    if (lan_ctx.ifidx) bpf_set_link_xdp_fd(lan_ctx.ifidx, -1, XDP_FLAGS_SKB_MODE);
    if (lan_bpf_obj) bpf_object__close(lan_bpf_obj);

    for (int i = 0; i < wan_cnt; i++) {
        xsk_cleanup(&wan[i].xsk);
        if (wan[i].xsk.ifidx) bpf_set_link_xdp_fd(wan[i].xsk.ifidx, -1, XDP_FLAGS_SKB_MODE);
        if (wan[i].bpf_obj) bpf_object__close(wan[i].bpf_obj);
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <send|recv> <lan_if> <wan1> [wan2...] [-k keyfile] [-p peer_mac]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    mode = (strcmp(argv[1], "recv") == 0) ? 1 : 0;
    const char *lan_if = argv[2];
    const char *keyfile = "tunnel.key";
    uint8_t peer_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i+1 < argc) {
            keyfile = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            unsigned int m[6];
            if (sscanf(argv[++i], "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6)
                for (int j = 0; j < 6; j++) peer_mac[j] = m[j];
        } else if (wan_cnt < MAX_WAN) {
            int ifidx = if_nametoindex(argv[i]);
            if (ifidx) {
                memset(&wan[wan_cnt], 0, sizeof(wan[wan_cnt]));
                wan[wan_cnt].xsk.ifidx = ifidx;
                get_mac(argv[i], wan[wan_cnt].local_mac);
                memcpy(wan[wan_cnt].peer_mac, peer_mac, 6);
                wan_cnt++;
            }
        }
    }

    if (wan_cnt == 0) { fprintf(stderr, "No WAN\n"); return 1; }
    load_key(keyfile);

    // Setup LAN
    int lan_ifidx = if_nametoindex(lan_if);
    if (!lan_ifidx) { fprintf(stderr, "Bad LAN\n"); return 1; }

    if (load_bpf(lan_if, lan_ifidx, mode, &lan_bpf_obj) < 0) {
        fprintf(stderr, "LAN BPF fail\n");
        return 1;
    }

    struct bpf_map *xsks_map = bpf_object__find_map_by_name(lan_bpf_obj, "xsks_map");
    int map_fd = xsks_map ? bpf_map__fd(xsks_map) : -1;

    lan_ctx.ifidx = lan_ifidx;
    if (xsk_setup(&lan_ctx, lan_if, map_fd) < 0) {
        fprintf(stderr, "LAN XSK fail\n");
        cleanup();
        return 1;
    }

    // Setup WAN
    pthread_t threads[MAX_WAN];

    for (int i = 0; i < wan_cnt; i++) {
        char ifname[16];
        if_indextoname(wan[i].xsk.ifidx, ifname);

        if (mode == 0) {
            // Sender: WAN TX only (no XDP needed)
            if (xsk_setup(&wan[i].xsk, ifname, -1) < 0)
                fprintf(stderr, "WAN[%d] XSK fail\n", i);
        } else {
            // Receiver: WAN RX with XDP
            if (load_bpf(ifname, wan[i].xsk.ifidx, 1, &wan[i].bpf_obj) < 0) continue;
            struct bpf_map *wmap = bpf_object__find_map_by_name(wan[i].bpf_obj, "xsks_map");
            if (xsk_setup(&wan[i].xsk, ifname, wmap ? bpf_map__fd(wmap) : -1) < 0) continue;
            pthread_create(&threads[i], NULL, receiver_loop, (void*)(intptr_t)i);
        }
    }

    pthread_t sender_thread;
    if (mode == 0) {
        pthread_create(&sender_thread, NULL, sender_loop, NULL);
    }

    while (run) sleep(1);

    if (mode == 0) {
        pthread_join(sender_thread, NULL);
    } else {
        for (int i = 0; i < wan_cnt; i++)
            pthread_join(threads[i], NULL);
    }

    cleanup();
    return 0;
}
