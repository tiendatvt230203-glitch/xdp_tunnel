// tunnel_daemon.c - Main tunnel program (encrypt/decrypt/LB/fragment)
// Usage: ./tunnel_daemon <lan_if> <vxlan1> [vxlan2] [vxlan3] ...

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "common.h"

// ============ CONFIG ============
#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE 64

// Split UMEM: first half for RX, second half for TX
#define RX_FRAMES (NUM_FRAMES / 2)
#define TX_FRAMES (NUM_FRAMES / 2)
#define RX_FRAME_START 0
#define TX_FRAME_START (RX_FRAMES * FRAME_SIZE)

// ChaCha20-Poly1305 key (256-bit) - CHANGE THIS IN PRODUCTION!
static const uint8_t ENCRYPT_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

// ============ GLOBALS ============
static volatile int running = 1;
static struct tunnel_stats stats = {0};
static uint32_t msg_id_counter = 0;

// AF_XDP structures
struct xsk_info {
    struct xsk_socket *xsk;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    void *umem_area;
    struct xsk_umem *umem;
    uint32_t outstanding_tx;

    // TX frame pool (free-list)
    uint64_t tx_free_list[TX_FRAMES];
    uint32_t tx_free_head;  // Next free frame index
    uint32_t tx_free_count; // Number of free frames
    pthread_spinlock_t tx_lock;

    // RX frame pool (for FQ refill)
    uint64_t rx_free_list[RX_FRAMES];
    uint32_t rx_free_head;
    uint32_t rx_free_count;
};

// VXLAN tunnel info
struct vxlan_tunnel {
    char ifname[16];
    int ifindex;
    int sock_fd;
};

static struct xsk_info *lan_xsk = NULL;
static struct vxlan_tunnel tunnels[MAX_TUNNELS_PER_GROUP];
static int tunnel_count = 0;
static int lan_ifindex = 0;

// Reassembly buffer
#define MAX_REASM_ENTRIES 256

struct reasm_entry {
    uint32_t msg_id;
    uint16_t flow_hash;
    uint16_t frag_cnt;
    uint16_t received;
    uint16_t orig_len;
    uint8_t *fragments[16];
    uint16_t frag_lens[16];
    uint8_t received_mask;  // Bitmask of received fragments
    uint64_t timestamp;
    uint64_t last_nack_time;  // Last NACK sent time
    int active;
    int tunnel_idx;  // Which tunnel this came from (for NACK reply)
};
static struct reasm_entry reasm_table[MAX_REASM_ENTRIES];
static pthread_mutex_t reasm_lock = PTHREAD_MUTEX_INITIALIZER;

// Send buffer (keep fragments for NACK resend)
#define MAX_SEND_ENTRIES 512

struct send_entry {
    uint32_t msg_id;
    uint16_t frag_idx;
    uint16_t frag_cnt;
    uint8_t *data;
    uint16_t data_len;
    uint64_t timestamp;
    int tunnel_idx;
    int active;
};
static struct send_entry send_buffer[MAX_SEND_ENTRIES];
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static int send_buf_idx = 0;

// ============ UTILITIES ============
static void signal_handler(int sig) { running = 0; }

static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint16_t compute_flow_hash(const uint8_t *pkt, int len) {
    // Simple hash on first 32 bytes (covers ETH + IP + ports)
    uint32_t hash = 0x811c9dc5;  // FNV-1a
    int n = len < 32 ? len : 32;
    for (int i = 0; i < n; i++) {
        hash ^= pkt[i];
        hash *= 0x01000193;
    }
    return (uint16_t)(hash ^ (hash >> 16));
}

// ChaCha20-Poly1305 encrypt: output = nonce(12) + ciphertext + tag(16)
// Returns output length, or -1 on error
static int encrypt_chacha(const uint8_t *in, int in_len, uint8_t *out, int out_cap) {
    if (out_cap < in_len + ENCRYPT_NONCE_LEN + ENCRYPT_TAG_LEN) return -1;

    // Generate random nonce
    uint8_t nonce[ENCRYPT_NONCE_LEN];
    RAND_bytes(nonce, ENCRYPT_NONCE_LEN);
    memcpy(out, nonce, ENCRYPT_NONCE_LEN);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, ciphertext_len;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, ENCRYPT_KEY, nonce) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, out + ENCRYPT_NONCE_LEN, &len, in, in_len) != 1) goto err;
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + ENCRYPT_NONCE_LEN + len, &len) != 1) goto err;
    ciphertext_len += len;

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, ENCRYPT_TAG_LEN,
                            out + ENCRYPT_NONCE_LEN + ciphertext_len) != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return ENCRYPT_NONCE_LEN + ciphertext_len + ENCRYPT_TAG_LEN;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// ChaCha20-Poly1305 decrypt: input = nonce(12) + ciphertext + tag(16)
// Returns plaintext length, or -1 on error
static int decrypt_chacha(const uint8_t *in, int in_len, uint8_t *out, int out_cap) {
    if (in_len < ENCRYPT_NONCE_LEN + ENCRYPT_TAG_LEN) return -1;

    int ciphertext_len = in_len - ENCRYPT_NONCE_LEN - ENCRYPT_TAG_LEN;
    if (out_cap < ciphertext_len) return -1;

    const uint8_t *nonce = in;
    const uint8_t *ciphertext = in + ENCRYPT_NONCE_LEN;
    const uint8_t *tag = in + in_len - ENCRYPT_TAG_LEN;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, plaintext_len;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, ENCRYPT_KEY, nonce) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, ciphertext_len) != 1) goto err;
    plaintext_len = len;

    // Set tag before final
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, ENCRYPT_TAG_LEN, (void *)tag) != 1) goto err;
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) goto err;  // Verify tag
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// ============ SEND BUFFER (for NACK resend) ============
static void send_buffer_add(uint32_t msg_id, uint16_t frag_idx, uint16_t frag_cnt,
                            const uint8_t *data, uint16_t data_len, int tunnel_idx) {
    uint64_t now = get_time_ms();
    pthread_mutex_lock(&send_lock);

    // Find slot (circular buffer)
    struct send_entry *e = &send_buffer[send_buf_idx % MAX_SEND_ENTRIES];

    // Free old data if exists
    if (e->data) { free(e->data); e->data = NULL; }

    // Store new entry
    e->msg_id = msg_id;
    e->frag_idx = frag_idx;
    e->frag_cnt = frag_cnt;
    e->data = malloc(data_len);
    if (e->data) {
        memcpy(e->data, data, data_len);
        e->data_len = data_len;
        e->timestamp = now;
        e->tunnel_idx = tunnel_idx;
        e->active = 1;
    }
    send_buf_idx++;

    pthread_mutex_unlock(&send_lock);
}

static struct send_entry *send_buffer_find(uint32_t msg_id, uint16_t frag_idx) {
    uint64_t now = get_time_ms();
    pthread_mutex_lock(&send_lock);

    for (int i = 0; i < MAX_SEND_ENTRIES; i++) {
        struct send_entry *e = &send_buffer[i];
        if (!e->active) continue;

        // Cleanup expired
        if ((now - e->timestamp) > SEND_BUFFER_TIMEOUT_MS) {
            if (e->data) { free(e->data); e->data = NULL; }
            e->active = 0;
            continue;
        }

        if (e->msg_id == msg_id && e->frag_idx == frag_idx) {
            pthread_mutex_unlock(&send_lock);
            return e;
        }
    }

    pthread_mutex_unlock(&send_lock);
    return NULL;
}

// ============ NACK FUNCTIONS ============
static void send_nack(int tunnel_idx, uint32_t msg_id, uint16_t frag_idx, uint16_t frag_cnt);
static void resend_fragment(uint32_t msg_id, uint16_t frag_idx);

// ============ FRAME POOL MANAGEMENT ============
// Initialize TX frame pool
static void tx_pool_init(struct xsk_info *xsk) {
    pthread_spin_init(&xsk->tx_lock, PTHREAD_PROCESS_PRIVATE);
    xsk->tx_free_head = 0;
    xsk->tx_free_count = TX_FRAMES;
    for (uint32_t i = 0; i < TX_FRAMES; i++) {
        xsk->tx_free_list[i] = TX_FRAME_START + (i * FRAME_SIZE);
    }
}

// Allocate TX frame from pool
static int64_t tx_frame_alloc(struct xsk_info *xsk) {
    int64_t addr = -1;
    pthread_spin_lock(&xsk->tx_lock);
    if (xsk->tx_free_count > 0) {
        addr = xsk->tx_free_list[xsk->tx_free_head];
        xsk->tx_free_head = (xsk->tx_free_head + 1) % TX_FRAMES;
        xsk->tx_free_count--;
    }
    pthread_spin_unlock(&xsk->tx_lock);
    return addr;
}

// Return TX frame to pool
static void tx_frame_free(struct xsk_info *xsk, uint64_t addr) {
    pthread_spin_lock(&xsk->tx_lock);
    if (xsk->tx_free_count < TX_FRAMES) {
        uint32_t tail = (xsk->tx_free_head + xsk->tx_free_count) % TX_FRAMES;
        xsk->tx_free_list[tail] = addr;
        xsk->tx_free_count++;
    }
    pthread_spin_unlock(&xsk->tx_lock);
}

// Poll CQ and reclaim TX frames
static void tx_complete_poll(struct xsk_info *xsk) {
    uint32_t idx;
    unsigned int completed = xsk_ring_cons__peek(&xsk->cq, BATCH_SIZE, &idx);
    if (completed == 0) return;

    for (unsigned int i = 0; i < completed; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->cq, idx++);
        tx_frame_free(xsk, addr);
    }
    xsk_ring_cons__release(&xsk->cq, completed);
    xsk->outstanding_tx -= completed;
}

// Initialize RX frame pool
static void rx_pool_init(struct xsk_info *xsk) {
    xsk->rx_free_head = 0;
    xsk->rx_free_count = RX_FRAMES;
    for (uint32_t i = 0; i < RX_FRAMES; i++) {
        xsk->rx_free_list[i] = RX_FRAME_START + (i * FRAME_SIZE);
    }
}

// Return RX frame to pool (after processing)
static void rx_frame_return(struct xsk_info *xsk, uint64_t addr) {
    if (xsk->rx_free_count < RX_FRAMES) {
        uint32_t tail = (xsk->rx_free_head + xsk->rx_free_count) % RX_FRAMES;
        xsk->rx_free_list[tail] = addr;
        xsk->rx_free_count++;
    }
}

// Refill FQ with RX frames
static void rx_fq_refill(struct xsk_info *xsk, uint32_t count) {
    if (count == 0 || xsk->rx_free_count == 0) return;
    if (count > xsk->rx_free_count) count = xsk->rx_free_count;

    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk->fq, count, &idx) != count) return;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t addr = xsk->rx_free_list[xsk->rx_free_head];
        xsk->rx_free_head = (xsk->rx_free_head + 1) % RX_FRAMES;
        xsk->rx_free_count--;
        *xsk_ring_prod__fill_addr(&xsk->fq, idx++) = addr;
    }
    xsk_ring_prod__submit(&xsk->fq, count);
}

static int get_ifindex(const char *ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(sock, SIOCGIFINDEX, &ifr);
    close(sock);
    return ret < 0 ? -1 : ifr.ifr_ifindex;
}

// ============ AF_XDP SETUP ============
static struct xsk_info *xsk_setup(const char *ifname, int queue_id) {
    struct xsk_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;

    // Allocate UMEM
    size_t umem_size = NUM_FRAMES * FRAME_SIZE;
    xsk->umem_area = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (xsk->umem_area == MAP_FAILED) {
        perror("mmap umem");
        free(xsk);
        return NULL;
    }

    // Create UMEM
    struct xsk_umem_config umem_cfg = {
        .fill_size = RX_FRAMES,
        .comp_size = TX_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };
    if (xsk_umem__create(&xsk->umem, xsk->umem_area, umem_size,
                         &xsk->fq, &xsk->cq, &umem_cfg)) {
        perror("xsk_umem__create");
        munmap(xsk->umem_area, umem_size);
        free(xsk);
        return NULL;
    }

    // Create socket
    struct xsk_socket_config xsk_cfg = {
        .rx_size = RX_FRAMES,
        .tx_size = TX_FRAMES,
        .bind_flags = XDP_COPY,  // Use copy mode for compatibility
    };
    if (xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                           &xsk->rx, &xsk->tx, &xsk_cfg)) {
        perror("xsk_socket__create");
        xsk_umem__delete(xsk->umem);
        munmap(xsk->umem_area, umem_size);
        free(xsk);
        return NULL;
    }

    // Initialize frame pools
    tx_pool_init(xsk);
    rx_pool_init(xsk);

    // Fill FQ with RX frames only (first half of UMEM)
    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk->fq, RX_FRAMES, &idx) == RX_FRAMES) {
        for (uint32_t i = 0; i < RX_FRAMES; i++) {
            uint64_t addr = RX_FRAME_START + (i * FRAME_SIZE);
            *xsk_ring_prod__fill_addr(&xsk->fq, idx++) = addr;
        }
        xsk_ring_prod__submit(&xsk->fq, RX_FRAMES);
        // Mark these frames as in-use (not in free pool)
        xsk->rx_free_count = 0;
    }

    return xsk;
}

static void xsk_cleanup(struct xsk_info *xsk) {
    if (!xsk) return;
    pthread_spin_destroy(&xsk->tx_lock);
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(xsk->umem);
    munmap(xsk->umem_area, NUM_FRAMES * FRAME_SIZE);
    free(xsk);
}

// ============ VXLAN SOCKET SETUP ============
static int vxlan_socket_create(int ifindex) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = ifindex,
    };
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

// ============ SEND TO VXLAN ============
static void send_to_vxlan(const uint8_t *orig_pkt, int orig_len, uint16_t flow_hash) {
    // Select tunnel by flow hash
    int idx = flow_hash % tunnel_count;
    struct vxlan_tunnel *tun = &tunnels[idx];

    // Calculate fragments needed
    int frag_cnt = (orig_len + MAX_PAYLOAD - 1) / MAX_PAYLOAD;
    if (frag_cnt > 16) frag_cnt = 16;  // Safety limit

    uint32_t msg_id = __sync_fetch_and_add(&msg_id_counter, 1);
    int offset = 0;

    for (int i = 0; i < frag_cnt; i++) {
        int payload_len = orig_len - offset;
        if (payload_len > MAX_PAYLOAD) payload_len = MAX_PAYLOAD;

        // Build frame: ETH + tunnel_hdr + encrypted_payload
        uint8_t frame[INNER_MTU];
        int frame_len = 0;

        // Ethernet header (inner) - use broadcast MAC so all peers receive
        struct ethhdr *eth = (struct ethhdr *)frame;
        memset(eth->h_dest, 0xff, 6);    // Broadcast MAC (ff:ff:ff:ff:ff:ff)
        memset(eth->h_source, 0x01, 6);  // Local MAC
        eth->h_proto = htons(CUSTOM_ETHERTYPE);
        frame_len += ETH_HLEN;

        // Tunnel header
        struct tunnel_hdr *hdr = (struct tunnel_hdr *)(frame + frame_len);
        hdr->magic = htonl(TUNNEL_MAGIC);
        hdr->version = TUNNEL_VERSION;
        hdr->flags = (frag_cnt > 1) ? FLAG_FRAGMENT : 0;
        if (i == frag_cnt - 1) hdr->flags |= FLAG_LAST_FRAG;
        hdr->flow_hash = htons(flow_hash);
        hdr->msg_id = htonl(msg_id);
        hdr->frag_idx = htons(i);
        hdr->frag_cnt = htons(frag_cnt);
        hdr->orig_len = htons(orig_len);
        hdr->payload_len = htons(payload_len);
        frame_len += TUNNEL_HDR_LEN;

        // Encrypt payload (adds nonce + tag)
        uint8_t encrypted[MAX_PAYLOAD + ENCRYPT_NONCE_LEN + ENCRYPT_TAG_LEN];
        int enc_len = encrypt_chacha(orig_pkt + offset, payload_len, encrypted, sizeof(encrypted));
        if (enc_len < 0) { stats.dropped++; continue; }

        memcpy(frame + frame_len, encrypted, enc_len);
        hdr->payload_len = htons(enc_len);  // Update to encrypted length
        frame_len += enc_len;

        // Send via raw socket
        struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_ifindex = tun->ifindex,
            .sll_halen = 6,
        };
        memcpy(sll.sll_addr, eth->h_dest, 6);

        if (sendto(tun->sock_fd, frame, frame_len, 0,
                   (struct sockaddr *)&sll, sizeof(sll)) > 0) {
            stats.tx_packets++;
            stats.tx_bytes += frame_len;
            if (frag_cnt > 1) {
                stats.fragments_sent++;
                // Save to send buffer for potential NACK resend
                send_buffer_add(msg_id, i, frag_cnt, frame, frame_len, idx);
            }
        }

        offset += payload_len;
    }
}

// Send NACK to request missing fragment
static void send_nack(int tunnel_idx, uint32_t msg_id, uint16_t frag_idx, uint16_t frag_cnt) {
    if (tunnel_idx < 0 || tunnel_idx >= tunnel_count) return;
    struct vxlan_tunnel *tun = &tunnels[tunnel_idx];

    // Build NACK frame
    uint8_t frame[ETH_HLEN + TUNNEL_HDR_LEN];
    int frame_len = 0;

    // Ethernet header - use broadcast MAC for NACK
    struct ethhdr *eth = (struct ethhdr *)frame;
    memset(eth->h_dest, 0xff, 6);    // Broadcast MAC
    memset(eth->h_source, 0x01, 6);  // Local MAC
    eth->h_proto = htons(CUSTOM_ETHERTYPE);
    frame_len += ETH_HLEN;

    // Tunnel header with NACK flag
    struct tunnel_hdr *hdr = (struct tunnel_hdr *)(frame + frame_len);
    hdr->magic = htonl(TUNNEL_MAGIC);
    hdr->version = TUNNEL_VERSION;
    hdr->flags = FLAG_NACK;
    hdr->flow_hash = 0;
    hdr->msg_id = htonl(msg_id);
    hdr->frag_idx = htons(frag_idx);
    hdr->frag_cnt = htons(frag_cnt);
    hdr->orig_len = 0;
    hdr->payload_len = 0;
    frame_len += TUNNEL_HDR_LEN;

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = tun->ifindex,
        .sll_halen = 6,
    };
    memcpy(sll.sll_addr, eth->h_dest, 6);

    if (sendto(tun->sock_fd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll)) > 0) {
        stats.nack_sent++;
    }
}

// Resend fragment from send buffer
static void resend_fragment(uint32_t msg_id, uint16_t frag_idx) {
    struct send_entry *e = send_buffer_find(msg_id, frag_idx);
    if (!e || !e->data) return;

    struct vxlan_tunnel *tun = &tunnels[e->tunnel_idx];
    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = tun->ifindex,
        .sll_halen = 6,
    };
    memset(sll.sll_addr, 0xff, 6);  // Broadcast MAC

    if (sendto(tun->sock_fd, e->data, e->data_len, 0,
               (struct sockaddr *)&sll, sizeof(sll)) > 0) {
        stats.resent++;
    }
}

// Check for missing fragments and send NACK
static void check_and_send_nack(struct reasm_entry *e) {
    uint64_t now = get_time_ms();
    if ((now - e->timestamp) < NACK_WAIT_MS) return;
    if ((now - e->last_nack_time) < NACK_WAIT_MS * 2) return;  // Don't spam NACK

    // Find missing fragments
    for (int i = 0; i < e->frag_cnt; i++) {
        if (!(e->received_mask & (1 << i))) {
            send_nack(e->tunnel_idx, e->msg_id, i, e->frag_cnt);
            e->last_nack_time = now;
            return;  // Send one NACK at a time
        }
    }
}

// ============ REASSEMBLY ============
static struct reasm_entry *find_or_create_reasm(uint32_t msg_id, uint16_t flow_hash,
                                                 uint16_t frag_cnt, uint16_t orig_len) {
    uint64_t now = get_time_ms();
    struct reasm_entry *free_entry = NULL;

    pthread_mutex_lock(&reasm_lock);
    for (int i = 0; i < MAX_REASM_ENTRIES; i++) {
        struct reasm_entry *e = &reasm_table[i];
        // Cleanup expired
        if (e->active && (now - e->timestamp) > REASM_TIMEOUT_MS) {
            for (int j = 0; j < 16; j++) {
                if (e->fragments[j]) { free(e->fragments[j]); e->fragments[j] = NULL; }
            }
            e->active = 0;
            stats.dropped++;
        }
        // Find existing
        if (e->active && e->msg_id == msg_id && e->flow_hash == flow_hash) {
            pthread_mutex_unlock(&reasm_lock);
            return e;
        }
        // Track free slot
        if (!e->active && !free_entry) free_entry = e;
    }

    // Create new
    if (free_entry) {
        memset(free_entry, 0, sizeof(*free_entry));
        free_entry->msg_id = msg_id;
        free_entry->flow_hash = flow_hash;
        free_entry->frag_cnt = frag_cnt;
        free_entry->orig_len = orig_len;
        free_entry->timestamp = now;
        free_entry->active = 1;
    }
    pthread_mutex_unlock(&reasm_lock);
    return free_entry;
}

static int reassemble_add(struct reasm_entry *e, int frag_idx, const uint8_t *data, int len, int tunnel_idx) {
    if (frag_idx >= 16 || e->fragments[frag_idx]) return 0;

    e->fragments[frag_idx] = malloc(len);
    if (!e->fragments[frag_idx]) return 0;
    memcpy(e->fragments[frag_idx], data, len);
    e->frag_lens[frag_idx] = len;
    e->received++;
    e->received_mask |= (1 << frag_idx);
    e->tunnel_idx = tunnel_idx;
    stats.fragments_received++;

    // Check if we should send NACK for missing fragments
    if (e->received < e->frag_cnt) {
        check_and_send_nack(e);
    }

    return (e->received == e->frag_cnt);
}

static int reassemble_complete(struct reasm_entry *e, uint8_t *out, int out_cap) {
    int total = 0;
    for (int i = 0; i < e->frag_cnt && total < out_cap; i++) {
        if (!e->fragments[i]) return -1;
        int len = e->frag_lens[i];
        if (total + len > out_cap) len = out_cap - total;
        memcpy(out + total, e->fragments[i], len);
        total += len;
        free(e->fragments[i]);
        e->fragments[i] = NULL;
    }
    e->active = 0;
    stats.reassembled++;
    return total;
}

// ============ FORWARD TO LAN ============
static void forward_to_lan(const uint8_t *pkt, int len) {
    if (!lan_xsk) return;

    // First, poll CQ to reclaim any completed TX frames
    tx_complete_poll(lan_xsk);

    // Allocate TX frame from pool
    int64_t addr = tx_frame_alloc(lan_xsk);
    if (addr < 0) {
        // No free frames, try polling CQ again
        tx_complete_poll(lan_xsk);
        addr = tx_frame_alloc(lan_xsk);
        if (addr < 0) {
            stats.dropped++;
            return;
        }
    }

    // Reserve TX ring slot
    uint32_t idx;
    if (xsk_ring_prod__reserve(&lan_xsk->tx, 1, &idx) != 1) {
        // Return frame to pool since we can't send
        tx_frame_free(lan_xsk, addr);
        stats.dropped++;
        return;
    }

    // Copy packet to frame
    uint8_t *frame = xsk_umem__get_data(lan_xsk->umem_area, addr);
    memcpy(frame, pkt, len);

    // Submit TX descriptor
    struct xdp_desc *desc = xsk_ring_prod__tx_desc(&lan_xsk->tx, idx);
    desc->addr = addr;
    desc->len = len;

    xsk_ring_prod__submit(&lan_xsk->tx, 1);
    // Kick kernel to send (compatible with older libxdp)
    sendto(xsk_socket__fd(lan_xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    lan_xsk->outstanding_tx++;
}

// ============ PROCESS RECEIVED VXLAN PACKET ============
static int process_debug = 0;
static void process_vxlan_rx(const uint8_t *frame, int frame_len, int tunnel_idx) {
    if (frame_len < ETH_HLEN + TUNNEL_HDR_LEN) {
        if (process_debug < 5) {
            printf("[PROCESS] Rejected: frame too short (%d < %lu)\n",
                   frame_len, ETH_HLEN + TUNNEL_HDR_LEN);
            process_debug++;
        }
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)frame;
    if (ntohs(eth->h_proto) != CUSTOM_ETHERTYPE) {
        if (process_debug < 5) {
            printf("[PROCESS] Rejected: wrong ethertype 0x%04x (expect 0x%04x)\n",
                   ntohs(eth->h_proto), CUSTOM_ETHERTYPE);
            process_debug++;
        }
        return;
    }

    struct tunnel_hdr *hdr = (struct tunnel_hdr *)(frame + ETH_HLEN);
    if (ntohl(hdr->magic) != TUNNEL_MAGIC) {
        if (process_debug < 5) {
            printf("[PROCESS] Rejected: wrong magic 0x%08x (expect 0x%08x)\n",
                   ntohl(hdr->magic), TUNNEL_MAGIC);
            process_debug++;
        }
        return;
    }

    if (process_debug < 10) {
        printf("[PROCESS] Accepted packet: msg_id=%u frag=%u/%u\n",
               ntohl(hdr->msg_id), ntohs(hdr->frag_idx), ntohs(hdr->frag_cnt));
        process_debug++;
    }

    uint32_t msg_id = ntohl(hdr->msg_id);
    uint16_t frag_idx = ntohs(hdr->frag_idx);
    uint16_t frag_cnt = ntohs(hdr->frag_cnt);

    // Handle NACK: resend requested fragment
    if (hdr->flags & FLAG_NACK) {
        stats.nack_received++;
        resend_fragment(msg_id, frag_idx);
        return;
    }

    uint16_t flow_hash = ntohs(hdr->flow_hash);
    uint16_t orig_len = ntohs(hdr->orig_len);
    uint16_t payload_len = ntohs(hdr->payload_len);

    const uint8_t *payload = frame + ETH_HLEN + TUNNEL_HDR_LEN;
    if (ETH_HLEN + TUNNEL_HDR_LEN + payload_len > frame_len) return;

    // Decrypt payload
    uint8_t decrypted[MAX_PAYLOAD];
    int dec_len = decrypt_chacha(payload, payload_len, decrypted, sizeof(decrypted));
    if (dec_len < 0) { stats.decrypt_fail++; return; }

    stats.rx_packets++;
    stats.rx_bytes += frame_len;

    if (frag_cnt == 1) {
        // Single packet, forward directly
        stats.decrypt_ok++;
        forward_to_lan(decrypted, dec_len);
    } else {
        // Fragmented, need reassembly
        struct reasm_entry *e = find_or_create_reasm(msg_id, flow_hash, frag_cnt, orig_len);
        if (!e) { stats.dropped++; return; }

        if (reassemble_add(e, frag_idx, decrypted, dec_len, tunnel_idx)) {
            // All fragments received
            uint8_t complete[65536];
            int len = reassemble_complete(e, complete, sizeof(complete));
            if (len > 0) {
                stats.decrypt_ok++;
                forward_to_lan(complete, len);
            } else {
                stats.decrypt_fail++;
            }
        }
    }
}

// ============ MAIN LOOPS ============
static void *lan_rx_thread(void *arg) {
    (void)arg;
    printf("[LAN RX] Started on queue 0\n");

    uint64_t rx_addrs[BATCH_SIZE];  // Store addresses for FQ refill

    while (running) {
        // Poll for RX
        struct pollfd pfd = { .fd = xsk_socket__fd(lan_xsk->xsk), .events = POLLIN };
        poll(&pfd, 1, 100);

        // Process RX
        uint32_t idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&lan_xsk->rx, BATCH_SIZE, &idx_rx);
        if (!rcvd) continue;

        // Save addresses and process packets
        for (unsigned int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&lan_xsk->rx, idx_rx);
            rx_addrs[i] = desc->addr;  // Save address for FQ refill
            uint8_t *pkt = xsk_umem__get_data(lan_xsk->umem_area, desc->addr);
            uint16_t flow_hash = compute_flow_hash(pkt, desc->len);
            send_to_vxlan(pkt, desc->len, flow_hash);
            idx_rx++;
        }
        xsk_ring_cons__release(&lan_xsk->rx, rcvd);

        // Refill FQ with the same addresses we just processed
        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&lan_xsk->fq, rcvd, &idx_fq) == rcvd) {
            for (unsigned int i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&lan_xsk->fq, idx_fq++) = rx_addrs[i];
            }
            xsk_ring_prod__submit(&lan_xsk->fq, rcvd);
        }
    }
    return NULL;
}

static void *vxlan_rx_thread(void *arg) {
    (void)arg;
    printf("[VXLAN RX] Started, tunnels: %d\n", tunnel_count);

    struct pollfd pfds[MAX_TUNNELS_PER_GROUP];
    for (int i = 0; i < tunnel_count; i++) {
        pfds[i].fd = tunnels[i].sock_fd;
        pfds[i].events = POLLIN;
    }

    uint8_t buf[2048];
    static int debug_count = 0;
    while (running) {
        int ret = poll(pfds, tunnel_count, 100);
        if (ret <= 0) continue;

        for (int i = 0; i < tunnel_count; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;

            ssize_t len = recv(tunnels[i].sock_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (len > 0) {
                // Debug: print first 10 packets received
                if (debug_count < 10) {
                    struct ethhdr *eth = (struct ethhdr *)buf;
                    printf("[VXLAN RX DEBUG] tunnel=%d len=%zd ethertype=0x%04x\n",
                           i, len, ntohs(eth->h_proto));
                    if (len >= ETH_HLEN + 4) {
                        uint32_t *magic = (uint32_t *)(buf + ETH_HLEN);
                        printf("[VXLAN RX DEBUG] magic=0x%08x (expect 0x%08x)\n",
                               ntohl(*magic), TUNNEL_MAGIC);
                    }
                    debug_count++;
                }
                process_vxlan_rx(buf, len, i);
            }
        }
    }
    return NULL;
}

static void *stats_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(5);
        printf("\n[STATS] TX:%lu RX:%lu Frag:%lu/%lu Reasm:%lu NACK:%lu/%lu Resent:%lu Drop:%lu DecryptFail:%lu\n",
               stats.tx_packets, stats.rx_packets,
               stats.fragments_sent, stats.fragments_received,
               stats.reassembled,
               stats.nack_sent, stats.nack_received, stats.resent,
               stats.dropped, stats.decrypt_fail);
    }
    return NULL;
}

// ============ MAIN ============
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <lan_if> <vxlan1> [vxlan2] ...\n", argv[0]);
        fprintf(stderr, "Example: %s enp7s0 ne_tunnel1 ne_tunnel2\n", argv[0]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    const char *lan_if = argv[1];
    lan_ifindex = get_ifindex(lan_if);
    if (lan_ifindex < 0) {
        fprintf(stderr, "Cannot find LAN interface: %s\n", lan_if);
        return 1;
    }
    printf("[INIT] LAN: %s (ifindex %d)\n", lan_if, lan_ifindex);

    // Setup VXLAN tunnels
    for (int i = 2; i < argc && tunnel_count < MAX_TUNNELS_PER_GROUP; i++) {
        struct vxlan_tunnel *tun = &tunnels[tunnel_count];
        strncpy(tun->ifname, argv[i], sizeof(tun->ifname) - 1);
        tun->ifindex = get_ifindex(tun->ifname);
        if (tun->ifindex < 0) {
            fprintf(stderr, "Cannot find VXLAN interface: %s\n", tun->ifname);
            continue;
        }
        tun->sock_fd = vxlan_socket_create(tun->ifindex);
        if (tun->sock_fd < 0) {
            fprintf(stderr, "Cannot create socket for: %s\n", tun->ifname);
            continue;
        }
        printf("[INIT] VXLAN[%d]: %s (ifindex %d)\n", tunnel_count, tun->ifname, tun->ifindex);
        tunnel_count++;
    }

    if (tunnel_count == 0) {
        fprintf(stderr, "No valid VXLAN tunnels\n");
        return 1;
    }

    // Setup AF_XDP on LAN
    printf("[INIT] Setting up AF_XDP on %s...\n", lan_if);
    lan_xsk = xsk_setup(lan_if, 0);
    if (!lan_xsk) {
        fprintf(stderr, "Failed to setup AF_XDP on %s\n", lan_if);
        // Continue without AF_XDP (for testing)
    }

    // Start threads
    pthread_t tid_lan, tid_vxlan, tid_stats;
    if (lan_xsk) pthread_create(&tid_lan, NULL, lan_rx_thread, NULL);
    pthread_create(&tid_vxlan, NULL, vxlan_rx_thread, NULL);
    pthread_create(&tid_stats, NULL, stats_thread, NULL);

    printf("[INIT] Running... (Ctrl+C to stop)\n");

    // Main loop just waits
    while (running) sleep(1);

    printf("\n[SHUTDOWN] Cleaning up...\n");
    running = 0;

    if (lan_xsk) pthread_join(tid_lan, NULL);
    pthread_join(tid_vxlan, NULL);
    pthread_join(tid_stats, NULL);

    // Cleanup
    xsk_cleanup(lan_xsk);
    for (int i = 0; i < tunnel_count; i++)
        close(tunnels[i].sock_fd);

    printf("[STATS] Final - TX:%lu RX:%lu\n", stats.tx_packets, stats.rx_packets);
    return 0;
}

