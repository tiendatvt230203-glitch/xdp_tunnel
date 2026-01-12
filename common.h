#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

// Magic number: "TNL1"
#define TUNNEL_MAGIC 0x544E4C31
#define TUNNEL_VERSION 1
#define CUSTOM_ETHERTYPE 0x88B5

// MTU calculations
#define VXLAN_OVERHEAD 50
#define ETH_HLEN 14
#define TUNNEL_HDR_LEN 24
#define ENCRYPT_TAG_LEN 16   // ChaCha20-Poly1305 auth tag
#define ENCRYPT_NONCE_LEN 12 // ChaCha20-Poly1305 nonce
#define INNER_MTU (1500 - VXLAN_OVERHEAD)
// Max original data per fragment (before encryption)
// After encrypt: payload + 12(nonce) + 16(tag) = payload + 28
#define ENCRYPT_OVERHEAD (ENCRYPT_NONCE_LEN + ENCRYPT_TAG_LEN)
#define MAX_PAYLOAD (INNER_MTU - ETH_HLEN - TUNNEL_HDR_LEN - ENCRYPT_OVERHEAD)

// Flags
#define FLAG_FRAGMENT 0x01
#define FLAG_LAST_FRAG 0x02
#define FLAG_NACK 0x04      // This is a NACK request

// Timing
#define REASM_TIMEOUT_MS 300    // Fallback timeout (reduced from 2000)
#define NACK_WAIT_MS 30         // Wait before sending NACK
#define SEND_BUFFER_TIMEOUT_MS 500  // Keep sent fragments for resend

// Tunnel header (24 bytes)
struct tunnel_hdr {
    uint32_t magic;        // TUNNEL_MAGIC
    uint8_t  version;      // TUNNEL_VERSION
    uint8_t  flags;        // FLAG_*
    uint16_t flow_hash;    // LB key (lower 16 bits)
    uint32_t msg_id;       // reassembly ID
    uint16_t frag_idx;     // fragment index
    uint16_t frag_cnt;     // total fragments
    uint16_t orig_len;     // original packet length
    uint16_t payload_len;  // this fragment payload length
} __attribute__((packed));

// VXLAN group config
#define MAX_GROUPS 4
#define MAX_TUNNELS_PER_GROUP 8

struct tunnel_group {
    char ifnames[MAX_TUNNELS_PER_GROUP][16];
    int ifindexes[MAX_TUNNELS_PER_GROUP];
    int count;
};

// Stats for debug
struct tunnel_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t fragments_sent;
    uint64_t fragments_received;
    uint64_t reassembled;
    uint64_t decrypt_ok;
    uint64_t decrypt_fail;
    uint64_t dropped;
    uint64_t nack_sent;
    uint64_t nack_received;
    uint64_t resent;
};

#endif // COMMON_H
