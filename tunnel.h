// tunnel.h - Minimal definitions
#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>

#define TUN_ETYPE       0x88B6
#define TUN_VERSION     3
#define MAX_WAN         4
#define MAX_PKT         4096
#define NONCE_SIZE      12
#define TAG_SIZE        16
#define KEY_SIZE        32
#define NODE_ID_SIZE    4

// MTU
#define WAN_MTU         1500
#define TUN_OVERHEAD    (14 + 16 + 16)  // ETH + HDR + TAG
#define MAX_INNER_LEN   (WAN_MTU - TUN_OVERHEAD)

// Tunnel header (16 bytes)
struct tun_hdr {
    uint8_t  ver;
    uint8_t  flags;
    uint16_t key_id;
    uint8_t  path_id;
    uint8_t  reserved;
    uint16_t inner_len;
    uint64_t seq;
} __attribute__((packed));

#define TUN_HDR_SIZE sizeof(struct tun_hdr)
#define TUN_FLAG_ENCRYPTED  0x01

#endif
