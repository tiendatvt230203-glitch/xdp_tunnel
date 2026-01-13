#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define TUNNEL_MAGIC    0x544E4C31
#define CUSTOM_ETHERTYPE 0x88B5
#define MAX_TUN         4
#define NUM_FRAMES      4096
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      64

struct tunnel_hdr {
    uint32_t magic;
    uint16_t msg_id;
    uint8_t  part;
    uint8_t  total;
} __attribute__((packed));

#endif
