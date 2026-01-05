// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel - Load Balancer with Dynamic WAN Failover & Sync
// Features:
// - Per-window load balancing (64KB chunks) to avoid TCP reordering
// - Dynamic reload when WAN goes down/up
// - Handshake protocol between 2 servers for WAN sync
// - Control port (9999) bypasses XDP for sync messages
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_WAN 3
#define CONTROL_PORT 9999  // UDP port cho sync giữa 2 server
#define WINDOW_CHUNK_SHIFT 16  // 65536 bytes = 64KB per chunk

// Config map: [0]=nwan, [1]=remote_net, [2]=remote_mask, [3]=local_if, [4-6]=wan_if
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// MACs map: [0-2]=wan_src, [3-5]=wan_dst, [6]=local
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} macs SEC(".maps");

// ARP cache for local network
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} arp_cache SEC(".maps");

static __always_inline void mac_copy(__u8 *dst, __u64 mac)
{
    dst[0] = mac;
    dst[1] = mac >> 8;
    dst[2] = mac >> 16;
    dst[3] = mac >> 24;
    dst[4] = mac >> 32;
    dst[5] = mac >> 40;
}

// ==================== TX: Local -> WAN ====================
SEC("xdp_local")
int xdp_tx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Cho UDP control port (9999) pass qua kernel - dùng để sync giữa 2 server
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (bpf_ntohs(udp->dest) == CONTROL_PORT ||
            bpf_ntohs(udp->source) == CONTROL_PORT) {
            return XDP_PASS;
        }
    }

    // Chỉ xử lý TCP và UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Load config
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u32 *nwan = bpf_map_lookup_elem(&config, &k0);
    __u32 *remote_net = bpf_map_lookup_elem(&config, &k1);
    __u32 *remote_mask = bpf_map_lookup_elem(&config, &k2);

    if (!nwan || !remote_net || !remote_mask || *nwan == 0)
        return XDP_PASS;

    // Check destination trong remote network
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    if ((dst_ip & *remote_mask) != (*remote_net & *remote_mask))
        return XDP_PASS;

    // ============ PER-WINDOW LOAD BALANCING ============
    // Thay vì round-robin từng packet, group theo TCP window chunks
    // Tất cả packets trong cùng 64KB chunk đi cùng 1 WAN
    // -> Tránh packet reordering trong cùng window
    __u32 wan_idx = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // Lấy TCP sequence number và chia theo chunks 64KB
        // seq 0-65535 -> chunk 0 -> WAN 0
        // seq 65536-131071 -> chunk 1 -> WAN 1
        // seq 131072-196607 -> chunk 2 -> WAN 2
        // ...
        __u32 seq = bpf_ntohl(tcp->seq);
        __u32 chunk = seq >> WINDOW_CHUNK_SHIFT;  // seq / 65536
        wan_idx = chunk % *nwan;
    } else {
        // UDP: per-packet round-robin (không cần per-window vì UDP không có ACK)
        wan_idx = bpf_ntohs(ip->id) % *nwan;
    }

    // Get WAN ifindex
    __u32 if_key = 4 + wan_idx;
    __u32 *wan_if = bpf_map_lookup_elem(&config, &if_key);
    if (!wan_if || *wan_if == 0)
        return XDP_PASS;

    // Get MACs
    __u64 *src_mac = bpf_map_lookup_elem(&macs, &wan_idx);
    __u32 dst_key = wan_idx + MAX_WAN;
    __u64 *dst_mac = bpf_map_lookup_elem(&macs, &dst_key);

    if (!src_mac || !dst_mac)
        return XDP_PASS;

    mac_copy(eth->h_source, *src_mac);
    mac_copy(eth->h_dest, *dst_mac);

    return bpf_redirect(*wan_if, 0);
}

// ==================== RX: WAN -> Local ====================
SEC("xdp_wan")
int xdp_rx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Cho UDP control port pass qua kernel
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (bpf_ntohs(udp->dest) == CONTROL_PORT ||
            bpf_ntohs(udp->source) == CONTROL_PORT) {
            return XDP_PASS;
        }
    }

    // Chỉ xử lý TCP và UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check source từ remote network
    __u32 k1 = 1, k2 = 2;
    __u32 *remote_net = bpf_map_lookup_elem(&config, &k1);
    __u32 *remote_mask = bpf_map_lookup_elem(&config, &k2);

    if (!remote_net || !remote_mask)
        return XDP_PASS;

    __u32 src_ip = bpf_ntohl(ip->saddr);
    if ((src_ip & *remote_mask) != (*remote_net & *remote_mask))
        return XDP_PASS;

    // Get local ifindex và MAC
    __u32 k3 = 3, k6 = 6;
    __u32 *local_if = bpf_map_lookup_elem(&config, &k3);
    __u64 *local_mac = bpf_map_lookup_elem(&macs, &k6);

    if (!local_if || !local_mac || *local_if == 0)
        return XDP_PASS;

    mac_copy(eth->h_source, *local_mac);

    // ARP lookup for destination MAC
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u64 *dst_mac = bpf_map_lookup_elem(&arp_cache, &dst_ip);

    if (dst_mac) {
        mac_copy(eth->h_dest, *dst_mac);
    } else {
        // Broadcast nếu không có trong ARP cache
        __builtin_memset(eth->h_dest, 0xff, 6);
    }

    return bpf_redirect(*local_if, 0);
}

char LICENSE[] SEC("license") = "GPL";
