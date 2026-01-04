// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel - TCP/UDP Load Balancer with WAN Health Check
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_WAN 3

// Config: [0]=nwan, [1]=remote_net, [2]=remote_mask, [3]=local_if, [4-6]=wan_if
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// MACs: [0-2]=wan_src, [3-5]=wan_dst, [6]=local
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} macs SEC(".maps");

// WAN status: 0=down, 1=up
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WAN);
    __type(key, __u32);
    __type(value, __u32);
} wan_status SEC(".maps");

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

// Find next active WAN using round-robin, skip down WANs
static __always_inline int find_active_wan(__u32 start_idx, __u32 nwan)
{
    __u32 idx = start_idx;

    #pragma unroll
    for (int i = 0; i < MAX_WAN; i++) {
        if (idx >= nwan)
            idx = 0;

        __u32 *status = bpf_map_lookup_elem(&wan_status, &idx);
        if (status && *status == 1)
            return idx;

        idx++;
    }

    return -1;  // No active WAN
}

// ==================== TX: Local -> WAN (round-robin with health check) ====================
SEC("xdp")
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

    // Handle both TCP and UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Load config
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u32 *nwan = bpf_map_lookup_elem(&config, &k0);
    __u32 *remote_net = bpf_map_lookup_elem(&config, &k1);
    __u32 *remote_mask = bpf_map_lookup_elem(&config, &k2);

    if (!nwan || !remote_net || !remote_mask || *nwan == 0)
        return XDP_PASS;

    // Check if destination is in remote network
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    if ((dst_ip & *remote_mask) != (*remote_net & *remote_mask))
        return XDP_PASS;

    // Round-robin starting point
    __u32 start_idx = bpf_ntohs(ip->id) % *nwan;

    // Find active WAN (skip down WANs)
    int wan_idx = find_active_wan(start_idx, *nwan);
    if (wan_idx < 0)
        return XDP_PASS;  // No active WAN, let kernel handle

    __u32 idx = wan_idx;

    // Get WAN ifindex
    __u32 if_key = 4 + idx;
    __u32 *wan_if = bpf_map_lookup_elem(&config, &if_key);
    if (!wan_if || *wan_if == 0)
        return XDP_PASS;

    // Get MACs
    __u64 *src_mac = bpf_map_lookup_elem(&macs, &idx);
    __u32 dst_key = idx + MAX_WAN;
    __u64 *dst_mac = bpf_map_lookup_elem(&macs, &dst_key);

    if (!src_mac || !dst_mac)
        return XDP_PASS;

    mac_copy(eth->h_source, *src_mac);
    mac_copy(eth->h_dest, *dst_mac);

    return bpf_redirect(*wan_if, 0);
}

// ==================== RX: WAN -> Local ====================
SEC("xdp")
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

    // Handle both TCP and UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check if source is from remote network
    __u32 k1 = 1, k2 = 2;
    __u32 *remote_net = bpf_map_lookup_elem(&config, &k1);
    __u32 *remote_mask = bpf_map_lookup_elem(&config, &k2);

    if (!remote_net || !remote_mask)
        return XDP_PASS;

    __u32 src_ip = bpf_ntohl(ip->saddr);
    if ((src_ip & *remote_mask) != (*remote_net & *remote_mask))
        return XDP_PASS;

    // Get local ifindex
    __u32 k3 = 3;
    __u32 *local_if = bpf_map_lookup_elem(&config, &k3);
    if (!local_if || *local_if == 0)
        return XDP_PASS;

    // Get local MAC
    __u32 k6 = 6;
    __u64 *local_mac = bpf_map_lookup_elem(&macs, &k6);
    if (!local_mac)
        return XDP_PASS;

    mac_copy(eth->h_source, *local_mac);

    // ARP lookup for destination
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u64 *dst_mac = bpf_map_lookup_elem(&arp_cache, &dst_ip);

    if (dst_mac) {
        mac_copy(eth->h_dest, *dst_mac);
    } else {
        __builtin_memset(eth->h_dest, 0xff, 6);
    }

    return bpf_redirect(*local_if, 0);
}

char LICENSE[] SEC("license") = "GPL";
