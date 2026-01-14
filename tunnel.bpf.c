// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel - Redirect to userspace for encryption, then load balance
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define MAX_WAN 3

// AF_XDP socket map - userspace bind vào đây
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Config map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// MAC addresses map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} macs SEC(".maps");

/*
 * XDP_LOCAL: Chạy trên LOCAL interface
 * Bắt packet từ LAN → redirect lên userspace để mã hóa
 */
SEC("xdp_local")
int xdp_tx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end)
        return XDP_PASS;

    // Lấy config
    __u32 k = 1;
    __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 2;
    __u32 *rmask = bpf_map_lookup_elem(&config, &k);

    if (!rnet || !rmask)
        return XDP_PASS;

    // Chỉ xử lý packet đến remote network
    if ((bpf_ntohl(ip->daddr) & *rmask) != (*rnet & *rmask))
        return XDP_PASS;

    // Redirect lên userspace qua AF_XDP để mã hóa
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);

    return XDP_PASS;
}

/*
 * XDP_WAN: Chạy trên WAN interfaces
 * Bắt packet từ WAN → redirect lên userspace để giải mã
 */
SEC("xdp_wan")
int xdp_rx(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end)
        return XDP_PASS;

    // Lấy config
    __u32 k = 1;
    __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 2;
    __u32 *rmask = bpf_map_lookup_elem(&config, &k);

    if (!rnet || !rmask)
        return XDP_PASS;

    // Chỉ xử lý packet từ remote network
    if ((bpf_ntohl(ip->saddr) & *rmask) != (*rnet & *rmask))
        return XDP_PASS;

    // Redirect lên userspace qua AF_XDP để giải mã
    __u32 index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
