// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 65536);     // đủ cho (ifindex<<16 | qid)
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline __u32 xsk_key(struct xdp_md *ctx)
{
    __u32 ifi = ctx->ingress_ifindex;     // có trên kernel mới (5.15 OK)
    __u32 qid = ctx->rx_queue_index & 0xFFFF;
    return (ifi << 16) | qid;
}

SEC("xdp")
int xdp_xsk_redirect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    __u16 proto = __builtin_bswap16(eth->h_proto);

    // Cho ARP đi kernel (để neighbor discovery không chết)
    if (proto == ETH_P_ARP)
        return XDP_PASS;

    // IPv4/IPv6 redirect lên userspace
    if (proto == ETH_P_IP || proto == ETH_P_IPV6) {
        __u32 key = xsk_key(ctx);
        return bpf_redirect_map(&xsks_map, key, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

