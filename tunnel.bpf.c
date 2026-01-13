// tunnel.bpf.c - XDP redirect to AF_XDP (v2)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TUN_ETYPE 0x88B6

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// mode: 0=LAN (intercept IP), 1=WAN (intercept tunnel)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} mode_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&mode_map, &key);
    __u32 m = mode ? *mode : 0;

    __u16 proto = bpf_ntohs(eth->h_proto);

    // LAN mode: intercept IP packets
    if (m == 0 && proto != ETH_P_IP)
        return XDP_PASS;

    // WAN mode: intercept tunnel frames
    if (m == 1 && proto != TUN_ETYPE)
        return XDP_PASS;

    // FIX A1: flags = 0, not XDP_DROP
    __u32 idx = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
