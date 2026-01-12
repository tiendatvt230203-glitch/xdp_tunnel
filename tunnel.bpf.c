// tunnel.bpf.c - XDP program to redirect LAN traffic to AF_XDP
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// XSKMAP for AF_XDP sockets
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Config map: which subnets to redirect (0 = redirect all IPv4)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // 1 = enabled, 0 = disabled
} config_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 for now
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Check if tunnel is enabled
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config_map, &key);
    if (!enabled || *enabled == 0)
        return XDP_PASS;

    // Redirect to AF_XDP socket
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
