// tunnel.bpf.c - XDP program: redirect to AF_XDP, PASS others (never DROP)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    __u32 idx = ctx->rx_queue_index;

    // If XSK registered for this queue, redirect to it
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, XDP_PASS);

    // Otherwise PASS to kernel (never DROP!)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
