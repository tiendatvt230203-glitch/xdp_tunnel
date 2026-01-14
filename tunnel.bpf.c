// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// config[0] = remote_net, config[1] = remote_mask, config[2] = direction (0=TX, 1=RX)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

SEC("xdp")
int xdp_redirect_to_user(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end) return XDP_PASS;

    __u32 k = 0;
    __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 1;
    __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    k = 2;
    __u32 *direction = bpf_map_lookup_elem(&config, &k);

    if (!rnet || !rmask || !direction) return XDP_PASS;

    __u32 check_ip;
    if (*direction == 0) {
        // TX: check destination
        check_ip = bpf_ntohl(ip->daddr);
    } else {
        // RX: check source
        check_ip = bpf_ntohl(ip->saddr);
    }

    if ((check_ip & *rmask) != (*rnet & *rmask))
        return XDP_PASS;

    // Redirect to userspace via AF_XDP
    __u32 idx = 0;
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, XDP_DROP);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";

