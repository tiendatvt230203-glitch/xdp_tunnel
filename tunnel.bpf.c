// SPDX-License-Identifier: GPL-2.0
// XDP Classifier - Redirect to AF_XDP
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define QUEUE_OUTGOING  0
#define QUEUE_INCOMING  1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u8);
} iface_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_classify(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 k = 0;
    __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 1;
    __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    if (!rnet || !rmask)
        return XDP_PASS;

    __u32 ifindex = ctx->ingress_ifindex;
    __u8 *iface_type = bpf_map_lookup_elem(&iface_map, &ifindex);
    if (!iface_type)
        return XDP_PASS;

    __u32 saddr = bpf_ntohl(ip->saddr);
    __u32 daddr = bpf_ntohl(ip->daddr);

    if (*iface_type == 0) {
        if ((daddr & *rmask) == (*rnet & *rmask))
            return bpf_redirect_map(&xsks_map, QUEUE_OUTGOING, XDP_PASS);
    } else {
        if ((saddr & *rmask) == (*rnet & *rmask))
            return bpf_redirect_map(&xsks_map, QUEUE_INCOMING, XDP_PASS);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
