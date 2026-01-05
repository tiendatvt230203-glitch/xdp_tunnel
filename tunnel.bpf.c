// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_WAN 3
#define CHUNK_SHIFT 16  // 64KB per chunk

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 16); __type(key, __u32); __type(value, __u32); } config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 8); __type(key, __u32); __type(value, __u64); } macs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 256); __type(key, __u32); __type(value, __u64); } arp_cache SEC(".maps");

static __always_inline void set_mac(__u8 *d, __u64 m) {
    d[0]=m; d[1]=m>>8; d[2]=m>>16; d[3]=m>>24; d[4]=m>>32; d[5]=m>>40;
}

SEC("xdp_local")
int xdp_tx(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth+1) > end || eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth+1);
    if ((void*)(ip+1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

    __u32 k=0; __u32 *nwan = bpf_map_lookup_elem(&config, &k);
    k=1; __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k=2; __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    if (!nwan || !rnet || !rmask || *nwan == 0) return XDP_PASS;
    if ((bpf_ntohl(ip->daddr) & *rmask) != (*rnet & *rmask)) return XDP_PASS;

    __u32 idx = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + (ip->ihl*4);
        if ((void*)(tcp+1) > end) return XDP_PASS;
        idx = (bpf_ntohl(tcp->seq) >> CHUNK_SHIFT) % *nwan;
    } else {
        idx = bpf_ntohs(ip->id) % *nwan;
    }

    k = 4+idx; __u32 *wif = bpf_map_lookup_elem(&config, &k);
    __u64 *smac = bpf_map_lookup_elem(&macs, &idx);
    k = idx+MAX_WAN; __u64 *dmac = bpf_map_lookup_elem(&macs, &k);
    if (!wif || !smac || !dmac || *wif == 0) return XDP_PASS;

    set_mac(eth->h_source, *smac);
    set_mac(eth->h_dest, *dmac);
    return bpf_redirect(*wif, 0);
}

SEC("xdp_wan")
int xdp_rx(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth+1) > end || eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth+1);
    if ((void*)(ip+1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

    __u32 k=1; __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k=2; __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    if (!rnet || !rmask) return XDP_PASS;
    if ((bpf_ntohl(ip->saddr) & *rmask) != (*rnet & *rmask)) return XDP_PASS;

    k=3; __u32 *lif = bpf_map_lookup_elem(&config, &k);
    k=6; __u64 *lmac = bpf_map_lookup_elem(&macs, &k);
    if (!lif || !lmac || *lif == 0) return XDP_PASS;

    set_mac(eth->h_source, *lmac);
    __u32 dip = bpf_ntohl(ip->daddr);
    __u64 *dm = bpf_map_lookup_elem(&arp_cache, &dip);
    if (dm) set_mac(eth->h_dest, *dm);
    else __builtin_memset(eth->h_dest, 0xff, 6);

    return bpf_redirect(*lif, 0);
}

char LICENSE[] SEC("license") = "GPL";
