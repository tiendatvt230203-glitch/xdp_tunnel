// SPDX-License-Identifier: GPL-2.0
// XDP Tunnel - Load Balancing với hook mã hóa
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

// ============== HOOK MÃ HÓA (THÊM SAU) ==============
// Trả về 0 = OK, -1 = drop packet
static __always_inline int encrypt_hook(void *data, void *end, struct iphdr *ip) {
    // TODO: Thêm mã hóa payload ở đây
    return 0;
}

static __always_inline int decrypt_hook(void *data, void *end, struct iphdr *ip) {
    // TODO: Thêm giải mã payload ở đây
    return 0;
}
// ====================================================

// Jenkins hash - phân phối đều hơn XOR
static __always_inline __u32 jhash_3words(__u32 a, __u32 b, __u32 c) {
    a += 0xdeadbeef;
    b += 0xdeadbeef;
    c += 0xdeadbeef;

    c ^= b; c -= (b << 14) | (b >> 18);
    a ^= c; a -= (c << 11) | (c >> 21);
    b ^= a; b -= (a << 25) | (a >> 7);
    c ^= b; c -= (b << 16) | (b >> 16);
    a ^= c; a -= (c << 4) | (c >> 28);
    b ^= a; b -= (a << 14) | (a >> 18);
    c ^= b; c -= (b << 24) | (b >> 8);

    return c;
}

// Hash 5-tuple để chọn WAN
static __always_inline __u32 flow_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto, __u32 nwan) {
    __u32 hash = jhash_3words(saddr ^ daddr, ((__u32)sport << 16) | dport, proto);
    return hash % nwan;
}

// Maps
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 16); __type(key, __u32); __type(value, __u32); } config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 8); __type(key, __u32); __type(value, __u64); } macs SEC(".maps");

static __always_inline void set_mac(__u8 *d, __u64 m) {
    d[0]=m; d[1]=m>>8; d[2]=m>>16; d[3]=m>>24; d[4]=m>>32; d[5]=m>>40;
}

SEC("xdp_local")
int xdp_tx(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Lấy config
    __u32 k = 0;
    __u32 *nwan = bpf_map_lookup_elem(&config, &k);
    k = 1; __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 2; __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    if (!nwan || !rnet || !rmask || *nwan == 0) return XDP_PASS;

    // Chỉ xử lý packet đến remote network
    if ((bpf_ntohl(ip->daddr) & *rmask) != (*rnet & *rmask)) return XDP_PASS;

    // Lấy port để hash
    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + (ip->ihl * 4);
        if ((void*)(tcp + 1) > end) return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + (ip->ihl * 4);
        if ((void*)(udp + 1) > end) return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    // Hash chọn WAN
    __u32 idx = flow_hash(ip->saddr, ip->daddr, sport, dport, ip->protocol, *nwan);

    // Lấy WAN interface và MAC
    k = 4 + idx;
    __u32 *wif = bpf_map_lookup_elem(&config, &k);
    __u64 *smac = bpf_map_lookup_elem(&macs, &idx);
    k = idx + MAX_WAN;
    __u64 *dmac = bpf_map_lookup_elem(&macs, &k);
    if (!wif || !smac || !dmac || *wif == 0) return XDP_PASS;

    // HOOK: Mã hóa trước khi gửi
    if (encrypt_hook(data, end, ip) < 0) return XDP_DROP;

    // Set MAC và redirect
    set_mac(eth->h_source, *smac);
    set_mac(eth->h_dest, *dmac);
    return bpf_redirect(*wif, 0);
}

SEC("xdp_wan")
int xdp_rx(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Kiểm tra source từ remote network
    __u32 k = 1;
    __u32 *rnet = bpf_map_lookup_elem(&config, &k);
    k = 2; __u32 *rmask = bpf_map_lookup_elem(&config, &k);
    if (!rnet || !rmask) return XDP_PASS;
    if ((bpf_ntohl(ip->saddr) & *rmask) != (*rnet & *rmask)) return XDP_PASS;

    k = 3;
    __u32 *lif = bpf_map_lookup_elem(&config, &k);
    if (!lif || *lif == 0) return XDP_PASS;

    // HOOK: Giải mã sau khi nhận
    if (decrypt_hook(data, end, ip) < 0) return XDP_DROP;

    // FIB lookup để lấy MAC đích
    struct bpf_fib_lookup fib = {0};
    fib.family = AF_INET;
    fib.ipv4_dst = ip->daddr;
    fib.ipv4_src = ip->saddr;
    fib.ifindex = *lif;

    int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        __builtin_memcpy(eth->h_dest, fib.dmac, 6);
        __builtin_memcpy(eth->h_source, fib.smac, 6);
        return bpf_redirect(*lif, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
