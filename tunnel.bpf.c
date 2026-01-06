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
#define WINDOW_SIZE 65536  // 64KB per window

// Flow key (5-tuple)
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// Connection state
struct conn_state {
    __u32 isn;              // Initial Sequence Number
    __u32 current_wan;      // Current WAN index
    __u32 window_start_seq; // Sequence number at start of current window
    __u32 bytes_in_window;  // Bytes sent in current window
};

// Maps
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 16); __type(key, __u32); __type(value, __u32); } config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 8); __type(key, __u32); __type(value, __u64); } macs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 256); __type(key, __u32); __type(value, __u64); } arp_cache SEC(".maps");

// Track connection state
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct conn_state);
} conn_track SEC(".maps");

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

        // Create flow key
        struct flow_key fkey = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .sport = tcp->source,
            .dport = tcp->dest
        };

        __u32 seq = bpf_ntohl(tcp->seq);
        __u16 payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);

        // Check if SYN packet (new connection)
        if (tcp->syn && !tcp->ack) {
            // New connection - initialize state
            struct conn_state state = {
                .isn = seq,
                .current_wan = 0,  // Start with WAN0
                .window_start_seq = seq,
                .bytes_in_window = 0
            };
            bpf_map_update_elem(&conn_track, &fkey, &state, BPF_ANY);
            idx = 0;
        } else {
            // Existing connection
            struct conn_state *state = bpf_map_lookup_elem(&conn_track, &fkey);
            if (state) {
                // Calculate bytes from window start
                __u32 seq_from_window_start;

                // Handle sequence number wrap-around
                if (seq >= state->window_start_seq) {
                    seq_from_window_start = seq - state->window_start_seq;
                } else {
                    // Wrap-around case
                    seq_from_window_start = (0xFFFFFFFF - state->window_start_seq) + seq + 1;
                }

                // Check if we need to move to next window
                if (seq_from_window_start >= WINDOW_SIZE) {
                    // Move to next WAN (round-robin)
                    state->current_wan = (state->current_wan + 1) % *nwan;
                    state->window_start_seq = seq;
                    state->bytes_in_window = payload_len;
                } else {
                    state->bytes_in_window += payload_len;
                }

                idx = state->current_wan;
            } else {
                // No state found - fallback to flow hash
                __u32 hash = fkey.saddr ^ fkey.daddr ^ ((__u32)fkey.sport << 16 | fkey.dport);
                idx = hash % *nwan;
            }
        }

        // Clean up on FIN/RST
        if (tcp->fin || tcp->rst) {
            bpf_map_delete_elem(&conn_track, &fkey);
        }
    } else {
        // UDP: use IP ID
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
