// xdp_kern.c - Filter: local traffic PASS, remote traffic REDIRECT
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* Config map: key=0 -> local_net, key=1 -> local_mask */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  /* ARP, IPv6, etc -> kernel handles */

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Get local network config */
    __u32 k0 = 0, k1 = 1;
    __u32 *local_net = bpf_map_lookup_elem(&config, &k0);
    __u32 *local_mask = bpf_map_lookup_elem(&config, &k1);

    if (!local_net || !local_mask)
        return XDP_PASS;  /* No config -> pass all */

    /* Check if destination is LOCAL network */
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u32 net = *local_net;
    __u32 mask = *local_mask;

    if ((dst_ip & mask) == (net & mask)) {
        /* Destination is local network -> let kernel handle */
        return XDP_PASS;
    }

    /* Destination is REMOTE -> redirect to userspace */
    __u32 key = 0;
    if (bpf_map_lookup_elem(&xsks_map, &key))
        return bpf_redirect_map(&xsks_map, key, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
