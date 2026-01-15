// clang -O2 -target bpf -c xdp_rx_to_user.c -o xdp_rx_to_user.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_rx(struct xdp_md *ctx)
{
    __u32 qid = 0;

    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

