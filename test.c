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



// gcc -O2 user_rx.c -o user_rx -lbpf
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include <bpf/bpf.h>

#define FRAMES 1024
#define FRAME_SIZE 2048

int main(int argc, char **argv)
{
    int ifindex = if_nametoindex(argv[1]);
    int xsk = socket(AF_XDP, SOCK_RAW, 0);

    void *umem = mmap(NULL, FRAMES * FRAME_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    struct xdp_umem_reg mr = {
        .addr = (uint64_t)umem,
        .len = FRAMES * FRAME_SIZE,
        .chunk_size = FRAME_SIZE,
    };

    setsockopt(xsk, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));

    int rx = FRAMES, fq = FRAMES;
    setsockopt(xsk, SOL_XDP, XDP_RX_RING, &rx, sizeof(rx));
    setsockopt(xsk, SOL_XDP, XDP_UMEM_FILL_RING, &fq, sizeof(fq));

    struct sockaddr_xdp sxdp = {
        .sxdp_family = AF_XDP,
        .sxdp_ifindex = ifindex,
        .sxdp_queue_id = 0,
    };
    bind(xsk, (void *)&sxdp, sizeof(sxdp));

    int map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    __u32 key = 0;
    bpf_map_update_elem(map_fd, &key, &xsk, 0);

    printf("listening...\n");

    while (1) {
        char buf[2048];
        recv(xsk, buf, sizeof(buf), 0);
        printf("packet received\n");
    }
}



clang -O2 -target bpf -c xdp_rx_to_user.c -o xdp_rx_to_user.o
sudo ip link set dev enp4s0 xdp obj xdp_rx_to_user.o sec xdp
sudo ./user_rx enp4s0

