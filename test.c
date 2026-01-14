// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx)
{
    __u32 qid = ctx->rx_queue_index;

    // If userspace bound XSK to this queue => redirect to it
    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";



#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

static void hexdump_ascii(const unsigned char *p, int len) {
    for (int i = 0; i < len; i++) {
        unsigned char c = p[i];
        putchar((c >= 32 && c <= 126) ? c : '.');
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <xdp_prog.o>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *objfile = argv[2];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    // 1) load + attach XDP program
    struct bpf_object *obj = bpf_object__open_file(objfile, NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open bpf obj failed\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load bpf obj failed\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect");
    if (!prog) { fprintf(stderr, "find prog failed\n"); return 1; }

    int xsk_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xsk_map_fd < 0) { fprintf(stderr, "find xsks_map failed\n"); return 1; }

    if (bpf_set_link_xdp_fd(ifindex, bpf_program__fd(prog), 0) < 0) {
        perror("bpf_set_link_xdp_fd attach");
        return 1;
    }
    printf("[+] XDP attached on %s\n", ifname);

    // 2) create UMEM + XSK (queue 0)
    void *buffer;
    if (posix_memalign(&buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }

    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0
    };

    if (xsk_umem__create(&umem, buffer, NUM_FRAMES * FRAME_SIZE, &fq, &cq, &ucfg)) {
        fprintf(stderr, "xsk_umem__create failed\n");
        return 1;
    }

    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_socket_config xcfg = {
        .rx_size = 2048,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_USE_NEED_WAKEUP
    };

    int qid = 0;
    if (xsk_socket__create(&xsk, ifname, qid, umem, &rx, &tx, &xcfg)) {
        fprintf(stderr, "xsk_socket__create failed (need root, driver support)\n");
        return 1;
    }

    // 3) put XSK fd into xsks_map at key=queue_id
    int xsk_fd = xsk_socket__fd(xsk);
    __u32 key = qid;
    if (bpf_map_update_elem(xsk_map_fd, &key, &xsk_fd, 0) < 0) {
        perror("bpf_map_update_elem xsks_map");
        return 1;
    }

    // 4) fill FQ with frame addresses
    __u32 idx;
    if (xsk_ring_prod__reserve(&fq, NUM_FRAMES, &idx) != NUM_FRAMES) {
        fprintf(stderr, "reserve fq failed\n");
        return 1;
    }
    for (__u32 i = 0; i < NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&fq, idx + i) = (__u64)i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&fq, NUM_FRAMES);

    printf("[+] AF_XDP ready on %s queue %d. Waiting packets...\n", ifname, qid);

    // 5) recv loop
    while (1) {
        __u32 rcvd = xsk_ring_cons__peek(&rx, 64, &idx);
        if (!rcvd) {
            usleep(1000);
            continue;
        }

        for (__u32 i = 0; i < rcvd; i++) {
            struct xdp_desc *d = xsk_ring_cons__rx_desc(&rx, idx + i);
            __u64 addr = d->addr;
            __u32 len  = d->len;

            unsigned char *pkt = xsk_umem__get_data(buffer, addr);

            printf("RX len=%u payload='", len);
            int show = (len > 120) ? 120 : (int)len;
            hexdump_ascii(pkt, show);
            printf("'\n");

            // recycle frame back to FQ
            __u32 fidx;
            if (xsk_ring_prod__reserve(&fq, 1, &fidx) == 1) {
                *xsk_ring_prod__fill_addr(&fq, fidx) = addr;
                xsk_ring_prod__submit(&fq, 1);
            }
        }
        xsk_ring_cons__release(&rx, rcvd);
    }

    return 0;
}



sen

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int get_mac(const char *ifname, unsigned char mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

// resolve L2 dest MAC via ARP (ping first)
static int get_peer_mac(const char *ifname, const char *peer_ip, unsigned char mac[6]) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W1 -I %s %s >/dev/null 2>&1", ifname, peer_ip);
    (void)system(cmd);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct arpreq q = {0};
    ((struct sockaddr_in*)&q.arp_pa)->sin_family = AF_INET;
    inet_pton(AF_INET, peer_ip, &((struct sockaddr_in*)&q.arp_pa)->sin_addr);
    strncpy(q.arp_dev, ifname, IFNAMSIZ-1);

    int ret = ioctl(fd, SIOCGARP, &q);
    close(fd);
    if (ret == 0) memcpy(mac, q.arp_ha.sa_data, 6);
    return ret;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <wan_iface> <peer_ip_on_that_wan> <message>\n"
            "Example: %s enp4s0 192.168.11.1 HELLO_WAN4\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *wan = argv[1];
    const char *peer_ip = argv[2];
    const char *msg = argv[3];

    int ifindex = if_nametoindex(wan);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    unsigned char smac[6], dmac[6];
    if (get_mac(wan, smac) < 0) { fprintf(stderr, "get_mac failed\n"); return 1; }
    if (get_peer_mac(wan, peer_ip, dmac) < 0) {
        fprintf(stderr, "get_peer_mac ARP failed. peer_ip must be L2-reachable on %s\n", wan);
        return 1;
    }

    // Frame: Ethernet + payload (no IP needed for this test)
    unsigned char frame[1514];
    memset(frame, 0, sizeof(frame));

    struct ethhdr *eth = (struct ethhdr*)frame;
    memcpy(eth->h_dest, dmac, 6);
    memcpy(eth->h_source, smac, 6);
    eth->h_proto = htons(0x88B5); // custom ethertype for testing

    int msg_len = (int)strlen(msg);
    if (msg_len > 1400) msg_len = 1400;
    memcpy(frame + sizeof(struct ethhdr), msg, msg_len);

    int len = sizeof(struct ethhdr) + msg_len;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;   // <<< chọn WAN ở đây, route không ảnh hưởng
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dmac, 6);

    if (sendto(fd, frame, len, 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        return 1;
    }

    printf("[+] Sent %d bytes via %s to peer %s (ethertype 0x88B5)\n", len, wan, peer_ip);
    return 0;
}


make


CLANG=clang
CC=gcc

all: xdp_recv_kern.o recv_xsk send_raw

xdp_recv_kern.o: xdp_recv_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

recv_xsk: recv_xsk.c
	$(CC) -O2 -g $< -o $@ -lbpf -lxdp

send_raw: send_raw.c
	$(CC) -O2 -g $< -o $@

clean:
	rm -f xdp_recv_kern.o recv_xsk send_raw

