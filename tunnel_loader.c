// XDP Loader - Simple version
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>

static volatile int run = 1;
static void sig(int s) { (void)s; run = 0; }

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <lan> <remote/prefix> <wan1> [wan2...]\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig);
    signal(SIGTERM, sig);
    libbpf_set_print(NULL);

    // Load BPF
    struct bpf_object *obj = bpf_object__open_file("tunnel.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "BPF load failed\n");
        return 1;
    }

    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "config");
    int if_fd = bpf_object__find_map_fd_by_name(obj, "iface_map");
    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_classify"));

    // Setup remote network
    char buf[64]; strncpy(buf, argv[2], 63);
    char *sl = strchr(buf, '/');
    int pfx = sl ? (*sl = 0, atoi(sl + 1)) : 24;
    __u32 k = 0, rnet = ntohl(inet_addr(buf));
    __u32 rmask = 0xFFFFFFFF << (32 - pfx);
    bpf_map_update_elem(cfg_fd, &k, &rnet, 0); k = 1;
    bpf_map_update_elem(cfg_fd, &k, &rmask, 0);

    // Setup LAN
    __u32 lan = if_nametoindex(argv[1]);
    __u8 type = 0;
    bpf_map_update_elem(if_fd, &lan, &type, 0);
    bpf_set_link_xdp_fd(lan, prog_fd, 0);
    printf("LAN: %s\n", argv[1]);

    // Setup WANs
    __u32 wans[8]; int nwan = 0;
    type = 1;
    for (int i = 3; i < argc && nwan < 8; i++) {
        wans[nwan] = if_nametoindex(argv[i]);
        if (wans[nwan]) {
            bpf_map_update_elem(if_fd, &wans[nwan], &type, 0);
            bpf_set_link_xdp_fd(wans[nwan], prog_fd, 0);
            printf("WAN: %s\n", argv[i]);
            nwan++;
        }
    }

    // Pin map for AF_XDP
    mkdir("/sys/fs/bpf/tunnel", 0755);
    bpf_map__unpin(bpf_object__find_map_by_name(obj, "xsks_map"), "/sys/fs/bpf/tunnel/xsks_map");
    bpf_map__pin(bpf_object__find_map_by_name(obj, "xsks_map"), "/sys/fs/bpf/tunnel/xsks_map");

    printf("Running... Ctrl+C to stop\n");
    while (run) sleep(1);

    // Cleanup
    bpf_set_link_xdp_fd(lan, -1, 0);
    for (int i = 0; i < nwan; i++) bpf_set_link_xdp_fd(wans[i], -1, 0);
    bpf_object__close(obj);
    printf("Done\n");
    return 0;
}

