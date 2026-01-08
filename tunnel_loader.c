// XDP Classifier Loader - Setup maps and attach XDP
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

#define IFACE_LAN 0
#define IFACE_WAN 1
#define MAX_WAN 4
#define PIN_PATH "/sys/fs/bpf/tunnel"

static volatile int running = 1;
static struct bpf_object *obj;
static __u32 lan_ifindex;
static __u32 wan_ifindex[MAX_WAN];
static int wan_count;

static void sig_handler(int sig) { (void)sig; running = 0; }

static int setup_maps(const char *lan, const char *remote_net, char **wans, int nwan)
{
    int config_fd = bpf_object__find_map_fd_by_name(obj, "config");
    int iface_fd = bpf_object__find_map_fd_by_name(obj, "iface_map");
    if (config_fd < 0 || iface_fd < 0) {
        fprintf(stderr, "Map not found\n");
        return -1;
    }

    // Parse remote network (e.g., "192.168.182.0/24")
    char buf[64];
    strncpy(buf, remote_net, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    int prefix = 24;
    if (slash) { *slash = 0; prefix = atoi(slash + 1); }

    __u32 rnet = ntohl(inet_addr(buf));
    __u32 rmask = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;

    // Setup config map
    __u32 k = 0, v;
    v = rnet;  bpf_map_update_elem(config_fd, &k, &v, BPF_ANY); k++;
    v = rmask; bpf_map_update_elem(config_fd, &k, &v, BPF_ANY);

    // Setup interface map
    lan_ifindex = if_nametoindex(lan);
    if (!lan_ifindex) {
        fprintf(stderr, "LAN interface not found: %s\n", lan);
        return -1;
    }
    __u8 type = IFACE_LAN;
    bpf_map_update_elem(iface_fd, &lan_ifindex, &type, BPF_ANY);
    printf("LAN: %s (ifindex=%d)\n", lan, lan_ifindex);

    // Setup WAN interfaces
    wan_count = 0;
    type = IFACE_WAN;
    for (int i = 0; i < nwan && i < MAX_WAN; i++) {
        wan_ifindex[i] = if_nametoindex(wans[i]);
        if (!wan_ifindex[i]) {
            fprintf(stderr, "WAN interface not found: %s\n", wans[i]);
            continue;
        }
        bpf_map_update_elem(iface_fd, &wan_ifindex[i], &type, BPF_ANY);
        printf("WAN%d: %s (ifindex=%d)\n", i, wans[i], wan_ifindex[i]);
        wan_count++;
    }

    if (wan_count == 0) {
        fprintf(stderr, "No valid WAN interfaces\n");
        return -1;
    }

    printf("Remote: %s/%d\n", buf, prefix);
    return 0;
}

static void pin_maps(void)
{
    mkdir(PIN_PATH, 0755);

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", PIN_PATH, bpf_map__name(map));
        bpf_map__unpin(map, path);
        if (bpf_map__pin(map, path) == 0)
            printf("Pinned: %s\n", path);
    }
}

static void detach_all(void)
{
    if (lan_ifindex)
        bpf_xdp_detach(lan_ifindex, 0, NULL);
    for (int i = 0; i < wan_count; i++)
        if (wan_ifindex[i])
            bpf_xdp_detach(wan_ifindex[i], 0, NULL);
}

static int attach_xdp(void)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_classify");
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return -1;
    }
    int fd = bpf_program__fd(prog);

    // Attach to LAN
    if (bpf_xdp_attach(lan_ifindex, fd, 0, NULL) < 0) {
        fprintf(stderr, "Attach LAN failed\n");
        return -1;
    }
    printf("Attached to LAN\n");

    // Attach to WANs
    for (int i = 0; i < wan_count; i++) {
        if (bpf_xdp_attach(wan_ifindex[i], fd, 0, NULL) < 0) {
            fprintf(stderr, "Attach WAN%d failed\n", i);
            return -1;
        }
        printf("Attached to WAN%d\n", i);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        printf("Usage: %s <lan_iface> <remote_net/prefix> <wan1> [wan2] ...\n", argv[0]);
        printf("Example: %s enp7s0 192.168.182.0/24 eth1 eth2\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load BPF
    obj = bpf_object__open_file("tunnel.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Setup maps
    if (setup_maps(argv[1], argv[2], &argv[3], argc - 3) < 0) {
        bpf_object__close(obj);
        return 1;
    }

    // Pin maps for AF_XDP app
    pin_maps();

    // Attach XDP
    if (attach_xdp() < 0) {
        detach_all();
        bpf_object__close(obj);
        return 1;
    }

    printf("\nRunning. AF_XDP app can use maps at %s/xsks_map\n", PIN_PATH);
    printf("Press Ctrl+C to stop\n\n");

    while (running) {
        sleep(1);
    }

    printf("\nDetaching...\n");
    detach_all();
    bpf_object__close(obj);
    return 0;
}

