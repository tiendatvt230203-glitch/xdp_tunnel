#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_IF 16

static volatile int running = 1;
static void sig(int s) { (void)s; running = 0; }

static void die(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <bpf.o> <wan_if1> [wan_if2] [wan_if3]...\n", argv[0]);
        fprintf(stderr, "Example: %s ./tunnel.bpf.o enp4s0 enp5s0 enp6s0\n", argv[0]);
        return 1;
    }

    const char *bpf_obj = argv[1];
    int n_if = argc - 2;
    if (n_if > MAX_IF) die("too many interfaces");

    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    /* load BPF */
    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) die("bpf_object__open_file failed");
    if (bpf_object__load(obj)) die("bpf_object__load failed");

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_drop_all");
    if (!prog) {
        fprintf(stderr, "Cannot find program 'xdp_drop_all'\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) die("bpf_program__fd failed");

    int ifindex[MAX_IF] = {0};
    __u32 flags_used[MAX_IF] = {0};

    /* attach XDP to each WAN interface */
    for (int i = 0; i < n_if; i++) {
        const char *ifname = argv[i + 2];
        ifindex[i] = if_nametoindex(ifname);
        if (!ifindex[i]) {
            fprintf(stderr, "if_nametoindex(%s) failed\n", ifname);
            continue;
        }

        __u32 flags = 0; /* native */
        if (bpf_set_link_xdp_fd(ifindex[i], prog_fd, flags) < 0) {
            /* fallback generic */
            flags = XDP_FLAGS_SKB_MODE;
            if (bpf_set_link_xdp_fd(ifindex[i], prog_fd, flags) < 0) {
                fprintf(stderr, "Attach XDP failed on %s: %s\n", ifname, strerror(errno));
                ifindex[i] = 0;
                continue;
            }
        }

        flags_used[i] = flags;
        printf("XDP DROP attached on %s (ifindex=%d) mode=%s\n",
               ifname, ifindex[i], flags ? "generic" : "native");
    }

    printf("Running... Ctrl+C to detach\n");
    while (running) sleep(1);

    /* detach */
    for (int i = 0; i < n_if; i++) {
        if (!ifindex[i]) continue;
        if (bpf_set_link_xdp_fd(ifindex[i], -1, flags_used[i]) < 0) {
            fprintf(stderr, "Detach failed ifindex=%d: %s\n", ifindex[i], strerror(errno));
        }
    }
    printf("Detached.\n");

    bpf_object__close(obj);
    return 0;
}

