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

static volatile int running = 1;
static void sig(int s) { (void)s; running = 0; }

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("Usage: %s <iface> <bpf.o>\n", argv[0]);
        return 1;
    }

    char *ifname = argv[1];
    char *bpf_obj = argv[2];

    signal(SIGINT, sig);
    signal(SIGTERM, sig);

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "open bpf obj failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load bpf obj failed\n");
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "xdp_drop_all");
    if (!prog) {
        fprintf(stderr, "cannot find xdp program\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("attach xdp");
        return 1;
    }

    printf("XDP DROP attached on %s\n", ifname);
    printf("Ctrl+C to detach\n");

    while (running)
        sleep(1);

    bpf_set_link_xdp_fd(ifindex, -1, 0);
    printf("XDP detached\n");

    bpf_object__close(obj);
    return 0;
}

