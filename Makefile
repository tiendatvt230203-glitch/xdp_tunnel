# AF_XDP Tunnel Makefile

CC = gcc
CLANG = clang

CFLAGS = -Wall -O2 -g
LDFLAGS = -lbpf -lxdp -lpthread

BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean

all: xdp_kern.o tunnel
        @echo ""
        @echo "Build complete!"
        @echo ""
        @echo "Usage: sudo ./tunnel <config_file> <wan_index>"
        @echo "Example: sudo ./tunnel config/server1.conf 1"
        @echo ""

xdp_kern.o: xdp_kern.c
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@
        @echo "[OK] Built XDP: $@"

tunnel: tunnel.c
        $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
        @echo "[OK] Built tunnel: $@"

clean:
        rm -f xdp_kern.o tunnel
        @echo "[OK] Cleaned"
