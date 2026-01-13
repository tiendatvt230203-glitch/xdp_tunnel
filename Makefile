CC = gcc
CLANG = clang
CFLAGS = -O2 -Wall -pthread
LDFLAGS = -lbpf -lxdp -lpthread

all: tunnel.bpf.o tunnel_xdp_lb

tunnel.bpf.o: tunnel.bpf.c
        $(CLANG) -O2 -g -target bpf -c $< -o $@

tunnel_xdp_lb: tunnel_xdp_lb.c
        $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
        rm -f tunnel.bpf.o tunnel_xdp_lb

.PHONY: all clean
