CC = gcc
CLANG = clang
CFLAGS = -O2 -Wall -pthread
LDFLAGS = -lbpf -lxdp -lpthread

all: tunnel.bpf.o tunnel_node

tunnel.bpf.o: tunnel.bpf.c
        $(CLANG) -O2 -g -target bpf -c $< -o $@

tunnel_node: tunnel_node.c tunnel.h
        $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
        rm -f tunnel.bpf.o tunnel_node

.PHONY: all clean
