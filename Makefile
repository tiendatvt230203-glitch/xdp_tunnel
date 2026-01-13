CC = gcc
CLANG = clang
CFLAGS = -O2 -Wall -pthread
LDFLAGS = -lbpf -lxdp -lpthread

all: tunnel.bpf.o tunnel_daemon

tunnel.bpf.o: tunnel.bpf.c
        $(CLANG) -O2 -g -target bpf -c $< -o $@

tunnel_daemon: tunnel_daemon.c common.h
        $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
        rm -f tunnel.bpf.o tunnel_daemon

.PHONY: all clean
