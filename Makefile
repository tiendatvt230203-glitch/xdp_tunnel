CLANG ?= clang
CC ?= gcc
CFLAGS = -O2 -Wall
BPF_CFLAGS = -O2 -g -target bpf

all: tunnel.bpf.o tunnel_loader

tunnel.bpf.o: tunnel.bpf.c
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@

tunnel_loader: tunnel_loader.c
        $(CC) $(CFLAGS) $< -o $@ -lbpf

clean:
        rm -f tunnel.bpf.o tunnel_loader

.PHONY: all clean
