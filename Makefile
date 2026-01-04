# XDP Tunnel Makefile (TCP/UDP)

CLANG := clang
CC := gcc

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include
BPF_CFLAGS += -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

USER_CFLAGS := -O2 -g -Wall
USER_LDFLAGS := -lbpf -lelf -lz -lpthread

.PHONY: all clean run detach

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tunnel_xdp: tunnel_loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f tunnel.bpf.o tunnel_xdp

run:
	sudo ./tunnel_xdp config/server1.conf ./tunnel.bpf.o

detach:
	@echo "Detaching XDP..."
	-sudo ip link set dev ens36 xdp off 2>/dev/null
	-sudo ip link set dev ens37 xdp off 2>/dev/null
	-sudo ip link set dev ens38 xdp off 2>/dev/null
	-sudo ip link set dev ens39 xdp off 2>/dev/null
	@echo "Done"

