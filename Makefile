CLANG := clang
CC := gcc

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS := -O2 -g -Wall
USER_LDFLAGS := -lbpf

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tunnel_xdp: tunnel_xdp.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f tunnel.bpf.o tunnel_xdp

