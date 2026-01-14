CLANG := clang
CC := gcc

BPF_CFLAGS := -O2 -target bpf -fno-builtin -Wno-unused-value
USER_CFLAGS := -O2 -g
LDFLAGS := -lbpf -lxdp

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tunnel_xdp: tunnel_loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f tunnel.bpf.o tunnel_xdp

