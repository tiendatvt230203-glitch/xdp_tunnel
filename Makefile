CLANG := clang
CC := gcc

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

tunnel_xdp: tunnel_loader.c
	$(CC) -O2 -g $< -o $@ -lbpf -lxdp

clean:
	rm -f tunnel.bpf.o tunnel_xdp

