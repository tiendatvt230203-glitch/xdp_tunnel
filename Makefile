CLANG := clang
CC := gcc

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) -O2 -target bpf -c $< -o $@

tunnel_xdp: tunnel_xdp.c
	$(CC) -O2 -g $< -o $@ -lbpf

clean:
	rm -f tunnel.bpf.o tunnel_xdp

