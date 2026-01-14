CLANG ?= clang
CC ?= gcc

BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf
USER_CFLAGS := -O2 -g -Wall -Wextra

LIBS := -lbpf -lelf -lz

all: tunnel.bpf.o tunnel_xdp

tunnel.bpf.o: tunnel.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tunnel_xdp: tunnel_xdp.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f tunnel.bpf.o tunnel_xdp

