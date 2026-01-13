CC = gcc
CFLAGS = -O2 -Wall -pthread
LDFLAGS = -lxdp -lbpf -lpthread -lssl -lcrypto

all: tunnel_node

tunnel_node: tunnel_node.c tunnel.h
        $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

key:
        openssl rand -out tunnel.key 32

clean:
        rm -f tunnel_node tunnel.key

.PHONY: all clean key
