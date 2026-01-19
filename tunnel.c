/* tunnel.c – FIXED theo ĐÚNG format config bạn dùng */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#define MAX_WAN     8
#define FRAMES      4096
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH       64
#define TX_FRAMES   256

static volatile int running = 1;

/* ================= CONFIG ================= */
static char local_if[32];
static uint8_t local_mac[6], client_mac[6];

static char wan_if[MAX_WAN][32];
static uint8_t wan_src_mac[MAX_WAN][6];
static uint8_t wan_peer_mac[MAX_WAN][6];
static int wan_count = 0;
static int selected_wan = 0;

static uint32_t remote_net, remote_mask;

/* ================= XSK ================= */
struct xsk_ctx {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *buf;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    __u32 tx_idx;
};

static struct xsk_ctx local_xsk, wan_xsk;

/* ================= HELPERS ================= */
static void sig_handler(int s){ (void)s; running = 0; }

static void get_mac(const char *ifname, uint8_t *mac){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
}

static void parse_mac(const char *s, uint8_t *mac){
    unsigned int m[6];
    sscanf(s, "%x:%x:%x:%x:%x:%x",
           &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
    for(int i=0;i<6;i++) mac[i]=m[i];
}

static void parse_cidr(const char *s, uint32_t *net, uint32_t *mask){
    char ip[32]; int p=24;
    strcpy(ip,s);
    char *c=strchr(ip,'/');
    if(c){ *c=0; p=atoi(c+1); }
    struct in_addr a;
    inet_aton(ip,&a);
    *net=ntohl(a.s_addr);
    *mask=p? (~0U<<(32-p)) : 0;
}

/* ================= CONFIG LOAD ================= */
static int load_config(const char *path){
    FILE *f=fopen(path,"r");
    if(!f) return -1;

    char line[256], k[32], v1[64], v2[64], v3[64];

    while(fgets(line,sizeof(line),f)){
        if(line[0]=='#'||line[0]=='\n') continue;
        v1[0]=v2[0]=v3[0]=0;
        sscanf(line,"%31s %63s %63s %63s",k,v1,v2,v3);

        if(!strcmp(k,"local")){
            strcpy(local_if,v1);
            get_mac(v1,local_mac);
        }
        else if(!strcmp(k,"client")){
            parse_mac(v1,client_mac);
        }
        else if(!strcmp(k,"remote")){
            parse_cidr(v1,&remote_net,&remote_mask);
        }
        else if(!strcmp(k,"wan") && wan_count<MAX_WAN){
            strcpy(wan_if[wan_count],v1);
            get_mac(v1,wan_src_mac[wan_count]);
            parse_mac(v3,wan_peer_mac[wan_count]);
            wan_count++;
        }
    }
    fclose(f);
    return (local_if[0] && wan_count>0 && remote_net)?0:-1;
}

/* ================= BPF ================= */
static int setup_bpf(const char *ifname,int mode,uint32_t net,uint32_t mask,int *xsks_fd){
    struct bpf_object *obj=bpf_object__open_file("xdp_kern.o",NULL);
    if(!obj) return -1;
    if(bpf_object__load(obj)) return -1;

    struct bpf_program *p=
        bpf_object__find_program_by_name(obj,"xdp_redirect_prog");
    int prog_fd=bpf_program__fd(p);

    *xsks_fd=bpf_object__find_map_fd_by_name(obj,"xsks_map");
    int cfg=bpf_object__find_map_fd_by_name(obj,"config");

    __u32 k,v;
    k=0; v=net;  bpf_map_update_elem(cfg,&k,&v,0);
    k=1; v=mask; bpf_map_update_elem(cfg,&k,&v,0);
    k=2; v=mode; bpf_map_update_elem(cfg,&k,&v,0);

    int ifi=if_nametoindex(ifname);
    bpf_set_link_xdp_fd(ifi,-1,XDP_FLAGS_SKB_MODE);
    if(bpf_set_link_xdp_fd(ifi,prog_fd,XDP_FLAGS_SKB_MODE)<0) return -1;
    return 0;
}

/* ================= XSK ================= */
static int setup_xsk(const char *ifname,int xsks_fd,struct xsk_ctx *x){
    posix_memalign(&x->buf,getpagesize(),FRAMES*FRAME_SIZE);

    struct xsk_umem_config ucfg={
        .fill_size=FRAMES,
        .comp_size=FRAMES,
        .frame_size=FRAME_SIZE
    };
    xsk_umem__create(&x->umem,x->buf,FRAMES*FRAME_SIZE,&x->fq,&x->cq,&ucfg);

    __u32 idx;
    xsk_ring_prod__reserve(&x->fq,FRAMES,&idx);
    for(int i=0;i<FRAMES;i++)
        *xsk_ring_prod__fill_addr(&x->fq,idx+i)=i*FRAME_SIZE;
    xsk_ring_prod__submit(&x->fq,FRAMES);

    struct xsk_socket_config cfg={
        .rx_size=2048,
        .tx_size=2048,
        .libbpf_flags=XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags=XDP_FLAGS_SKB_MODE,
        .bind_flags=XDP_COPY
    };

    if(xsk_socket__create(&x->xsk,ifname,0,x->umem,&x->rx,&x->tx,&cfg))
        return -1;

    int fd=xsk_socket__fd(x->xsk);
    __u32 key=0;
    bpf_map_update_elem(xsks_fd,&key,&fd,0);

    x->tx_idx=0;
    return 0;
}

/* ================= FORWARD ================= */
static void forward(struct xsk_ctx *src,struct xsk_ctx *dst,
                    uint8_t *smac,uint8_t *dmac){
    __u32 idx;
    unsigned int n=xsk_ring_cons__peek(&src->rx,BATCH,&idx);
    if(!n) return;

    __u32 c;
    unsigned int done=xsk_ring_cons__peek(&dst->cq,TX_FRAMES,&c);
    if(done) xsk_ring_cons__release(&dst->cq,done);

    for(unsigned int i=0;i<n;i++){
        struct xdp_desc *rd=xsk_ring_cons__rx_desc(&src->rx,idx+i);
        uint8_t *pkt=xsk_umem__get_data(src->buf,rd->addr);

        struct ethhdr *eth=(void*)pkt;
        memcpy(eth->h_source,smac,6);
        memcpy(eth->h_dest,dmac,6);

        __u32 t;
        if(xsk_ring_prod__reserve(&dst->tx,1,&t)==1){
            __u64 a=(dst->tx_idx++%TX_FRAMES)*FRAME_SIZE;
            memcpy(xsk_umem__get_data(dst->buf,a),pkt,rd->len);
            struct xdp_desc *td=xsk_ring_prod__tx_desc(&dst->tx,t);
            td->addr=a; td->len=rd->len;
            xsk_ring_prod__submit(&dst->tx,1);
            sendto(xsk_socket__fd(dst->xsk),NULL,0,MSG_DONTWAIT,NULL,0);
        }

        __u32 f;
        if(xsk_ring_prod__reserve(&src->fq,1,&f)==1){
            *xsk_ring_prod__fill_addr(&src->fq,f)=rd->addr;
            xsk_ring_prod__submit(&src->fq,1);
        }
    }
    xsk_ring_cons__release(&src->rx,n);
}

/* ================= MAIN ================= */
int main(int argc,char **argv){
    if(argc<3) return 1;
    selected_wan=atoi(argv[2]);

    struct rlimit r={RLIM_INFINITY,RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK,&r);
    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);

    if(load_config(argv[1])<0) return 1;
    if(selected_wan>=wan_count) return 1;

    int map_local,map_wan;

    setup_bpf(local_if,0,remote_net,remote_mask,&map_local);
    setup_bpf(wan_if[selected_wan],1,0,0,&map_wan);

    setup_xsk(local_if,map_local,&local_xsk);
    setup_xsk(wan_if[selected_wan],map_wan,&wan_xsk);

    struct pollfd fds[2]={
        {xsk_socket__fd(local_xsk.xsk),POLLIN},
        {xsk_socket__fd(wan_xsk.xsk),POLLIN}
    };

    while(running){
        poll(fds,2,50);
        forward(&local_xsk,&wan_xsk,
                wan_src_mac[selected_wan],
                wan_peer_mac[selected_wan]);
        forward(&wan_xsk,&local_xsk,
                local_mac,
                client_mac);
    }
    return 0;
}

