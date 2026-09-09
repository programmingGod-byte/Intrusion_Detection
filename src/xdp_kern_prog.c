#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define AETHON_MAX_IPS 65536
#define AETHON_MAX_QUEUE_SIZE 64


struct aethon_ip_address{
    union{
        unsigned int v4;
        unsigned int v6[4];
    } addr;

    unsigned int is_ipv6;
};





// IP blocking
struct {
    //   int (*type)[BPF_MAP_TYPE_HASH];
    __uint(type, BPF_MAP_TYPE_HASH); // globally blocked ips
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key,__u32);
    __type(value,__u64);
} aethon_ip_blockist SEC(".maps");


struct rate_limit_state{
    __u64 tokens;
    __u64 last_updated;
};

struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_HASH); // single cpu
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key,struct aethon_ip_address);
    __type(value, struct rate_limit_state);
} aethon_ip_ratelimit SEC(".mpas");


struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, AETHON_MAX_QUEUE_SIZE);
    __type(key, int);
    __type(value, int);
} aethon_xsks_map SEC(".maps");



// stats map
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct datarec);
  __uint(max_entries, XDP_ACTION_MAX);
} aetho_xdp_stats_map SEC(".maps");



// function to count records
static aethon_always_inline stats_record_count(struct xdp_md * ctx, __u32 action){
    
}


SEC("xdp")
int aethon_xdp_prog_main(struct xdp_md * ctx){
    void *data_end = (void *)(long)ctx->data_end;
     void *data = (void *)(long)ctx->data;

     struct ethhdr * eth = (struct ethhdr *)data;
     if((void *)(eth + 1)> data_end) return XDP_DROP;

     struct aethon_ip_address src_ip = {};

     if(eth->h_proto ==   bpf_htons(ETH_P_IP)) {// ipv4
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if((void *)(iph + 1) > data_end) return XDP_DROP;
        src_ip.addr.v4 = iph->saddr;
        src_ip.is_ipv6 = 0;
    }else if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if((void *)(ip6h + 1) > data_end) return XDP_DROP;

        __builtin_memcpy(src_ip.addr.v6,ip6h->saddr.in6_u.u6_addr32,16);
        src_ip.is_ipv6=  1;
    }else{
        return XDP_PASS;
    }      


    if(bpf_map_lookup_elem(&aethon_ip_blockist,&src_ip)) return XDP_DROP;
};
