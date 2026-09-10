#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "../common.h"

#define AETHON_MAX_IPS 65536
#define AETHON_MAX_QUEUE_SIZE 64
#define MINUTE 60000000000ULL
#define AETHON_LIMIT_TOKEN 600
#define AETHON_MAX_XDP_RETURN_TYPE 5


// IP blocking map
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // globally blocked ips
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key, struct aethon_ip_address);
    __type(value, __u64);
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
} aethon_ip_ratelimit SEC(".maps");


// afxdp NIC queue to AF_XDP 
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


// rate limiting state
struct aethon_rate_limit_state{
    __u64 tokens;
    __u64 last_updated;
};


// records maps (PER CLIMITER)
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,__u32);
    __type(value,struct datarec);
    __uint(max_entries,AETHON_MAX_XDP_RETURN_TYPE);
} aethon_xdp_stats_map SEC(".maps");


// function to count records
static aethon_always_inline void stats_record_count(struct xdp_md * ctx, __u32 action){
    struct datarec *rec;
    __u32 key  = action;
    rec = (struct datarec * )bpf_map_lookup_elem(&aethon_xdp_stats_map,&key);
    if(rec){
        void * data_end = (void *)(long)ctx->data_end;
        void * data = (void *)(long)ctx->data;

        __u64 bytes  = (__u64)((__u64)data_end - (__u64)data);
        rec->rx_bytes+=bytes;
        rec->rx_packets+=1;
    }
}
SEC("xdp")
int aethon_xdp_prog_main(struct xdp_md * ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int action = XDP_PASS;

    bpf_printk("XDP triggered\n");

    // 1. Parse Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) 
        return XDP_DROP;

    // 2. Parse IP Header & Extract src_ip FIRST
    struct aethon_ip_address src_ip = {};
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) 
            return XDP_DROP;
        src_ip.addr.v4 = iph->saddr;
        src_ip.is_ipv6 = 0;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) 
            return XDP_DROP;
        __builtin_memcpy(src_ip.addr.v6, ip6h->saddr.in6_u.u6_addr32, 16);
        src_ip.is_ipv6 = 1;
    } else {
        // Non-IP traffic (ARP, etc.) -> Pass
        action = XDP_PASS;
        goto out;
    }

    // 3. Blocklist Check (Using the extracted src_ip)
    if (bpf_map_lookup_elem(&aethon_ip_blockist, &src_ip)) {
        action = XDP_DROP;
        goto out;
    }

    __u64 now = bpf_ktime_get_ns();
    struct aethon_rate_limit_state *state = bpf_map_lookup_elem(&aethon_ip_ratelimit, &src_ip);
    if (!state) {
        struct aethon_rate_limit_state init_state = {
            .tokens = AETHON_LIMIT_TOKEN - 1,
            .last_updated = now
        };
        bpf_map_update_elem(&aethon_ip_ratelimit, &src_ip, &init_state, BPF_ANY);
    } else {
        __u64 elapsed = now - state->last_updated;
        __u64 tokens_to_add = (elapsed * AETHON_LIMIT_TOKEN) / MINUTE;
        if (tokens_to_add > 0) {
            __u64 new_tokens = state->tokens + tokens_to_add;
            state->tokens = (new_tokens > AETHON_LIMIT_TOKEN) ? AETHON_LIMIT_TOKEN : new_tokens;
            state->last_updated = now;
        }

        if (state->tokens == 0) {
            action = XDP_DROP;
            goto out;
        }
        state->tokens -= 1;
    }

    __u32 queue_idx = ctx->rx_queue_index;
    action = bpf_redirect_map(&aethon_xsks_map, queue_idx, 0);
    bpf_printk("Packet received, redirect map ret: %d, qid: %d\n", action, queue_idx);

out:
    stats_record_count(ctx, action);
    return action;
}



char _license[] SEC("license") = "GPL";
