#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_link.h>

char LICENSE[] SEC("license") = "GPL";

struct ip_port { __u32 ip; __u16 port; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct ip_port); __type(value, __u8); } allowed_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024); __type(key, __u16); __type(value, __u32); } lb_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_DEVMAP); __uint(max_entries,16); __type(key,__u32); __type(value,__u32);} dev_map SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,2); __type(key,__u32); __type(value,__u64);} counters SEC(".maps");

#define PASS_IDX 0
#define DROP_IDX 1

SEC("xdp")
int xdp_fw_lb(struct xdp_md *ctx){
    void *data=(void*)(long)ctx->data;
    void *data_end=(void*)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth+1)>data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto)!=ETH_P_IP) return XDP_PASS;

    struct iphdr *ip=(void*)(eth+1);
    if ((void*)(ip+1)>data_end) return XDP_PASS;
    if(ip->protocol!=IPPROTO_TCP) return XDP_PASS;

    __u32 ihl=ip->ihl*4;
    struct tcphdr *tcp=(void*)ip+ihl;
    if ((void*)(tcp+1)>data_end) return XDP_PASS;

    struct ip_port key = { ip->saddr, bpf_ntohs(tcp->dest) };
    __u8 *allow=bpf_map_lookup_elem(&allowed_map,&key);
    __u64 *cnt_pass=bpf_map_lookup_elem(&counters,&(u32){PASS_IDX});
    __u64 *cnt_drop=bpf_map_lookup_elem(&counters,&(u32){DROP_IDX});

    if(!allow){
        if(cnt_drop) __sync_fetch_and_add(cnt_drop,1);
        return XDP_DROP;
    }

    // REDIRECT
    __u32 *out_if=bpf_map_lookup_elem(&lb_map,&bpf_ntohs(tcp->dest));
    if(out_if){
        if(cnt_pass) __sync_fetch_and_add(cnt_pass,1);
        return bpf_redirect_map(&dev_map,*out_if,0);
    }

    if(cnt_pass) __sync_fetch_and_add(cnt_pass,1);
    return XDP_PASS;
}
