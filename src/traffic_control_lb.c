#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_BACKENDS 8

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct backend_list {
    __u32 count;
    __u32 addrs[MAX_BACKENDS];
};

struct conn_info {
    __u32 client_ip;
    __u16 client_port;
    __u32 backend_ip;
    __u16 backend_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct backend_list);
} lb_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u32);
} lb_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct conn_info);
    __type(value, struct conn_info);
} conntrack_map SEC(".maps");

static __inline void l4_checksum_recalc(struct iphdr *iph, struct tcphdr *tcph) {
    tcph->check = 0;
    iph->check = 0;
}

SEC("tc")
int tclbrr(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcph = (void*)iph + iph->ihl * 4;
    if ((void*)(tcph + 1) > data_end) return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcph->dest);
    __u16 sport = bpf_ntohs(tcph->source);

    struct conn_info conn_key = {
        .client_ip = iph->daddr,
        .client_port = dport,
        .backend_ip = iph->saddr,
        .backend_port = sport
    };
    struct conn_info *conn_val_ptr = bpf_map_lookup_elem(&conntrack_map, &conn_key);
    if (conn_val_ptr) {
        struct conn_info conn_val = *conn_val_ptr; // stack copy
        iph->saddr = conn_val.backend_ip;
        iph->daddr = conn_val.client_ip;
        tcph->source = bpf_htons(conn_val.backend_port);
        tcph->dest = bpf_htons(conn_val.client_port);
        l4_checksum_recalc(iph, tcph);
        return TC_ACT_OK;
    }

    if (tcph->syn && !tcph->ack) {
        struct backend_list *backends_ptr = bpf_map_lookup_elem(&lb_map, &dport);
        if (!backends_ptr) return TC_ACT_OK;

        struct backend_list backends;
        __builtin_memcpy(&backends, backends_ptr, sizeof(backends));
        if (backends.count == 0) return TC_ACT_OK;

        __u32 counter = 0;
        __u32 *counter_ptr = bpf_map_lookup_elem(&lb_counters, &dport);
        if (counter_ptr) counter = *counter_ptr;

        __u32 index = counter % backends.count;

        __u32 selected_ip = 0;
        #pragma unroll
        for (int i = 0; i < MAX_BACKENDS; i++) {
            if (i == index) {
                selected_ip = backends.addrs[i];
            }
        }

        __u32 next_counter = counter + 1;
        bpf_map_update_elem(&lb_counters, &dport, &next_counter, BPF_ANY);

        iph->saddr = selected_ip;
        l4_checksum_recalc(iph, tcph);

        struct conn_info new_conn = {
            .client_ip = iph->daddr,
            .client_port = dport,
            .backend_ip = selected_ip,
            .backend_port = sport
        };
        bpf_map_update_elem(&conntrack_map, &new_conn, &new_conn, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}
