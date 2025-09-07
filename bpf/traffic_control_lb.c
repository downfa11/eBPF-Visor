#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h> // TC 훅을 위해 필요

char LICENSE[] SEC("license") = "GPL";

#define MAX_BACKENDS 8

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

// lb_backends: service IP list Map. {Port, BackendList}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct backend_list);
} lb_backends SEC(".maps");

// lb_counters: round-robin counter Map. {Port, Counter}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u32);
} lb_counters SEC(".maps");

// conntrack_map: 연결 상태 추적 Map. {Client IP/Port, Connection Info}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct conn_info);
    __type(value, struct conn_info);
} conntrack_map SEC(".maps");

// IP/TCP checksum calculate
static inline void l4_checksum_recalc(struct iphdr *iph, struct tcphdr *tcph, __u32 old_saddr, __u32 new_saddr, __u32 old_daddr, __u32 new_daddr) {
    __u32 diff = ~((old_saddr & 0xffff) + (old_saddr >> 16) + (old_daddr & 0xffff) + (old_daddr >> 16));
    diff = ~((new_saddr & 0xffff) + (new_saddr >> 16) + (new_daddr & 0xffff) + (new_daddr >> 16)) + diff;
    tcph->check = bpf_csum_fold_helper(bpf_csum_diff(0, 0, &diff, sizeof(diff), tcph->check));
    iph->check = 0;
    iph->check = bpf_csum_fold_helper(bpf_csum_diff(0, 0, &diff, sizeof(diff), 0));
}

SEC("tc")
int tc_lb_rr(struct __sk_buff *skb) {
    void *data_end = (void*)(long)skb->data_end;
    void *data = (void*)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcph = (void*)iph + iph->ihl * 4;
    if ((void*)(tcph + 1) > data_end) return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcph->dest);
    __u16 sport = bpf_ntohs(tcph->source);

    // 1. 기존 연결 상태 추적 (SNAT)
    struct conn_info conn_key = { .client_ip = iph->daddr, .client_port = dport, .backend_ip = iph->saddr, .backend_port = sport };
    struct conn_info *conn_val = bpf_map_lookup_elem(&conntrack_map, &conn_key);

    if (conn_val) {
        // 기존 연결 패킷이면, 원래 클라이언트로 역변환
        l4_checksum_recalc(iph, tcph, iph->daddr, conn_val->client_ip, iph->saddr, conn_val->backend_ip);
        iph->daddr = conn_val->client_ip;
        iph->saddr = conn_val->backend_ip;
        tcph->dest = bpf_htons(conn_val->client_port);
        tcph->source = bpf_htons(conn_val->backend_port);
        return TC_ACT_OK;
    }

    // 2. 새로운 연결 (SYN) 처리 및 라운드 로빈
    if ((tcph->syn == 1) && (tcph->ack == 0)) {
        struct backend_list *backends = bpf_map_lookup_elem(&lb_backends, &dport);
        if (backends && backends->count > 0) {
            __u32 *counter_ptr = bpf_map_lookup_elem(&lb_counters, &dport);
            if (!counter_ptr) {
                __u32 initial_counter = 0;
                bpf_map_update_elem(&lb_counters, &dport, &initial_counter, BPF_NOEXIST);
                counter_ptr = bpf_map_lookup_elem(&lb_counters, &dport);
                if (!counter_ptr) return TC_ACT_OK;
            }

            __u32 index = *counter_ptr % backends->count;
            __u32 next_counter = *counter_ptr + 1;
            bpf_map_update_elem(&lb_counters, &dport, &next_counter, BPF_ANY);

            __u32 selected_backend_ip = backends->addrs[index];
            
            // 3. 패킷 헤더 수정 (DNAT, SNAT)
            // L4 체크섬 재계산
            l4_checksum_recalc(iph, tcph, iph->saddr, selected_backend_ip, iph->daddr, iph->daddr);
            bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &selected_backend_ip, sizeof(__u32), 0); // SNAT
            bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &selected_backend_ip, sizeof(__u32), 0); // DNAT
            // bpf_skb_store_bytes 함수 사용 시 iph, tcph 포인터는 무효화되므로 재할당 필요
            
            // 4. Conntrack 맵 업데이트
            struct conn_info new_conn = { .client_ip = iph->saddr, .client_port = sport, .backend_ip = selected_backend_ip, .backend_port = dport };
            bpf_map_update_elem(&conntrack_map, &new_conn, &new_conn, BPF_NOEXIST);
            
            return TC_ACT_OK;
        }
    }
    
    return TC_ACT_OK;
}