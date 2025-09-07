#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>

struct tcp_event { 
    __u32 pid; 
    __u32 saddr; 
    __u32 daddr; 
    __u16 dport; 
    __u16 pad; 
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(void *ctx)
{
    struct tcp_event ev = {};
    ev.pid = bpf_get_current_pid_tgid() >> 32;

    struct sockaddr_in *usrsock_ptr = NULL;
    bpf_probe_read(&usrsock_ptr, sizeof(usrsock_ptr),
                   (void *)((char *)ctx + sizeof(__u64))); 
    if (!usrsock_ptr)
        return 0;

    struct sockaddr_in usrsock;
    bpf_probe_read_user(&usrsock, sizeof(usrsock), usrsock_ptr);

    ev.daddr = usrsock.sin_addr.s_addr;
    ev.dport = usrsock.sin_port;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
