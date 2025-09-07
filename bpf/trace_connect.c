#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>

struct tcp_event { __u32 pid; __u32 saddr; __u32 daddr; __u16 dport; __u16 pad; };

struct { __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries,128); __type(key,__u32); __type(value,__u32); } events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter* ctx){
    struct tcp_event ev={};
    ev.pid=bpf_get_current_pid_tgid()>>32;
    struct sockaddr_in *usrsock=(struct sockaddr_in*)ctx->args[1];
    if(!usrsock) return 0;
    bpf_probe_read_user(&ev.daddr,sizeof(ev.daddr),&usrsock->sin_addr.s_addr);
    bpf_probe_read_user(&ev.dport,sizeof(ev.dport),&usrsock->sin_port);
    bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&ev,sizeof(ev));
    return 0;
}
