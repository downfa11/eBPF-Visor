# Custom eBPF Platform

A lightweight eBPF-based platform that provides network control and service topology visualization.

일단 eBPF Verifier가 뭘 자꾸 막아대는데 빡친다. 

컴파일 시점에서 모르니까 매번 빌드하는데 응몸쓰면머리안써도돼 나시간많아

최신 오류

```
2025/09/07 09:35:08 failed to attach TC:tcx not supported (requires >= v6.6)
```

- trace_connect(Observability): 어떤 Pod가 어느 IP로 연결(connect) 시도할때마다 이벤트 생성
- xdp_fw_lb(L4): XDP Hook으로 firewall & NIC redirect LB
- traffic_control_lb(L4): TC Hook으로 Round-Robin LB와 패킷 변환 (SNAT/DNAT)

# Quick Started

need: Helm, Prometeus Stack


```
kubectl apply -f ebpf-dashboard.yaml
kubectl apply -f ebpf-agent.yaml
```


