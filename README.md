# Custom eBPF Platform

A lightweight eBPF-based platform that provides network control and service topology visualization.

<br>

일단 eBPF Verifier가 뭘 자꾸 막아대는데 빡친다. WSL 커널 버전 후달려서 TCX도 못써

```
2025/09/07 09:35:08 failed to attach TC:tcx not supported (requires >= v6.6)
```

### Feature

- trace_connect(Observability): 어떤 Pod가 어느 IP로 연결(connect) 시도할때마다 이벤트 생성
- xdp_fw_lb(L4): XDP Hook으로 firewall & NIC redirect LB
- traffic_control_lb(L4): TC Hook으로 Round-Robin LB와 패킷 변환 (SNAT/DNAT)

<br>

### Quick Started

need: Helm, Prometeus Stack


```
kubectl apply -f ebpf-dashboard.yaml
kubectl apply -f ebpf-agent.yaml
```


