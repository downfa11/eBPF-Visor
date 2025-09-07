# Custom eBPF Platform

A lightweight eBPF-based platform that provides network control and service topology visualization.

eBPF is used to automatically inspect application executables and the OS networking layer

- creates a visual network map of the services running in your cluster.

As with most eBPF tools, all data capture and instrumentation occurs without any modifications to your application code or configuration.

eBPF 플랫폼 만들어봤어요. 
link.NewXDP와 perf.NewReader는 Windows에서 지원되지 않는 API입니다.

```
bpf/
 ├─ xdp_fw_lb.c      // IP+Port Filter + REDIRECT
 └─ trace_connect.c  // TCP connect tracepoint
```


1. 컨트롤러 실행: `sudo DEV=eth0 go run main.go`

2. IP+Port 허용: `curl "http://localhost:8080/allow?ip=192.168.0.10&port=80"`

3. 로드밸런싱 추가: `curl "http://localhost:8080/add?port=8080&nic=2"`

4. Prometheus scrape: Grafana에서 다음 메트릭 시각화

    - `xdp_pass_total`, `xdp_drop_total` → 패킷 통계

    - `tcp_connect_total{dst_ip,dst_port}` → TCP connect 이벤트


# Quick Started

호스트 네트워크 혹은 `--privileged` 권한이 필요

- `make all` -> eBPF & Go Controller Build

1. Grafana에서 Import → Upload JSON file

2. Datasource는 Prometheus 선택
    - URL: http://<Controller IP>:2112/metrics

3. Dashboard 로드 → 실시간 패킷/연결 이벤트 시각화




# Linux Kernel Header install

```
sudo apt-get install linux-headers-$(uname -r)
```


# Quick Started (Docker)

```
docker compose up --build
```

Grafana account - admin, admin