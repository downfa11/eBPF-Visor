FROM ubuntu:24.04

RUN apt update && \
    apt install -y libmnl-dev clang llvm gcc make iproute2 iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY custom-ebpf .
COPY bpf/*.o ./bpf/
RUN chmod +x custom-ebpf

CMD ["./custom-ebpf"]
