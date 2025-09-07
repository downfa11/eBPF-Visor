# Part 1:
FROM ubuntu:20.04 AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    bpftool \
    linux-headers-$(uname -r)

WORKDIR /src

COPY bpf/xdp_fw_lb.c bpf/trace_connect.c ./bpf/

RUN clang -g -O2 -target bpf -I/usr/include/bpf -c bpf/xdp_fw_lb.c -o bpf/xdp_fw_lb.o
RUN clang -g -O2 -target bpf -I/usr/include/bpf -c bpf/trace_connect.c -o bpf/trace_connect.o

#----------------------------------------------------------------------------------------------------

# Part 2:
FROM golang:1.25-alpine AS go-builder


RUN apk add --no-cache gcc libc-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY api/ ./api/
COPY metrics/ ./metrics/
COPY utils/ ./utils/
# *.c noooo 
COPY bpf/bpf.go ./bpf/

RUN CGO_ENABLED=1 GOOS=linux go build -o ebpf-app main.go

#----------------------------------------------------------------------------------------------------

# Part 3:
FROM alpine:latest

WORKDIR /

RUN apk add --no-cache libmnl

COPY --from=go-builder /app/ebpf-app /
COPY --from=builder /src/bpf/xdp_fw_lb.o /bpf/xdp_fw_lb.o
COPY --from=builder /src/bpf/trace_connect.o /bpf/trace_connect.o

CMD ["/ebpf-app"]