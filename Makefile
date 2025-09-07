BPF_SRC=bpf/xdp_fw_lb.c
BPF_OBJ=bpf/xdp_fw_lb.o
GO_SRC=main.go
APP_IMAGE=custom-ebpf:latest

all: bpf go docker

bpf:
	@echo "==> Building eBPF program..."
	clang -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

go:
	@echo "==> Building Go controller..."
	go build -o custom-ebpf $(GO_SRC)

docker:
	@echo "==> Building Docker image..."
	docker build -t $(APP_IMAGE) .

clean:
	rm -f custom-ebpf
	rm -f $(BPF_OBJ)
