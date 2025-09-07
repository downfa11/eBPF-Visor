BINARY := custom-ebpf

BPF_SRCS := $(wildcard src/*.c)
BPF_OBJS := $(patsubst src/%.c,bpf/%.o,$(BPF_SRCS))


IMAGE := downfa11/ebpf-visor:latest

.PHONY: all bpf go docker clean

all: bpf go docker

bpf: $(BPF_OBJS)

bpf/%.o: src/%.c
	@mkdir -p bpf
	@echo "Compiling $< to $@..."
	clang -O2 -g -target bpf -c $< -o $@

go:
	@echo "Building Go controller..."
	go build -o $(BINARY) main.go

docker: $(BINARY) $(BPF_OBJS)
	@echo "Building Docker image..."
	docker build -t $(IMAGE) .

clean:
	@echo "Cleaning..."
	rm -f $(BINARY) $(BPF_OBJS)
