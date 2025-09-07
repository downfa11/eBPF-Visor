package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"

	"ebpf/api"
	"ebpf/bpf"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	iface := os.Getenv("DEV")
	if iface == "" {
		iface = "eth0"
	}

	// BPF
	bpf.LoadBPF("bpf/xdp_fw_lb.o")
	bpf.AttachXDP(iface)
	defer bpf.XdpLink.Close()
	defer bpf.Coll.Close()

	// metrics
	bpf.StartPerfReader()
	bpf.StartXDPStats()

	// HTTP handler
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/allow", api.AllowHandler)
	http.HandleFunc("/deny", api.DenyHandler)
	http.HandleFunc("/add", api.AddLBHandler)
	http.HandleFunc("/del", api.DelLBHandler)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	log.Println("controller started at :8080")
	http.ListenAndServe(":8080", nil)
	<-stop
}
