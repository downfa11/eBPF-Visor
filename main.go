package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"ebpf/api"
	"ebpf/bpf"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	iface := os.Getenv("NETWORK_INTERFACE")
	if iface == "" {
		iface = "eth0"
	}

	bpf.LoadBPF()
	bpf.AttachXDP(iface)
	bpf.AttachTC(iface)

	defer bpf.XdpLink.Close()
	defer bpf.TcLink.Close()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/allow", api.AllowHandler)
	http.HandleFunc("/deny", api.DenyHandler)
	http.HandleFunc("/add", api.AddLBHandler)
	http.HandleFunc("/del", api.DelLBHandler)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("controller started at :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on port 8080: %v\n", err)
		}
	}()

	<-stop
	log.Println("Shutting down...")
}
