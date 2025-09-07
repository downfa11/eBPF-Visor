package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	TCPCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "tcp_connect_total", Help: "TCP connect events"},
		[]string{"dst_ip", "dst_port"},
	)
	XDPPass = prometheus.NewGauge(prometheus.GaugeOpts{Name: "xdp_pass_total", Help: "XDP pass packets"})
	XDPDrop = prometheus.NewGauge(prometheus.GaugeOpts{Name: "xdp_drop_total", Help: "XDP drop packets"})
)

func init() { prometheus.MustRegister(TCPCounter, XDPPass, XDPDrop) }
