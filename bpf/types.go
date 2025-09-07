package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type IpPort struct {
	IP   uint32
	Port uint16
	_    uint16
}

var (
	XdpProgram *ebpf.Program
	Counters   *ebpf.Map
	LbMap      *ebpf.Map
	DevMap     *ebpf.Map
	XdpLink    link.Link
)

const MaxBackends = 16

type TcBackendList struct {
	Addrs [MaxBackends]uint32
	Count uint32
}

var (
	TcProgram *ebpf.Program
	TcLbMap   *ebpf.Map
	TcLink    link.Link
)

var (
	TraceProgram *ebpf.Program
	TraceMap     *ebpf.Map
	TraceLink    link.Link
)
