package bpf

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func LoadBPF() {
	xdpSpec, err := ebpf.LoadCollectionSpec("bpf/xdp_fw_lb.o")
	if err != nil {
		log.Fatalf("failed to load XDP object: %v", err)
	}
	xdpObjs := struct {
		XdpProg  *ebpf.Program `ebpf:"xdp_fw_lb"`
		Counters *ebpf.Map     `ebpf:"counters"`
		LbMap    *ebpf.Map     `ebpf:"lb_map"`
		DevMap   *ebpf.Map     `ebpf:"dev_map"`
	}{}
	if err := xdpSpec.LoadAndAssign(&xdpObjs, nil); err != nil {
		log.Fatalf("failed to assign XDP objects: %v", err)
	}
	XdpProgram = xdpObjs.XdpProg
	Counters = xdpObjs.Counters
	LbMap = xdpObjs.LbMap
	DevMap = xdpObjs.DevMap

	tcSpec, err := ebpf.LoadCollectionSpec("bpf/traffic_control_lb.o")
	if err != nil {
		log.Fatalf("failed to load TC object: %v", err)
	}
	tcObjs := struct {
		TcProg *ebpf.Program `ebpf:"tclbrr"`
		LbMap  *ebpf.Map     `ebpf:"lb_map"`
	}{}
	if err := tcSpec.LoadAndAssign(&tcObjs, nil); err != nil {
		log.Fatalf("failed to assign TC objects: %v", err)
	}
	TcProgram = tcObjs.TcProg
	TcLbMap = tcObjs.LbMap

	traceSpec, err := ebpf.LoadCollectionSpec("bpf/trace_connect.o")
	if err != nil {
		log.Fatalf("failed to load Trace object: %v", err)
	}
	traceObjs := struct {
		TraceProg *ebpf.Program `ebpf:"trace_connect"`
		TraceMap  *ebpf.Map     `ebpf:"events"`
	}{}
	if err := traceSpec.LoadAndAssign(&traceObjs, nil); err != nil {
		log.Fatalf("failed to assign Trace objects: %v", err)
	}
	TraceProgram = traceObjs.TraceProg
	TraceMap = traceObjs.TraceMap
}

func AttachXDP(iface string) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal("interface not found:", err)
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   XdpProgram,
		Interface: ifaceObj.Index,
	})
	if err != nil {
		log.Fatal("failed to attach XDP:", err)
	}
	XdpLink = lnk
}

func AttachTC(iface string) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal("interface not found:", err)
	}
	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   TcProgram,
		Interface: ifaceObj.Index,
	})
	if err != nil {
		log.Fatal("failed to attach TC:", err)
	}
	TcLink = lnk
}

func AttachTrace() {
	lnk, err := link.Tracepoint("syscalls", "sys_enter_connect", TraceProgram, nil)
	if err != nil {
		log.Fatal("failed to attach Trace:", err)
	}
	TraceLink = lnk
}
