package bpf

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"time"

	"ebpf/metrics"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const BPF_ANY = ebpf.UpdateAny

var (
	Coll                                                              *ebpf.Collection
	AllowedMap, LbMap, LbBackendsMap, LbCountersMap, DevMap, Counters *ebpf.Map
	XdpLink                                                           link.Link
)

type tcpEvent struct {
	PID   uint32
	SAddr uint32
	DAddr uint32
	DPort uint16
	_     uint16
}

func LoadBPF(obj string) {
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		log.Fatal("LoadCollectionSpec:", err)
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("NewCollection:", err)
	}
	Coll = c
	AllowedMap = Coll.Maps["allowed_map"]
	LbMap = Coll.Maps["lb_map"]

	LbBackendsMap = Coll.Maps["lb_backends"]
	LbCountersMap = Coll.Maps["lb_counters"]

	DevMap = Coll.Maps["dev_map"]
	Counters = Coll.Maps["counters"]
}

// xdp connect to NIC
func AttachXDP(iface string) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal(err)
	}
	prog := Coll.Programs["xdp_fw_lb"]

	// OS 환경에 따라 다른 함수를 사용 (조건부 컴파일)
	lnk, err := link.NewXDP(ifaceObj, prog, &link.XDPOptions{})
	if err != nil {
		log.Fatal(err)
	}
	XdpLink = lnk
}

func AttachTC(iface string) {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal(err)
	}
	prog := Coll.Programs["tc_lb_rr"] // TC용 eBPF 프로그램 이름

	lnk, err := link.AttachTCX(link.TCXOptions{
		Program: prog,
		Iface:   ifaceObj.Name,
	})
	if err != nil {
		log.Fatal(err)
	}
	XdpLink = lnk // 변수명은 TC로 변경하는 것이 좋음
}

// Perf 이벤트 리더를 시작해서 BPF 이벤트 데이터를 읽는다
func StartPerfReader() {
	rd, err := perf.NewReader(Coll.Maps["events"], 4096)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				continue
			}
			if record.LostSamples > 0 {
				log.Println("lost samples", record.LostSamples)
				continue
			}

			var ev tcpEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
				continue
			}

			dstIP := net.IPv4(byte(ev.DAddr), byte(ev.DAddr>>8), byte(ev.DAddr>>16), byte(ev.DAddr>>24)).String()
			metrics.TCPCounter.WithLabelValues(dstIP, strconv.Itoa(int(ev.DPort))).Inc()
		}
	}()
}

// Prometheus Metrics update
func StartXDPStats() {
	go func() {
		for {
			var pass, drop uint64
			Counters.Lookup(uint32(0), &pass)
			Counters.Lookup(uint32(1), &drop)
			metrics.XDPPass.Set(float64(pass))
			metrics.XDPDrop.Set(float64(drop))
			time.Sleep(1 * time.Second)
		}
	}()
}
