package api

import (
	"fmt"
	"net/http"
	"strconv"
	"unsafe"

	"ebpf/bpf"
	"ebpf/utils"

	"github.com/cilium/ebpf"
)

// --- L3/L4 Filtering: allow ---
func AllowHandler(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	portStr := r.URL.Query().Get("port")

	ip, err := utils.ParseIPv4(ipStr)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	p, _ := strconv.Atoi(portStr)

	key := bpf.IpPort{IP: ip, Port: uint16(p)}
	val := uint64(1) // Counters가 u64라서;;;;

	if err := bpf.LbMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&val), ebpf.UpdateAny); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "allowed %s:%d\n", ipStr, p)
}

// --- L3/L4 Filtering: deny ---
func DenyHandler(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	portStr := r.URL.Query().Get("port")

	ip, _ := utils.ParseIPv4(ipStr)
	p, _ := strconv.Atoi(portStr)

	key := bpf.IpPort{IP: ip, Port: uint16(p)}
	if err := bpf.LbMap.Delete(unsafe.Pointer(&key)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "removed %s:%d\n", ipStr, p)
}

// --- L4 Load Balancing ---
func AddLBHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	nicStr := r.URL.Query().Get("nic")

	p, _ := strconv.Atoi(portStr)
	n, _ := strconv.Atoi(nicStr)

	key := uint16(p)
	val := uint32(n)

	if err := bpf.TcLbMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&val), ebpf.UpdateAny); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "redirect port %d -> NIC %d\n", p, n)
}

func DelLBHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	p, _ := strconv.Atoi(portStr)
	key := uint16(p)

	if err := bpf.TcLbMap.Delete(unsafe.Pointer(&key)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "removed redirect for port %d\n", p)
}

// --- Round-Robin LB: add backend ---
func AddBackendHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	ipStr := r.URL.Query().Get("ip")

	p, _ := strconv.Atoi(portStr)
	ip, err := utils.ParseIPv4(ipStr)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	port := uint16(p)
	backendIP := ip

	var backends bpf.TcBackendList
	err = bpf.TcLbMap.Lookup(unsafe.Pointer(&port), unsafe.Pointer(&backends))
	if err != nil {
		backends.Count = 0
	}

	if backends.Count >= bpf.MaxBackends {
		http.Error(w, "backend list is full", 500)
		return
	}

	backends.Addrs[backends.Count] = backendIP
	backends.Count++

	if err := bpf.TcLbMap.Update(unsafe.Pointer(&port), unsafe.Pointer(&backends), ebpf.UpdateAny); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintf(w, "Added backend %s to port %d\n", ipStr, port)
}

// --- Round-Robin LB: delete backend ---
func DeleteBackendHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	ipStr := r.URL.Query().Get("ip")

	p, _ := strconv.Atoi(portStr)
	ip, err := utils.ParseIPv4(ipStr)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	port := uint16(p)
	backendIP := ip

	var backends bpf.TcBackendList
	if err := bpf.TcLbMap.Lookup(unsafe.Pointer(&port), unsafe.Pointer(&backends)); err != nil {
		http.Error(w, "port not found", 404)
		return
	}

	found := false
	for i := 0; i < int(backends.Count); i++ {
		if backends.Addrs[i] == backendIP {
			copy(backends.Addrs[i:], backends.Addrs[i+1:])
			backends.Count--
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "backend not found for this port", 404)
		return
	}

	if err := bpf.TcLbMap.Update(unsafe.Pointer(&port), unsafe.Pointer(&backends), ebpf.UpdateAny); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintf(w, "Removed backend %s from port %d\n", ipStr, port)
}
