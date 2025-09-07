package api

import (
	"fmt"
	"net/http"
	"strconv"

	"ebpf/bpf"
	"ebpf/utils"
)

// L3/L4 Filtering: allow
func AllowHandler(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	portStr := r.URL.Query().Get("port")
	ip, err := utils.ParseIPv4(ipStr)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	p, _ := strconv.Atoi(portStr)
	key := utils.IpPortKey{IP: ip, Port: uint16(p)}
	val := uint8(1)
	if err := bpf.AllowedMap.Put(&key, &val); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "allowed %s:%d\n", ipStr, p)
}

// L3/L4 Filtering: deny
func DenyHandler(w http.ResponseWriter, r *http.Request) {
	ipStr := r.URL.Query().Get("ip")
	portStr := r.URL.Query().Get("port")
	ip, _ := utils.ParseIPv4(ipStr)
	p, _ := strconv.Atoi(portStr)
	key := utils.IpPortKey{IP: ip, Port: uint16(p)}
	if err := bpf.AllowedMap.Delete(&key); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "removed %s:%d\n", ipStr, p)
}

// L4 Load Balancing: add Rule (NIC redirect based Port)
func AddLBHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	nicStr := r.URL.Query().Get("nic")
	p, _ := strconv.Atoi(portStr)
	n, _ := strconv.Atoi(nicStr)
	key := uint16(p)
	val := uint32(n)
	if err := bpf.LbMap.Put(&key, &val); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "redirect port %d -> NIC %d\n", p, n)
}

// L4 Load Balancing: delete Rule (NIC redirect based Port)
func DelLBHandler(w http.ResponseWriter, r *http.Request) {
	portStr := r.URL.Query().Get("port")
	p, _ := strconv.Atoi(portStr)
	key := uint16(p)
	if err := bpf.LbMap.Delete(&key); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "removed redirect for port %d\n", p)
}

// Round-Robin Load Balancing: add a backend
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

	var backends utils.BackendList
	if err := bpf.LbBackendsMap.Lookup(&port, &backends); err != nil {
		backends.Count = 0
	}

	if backends.Count >= utils.MaxBackends {
		http.Error(w, "backend list is full", 500)
		return
	}

	backends.Addrs[backends.Count] = backendIP
	backends.Count++

	if err := bpf.LbBackendsMap.Update(&port, &backends, bpf.BPF_ANY); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintf(w, "Added backend %s to port %d\n", ipStr, port)
}

// Round-Robin Load Balancing: delete a backend
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

	var backends utils.BackendList
	if err := bpf.LbBackendsMap.Lookup(&port, &backends); err != nil {
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

	if err := bpf.LbBackendsMap.Update(&port, &backends, bpf.BPF_ANY); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprintf(w, "Removed backend %s from port %d\n", ipStr, port)
}
