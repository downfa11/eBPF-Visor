package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const MaxBackends = 8 // MAX_BACKENDS (*.c)

type IpPortKey struct {
	IP   uint32
	Port uint16
}

type BackendList struct {
	Count uint32
	Addrs [MaxBackends]uint32
}

func ParseIPv4(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid ipv4: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func Ipv4ToString(ip uint32) string {
	var builder strings.Builder
	builder.WriteString(strconv.Itoa(int(byte(ip))))
	builder.WriteString(".")
	builder.WriteString(strconv.Itoa(int(byte(ip >> 8))))
	builder.WriteString(".")
	builder.WriteString(strconv.Itoa(int(byte(ip >> 16))))
	builder.WriteString(".")
	builder.WriteString(strconv.Itoa(int(byte(ip >> 24))))
	return builder.String()
}
