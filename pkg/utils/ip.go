package utils

import (
	"net"
)

// IsPrivateIP checks if an IP address is private
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}

	for _, r := range privateRanges {
		if bytes4ToUint32(ip.To4()) >= bytes4ToUint32(r.start.To4()) &&
			bytes4ToUint32(ip.To4()) <= bytes4ToUint32(r.end.To4()) {
			return true
		}
	}

	return false
}

// bytes4ToUint32 converts a 4-byte IP to uint32
func bytes4ToUint32(bytes []byte) uint32 {
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// GetLocalIPs returns all local IP addresses
func GetLocalIPs() ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	return ips, nil
}
