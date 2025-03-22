package scanner

import (
	"net"
	"strings"
)

// canUseICMP checks if ICMP is available
func canUseICMP() bool {
	// In a real implementation, this would check for proper permissions
	return true
}

// detectServiceVersion attempts to detect the service version from banner
func detectServiceVersion(service, banner string) string {
	// Simple version detection based on banner
	// In a real implementation, this would use regex patterns for each service
	if service == "http" || service == "https" {
		if strings.Contains(banner, "Apache") {
			return extractVersion(banner, "Apache/")
		} else if strings.Contains(banner, "nginx") {
			return extractVersion(banner, "nginx/")
		} else if strings.Contains(banner, "IIS") {
			return extractVersion(banner, "IIS/")
		}
	} else if service == "ssh" {
		return strings.TrimSpace(strings.Split(banner, "\n")[0])
	}
	return ""
}

// extractVersion extracts version number from a banner
func extractVersion(banner, prefix string) string {
	if idx := strings.Index(banner, prefix); idx >= 0 {
		start := idx + len(prefix)
		end := start
		for end < len(banner) && (banner[end] != ' ' && banner[end] != '\r' && banner[end] != '\n') {
			end++
		}
		if start < end {
			return banner[start:end]
		}
	}
	return ""
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// expandCIDR expands a CIDR notation to a list of IPs
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast address for IPv4
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// getCommonPorts returns the N most common ports
func getCommonPorts(count int) []int {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
		3306, 3389, 5900, 8080, 20, 79, 88, 106, 119, 123, 137, 138, 161, 162, 389,
		636, 1025, 1433, 1434, 3283, 5060, 5061, 5432, 5800, 6000, 6001, 6667, 8000,
		8081, 8443, 8888, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
	}

	if count >= len(commonPorts) {
		return commonPorts
	}

	return commonPorts[:count]
}

// getServiceName returns a service name for a given port
func getServiceName(port int) string {
	// Common TCP services
	switch port {
	case 20, 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "domain"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1723:
		return "pptp"
	case 2121:
		return "ccproxy-ftp"
	case 3306:
		return "mysql"
	case 3389:
		return "ms-wbt-server"
	case 5432:
		return "postgresql"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	default:
		return "unknown"
	}
}

// getUDPServiceName returns a service name for a UDP port
func getUDPServiceName(port int) string {
	// Add special handling for common UDP services
	switch port {
	case 53:
		return "domain"
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 123:
		return "ntp"
	case 161:
		return "snmp"
	case 500:
		return "isakmp"
	case 514:
		return "syslog"
	case 520:
		return "route"
	case 1900:
		return "upnp"
	default:
		return getServiceName(port) // Fall back to generic service name
	}
}
