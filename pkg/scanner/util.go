package scanner

import (
	"net"
	"regexp"
)

// canUseICMP checks if ICMP is available
func canUseICMP() bool {
	return true
}

// detectServiceVersion attempts to detect the service version from banner
func detectServiceVersion(service, banner string) string {
	if banner == "" {
		return ""
	}

	patterns := map[string]string{
		"SSH":    `SSH-\d+\.\d+-([\w\._-]+)`,
		"HTTP":   `Server: ([^\r\n]+)`,
		"SMTP":   `^220 [^ ]+ ESMTP ([^\r\n]+)`,
		"FTP":    `^220 [^ ]+ FTP [^ ]+ ([^\r\n]+)`,
		"POP3":   `^+OK [^ ]+ ([^\r\n]+)`,
		"IMAP":   `^\* OK [^<]*<([^>]+)>`,
		"MySQL":  `^.\x00\x00\x00\x0a(\d+\.\d+\.\d+)`,
		"Telnet": `^([\w\._-]+) telnetd`,
	}

	if pattern, ok := patterns[service]; ok {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			return matches[1]
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

// getServiceName returns the service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		20:    "FTP-data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP",
		68:    "DHCP",
		69:    "TFTP",
		80:    "HTTP",
		88:    "Kerberos",
		110:   "POP3",
		111:   "RPC",
		119:   "NNTP",
		123:   "NTP",
		135:   "MSRPC",
		137:   "NetBIOS-ns",
		138:   "NetBIOS-dgm",
		139:   "NetBIOS-ssn",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP-trap",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		464:   "Kerberos",
		465:   "SMTPS",
		500:   "IKE",
		514:   "Syslog",
		515:   "LPD",
		520:   "RIP",
		587:   "SMTP",
		636:   "LDAPS",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS",
		1194:  "OpenVPN",
		1433:  "MSSQL",
		1434:  "MSSQL-admin",
		1521:  "Oracle",
		1723:  "PPTP",
		1812:  "RADIUS",
		2049:  "NFS",
		2082:  "cPanel",
		2083:  "cPanel-SSL",
		2086:  "WHM",
		2087:  "WHM-SSL",
		2095:  "Webmail",
		2096:  "Webmail-SSL",
		3306:  "MySQL",
		3389:  "RDP",
		5060:  "SIP",
		5061:  "SIP-TLS",
		5432:  "PostgreSQL",
		5666:  "NRPE",
		5900:  "VNC",
		5901:  "VNC-1",
		5902:  "VNC-2",
		5903:  "VNC-3",
		6379:  "Redis",
		6667:  "IRC",
		8000:  "HTTP-alt",
		8080:  "HTTP-proxy",
		8443:  "HTTPS-alt",
		8888:  "HTTP-alt",
		9100:  "Printer",
		9200:  "Elasticsearch",
		9418:  "Git",
		9999:  "HTTP-alt",
		27017: "MongoDB",
		49152: "Windows-RPC",
		49153: "Windows-RPC",
		49154: "Windows-RPC",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}
