package utils

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Host represents a host with IP and MAC address
type Host struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
}

// DiscoverHosts discovers hosts on the local network
func DiscoverHosts(cidr string) ([]Host, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []Host

	switch runtime.GOOS {
	case "windows":
		hosts, err = arpScanWindows()
	case "darwin":
		hosts, err = arpScanMac()
	default:
		hosts, err = arpScanLinux()
	}

	if err != nil {
		return nil, err
	}

	var filteredHosts []Host
	for _, host := range hosts {
		hostIP := net.ParseIP(host.IP)
		if hostIP != nil && ipnet.Contains(hostIP) {
			filteredHosts = append(filteredHosts, host)
		}
	}

	return filteredHosts, nil
}

// arpScanWindows performs an ARP scan on Windows
func arpScanWindows() ([]Host, error) {
	var hosts []Host

	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "dynamic") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				hosts = append(hosts, Host{
					IP:  fields[0],
					MAC: fields[1],
				})
			}
		}
	}

	return hosts, nil
}

// arpScanMac performs an ARP scan on macOS
func arpScanMac() ([]Host, error) {
	var hosts []Host

	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if len(line) > 0 {
			ipStart := strings.Index(line, "(")
			ipEnd := strings.Index(line, ")")

			if ipStart >= 0 && ipEnd > ipStart {
				ip := line[ipStart+1 : ipEnd]

				macStart := strings.Index(line, "at ") + 3
				macEnd := strings.Index(line[macStart:], " ") + macStart

				if macStart >= 3 && macEnd > macStart {
					mac := line[macStart:macEnd]

					hosts = append(hosts, Host{
						IP:  ip,
						MAC: mac,
					})
				}
			}
		}
	}

	return hosts, nil
}

// arpScanLinux performs an ARP scan on Linux
func arpScanLinux() ([]Host, error) {
	var hosts []Host

	cmd := exec.Command("ip", "neighbor", "show")
	output, err := cmd.Output()

	if err != nil {
		cmd = exec.Command("arp", "-a")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := strings.Trim(fields[1], "()")
				mac := fields[3]

				if mac != "<incomplete>" {
					hosts = append(hosts, Host{
						IP:  ip,
						MAC: mac,
					})
				}
			}
		}
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 5 && fields[2] == "lladdr" {
				hosts = append(hosts, Host{
					IP:  fields[0],
					MAC: fields[4],
				})
			}
		}
	}

	return hosts, nil
}

// TCPPortState checks if a TCP port is open
func TCPPortState(ip string, port int, timeout time.Duration) (string, time.Duration) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return "closed", elapsed
		}
		return "filtered", elapsed
	}

	defer conn.Close()
	return "open", elapsed
}

// UDPPortState checks if a UDP port is open
func UDPPortState(ip string, port int, timeout time.Duration) (string, time.Duration) {
	start := time.Now()
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
	elapsed := time.Since(start)

	if err != nil {
		return "filtered", elapsed
	}

	defer conn.Close()
	return "open|filtered", elapsed
}

// TraceRoute performs a traceroute to the target
func TraceRoute(target string, maxHops int) ([]string, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tracert", "-d", "-h", fmt.Sprintf("%d", maxHops), target)
	default:
		cmd = exec.Command("traceroute", "-n", "-m", fmt.Sprintf("%d", maxHops), target)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var hops []string

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		hops = append(hops, line)
	}

	return hops, nil
}
