package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"time"
)

// ScanHost performs a comprehensive scan of a host
func (s *Scanner) ScanHost() *HostResult {
	host := &HostResult{
		IP: s.target,
	}

	if s.hostDiscovery && !s.skipHostDiscovery {
		isUp, rtt := s.pingHost()
		if !isUp {
			host.Status = "down"
			return host
		}
		host.Status = "up"
		host.RTT = rtt
	} else {
		host.Status = "unknown"
	}

	hostnames, _ := net.LookupAddr(s.target)
	host.Hostname = hostnames

	if s.traceRoute {
		host.HopCount = s.performTraceroute()
	}

	commonPorts := getCommonPorts(100)
	openPorts := s.ScanRange("tcp", commonPorts[0], commonPorts[len(commonPorts)-1])
	host.OpenPorts = openPorts

	if s.osDetection && len(openPorts) > 0 {
		host.OS, host.OSAccuracy = s.detectOS()
	}

	if len(openPorts) > 0 {
		host.Status = "up"
	}

	return host
}

// pingHost checks if a host is up using multiple methods
func (s *Scanner) pingHost() (bool, time.Duration) {
	// Try ICMP first if available
	if canUseICMP() {
		alive, rtt := s.icmpPing()
		if alive {
			return true, rtt
		}
	}

	// Try TCP ping to common ports
	commonPorts := []int{80, 443, 22, 25, 3389}
	for _, port := range commonPorts {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.target, fmt.Sprintf("%d", port)), s.timeout/2)
		if err == nil {
			conn.Close()
			return true, time.Since(start)
		}
	}

	return false, 0
}

// icmpPing performs an ICMP echo request
func (s *Scanner) icmpPing() (bool, time.Duration) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", s.timeout/time.Millisecond), s.target)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", s.timeout/time.Second), s.target)
	}

	startTime := time.Now()
	err := cmd.Run()
	elapsed := time.Since(startTime)

	return err == nil, elapsed
}

// performTraceroute determines the number of hops to the target
func (s *Scanner) performTraceroute() int {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tracert", "-d", "-h", "10", s.target)
	default:
		cmd = exec.Command("traceroute", "-n", "-m", "10", s.target)
	}

	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	ipPattern := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	matches := ipPattern.FindAllString(string(output), -1)

	return len(matches)
}
