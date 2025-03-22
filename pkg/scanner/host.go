package scanner

import (
	"net"
	"time"
)

// ScanHost scans a host and returns detailed information
func (s *Scanner) ScanHost() *HostResult {
	startTime := time.Now()

	// Initialize the result
	result := &HostResult{
		IP:     s.target,
		Status: "up",
	}

	// Perform hostname lookup
	names, err := net.LookupAddr(s.target)
	if err == nil && len(names) > 0 {
		result.Hostname = names
	} else {
		result.Hostname = []string{}
	}

	// Measure latency with a simple ping if possible
	if canUseICMP() {
		// In a real implementation, we would use ping here
		// For now, just record the time since starting
		result.RTT = time.Since(startTime)
	}

	// Scan the most common ports to determine if host is up
	commonPorts := getCommonPorts(20) // Get 20 most common ports

	// Track open, filtered, and closed ports
	var openPorts, filteredPorts, closedPorts []ScanResult

	// Scan common ports first
	for _, port := range commonPorts {
		scanResult := s.ScanPort("tcp", port)

		switch scanResult.State {
		case "open":
			openPorts = append(openPorts, scanResult)
		case "filtered":
			filteredPorts = append(filteredPorts, scanResult)
		case "closed":
			closedPorts = append(closedPorts, scanResult)
		}
	}

	// If we found no open ports on common ones and host discovery is enabled,
	// try to verify host is up with additional methods
	if len(openPorts) == 0 && s.hostDiscovery {
		// Check if we can actually reach the host
		if canUseICMP() {
			// Would use ICMP ping here
			// For now, assume host is up if we got at least one filtered port
			if len(filteredPorts) == 0 && len(closedPorts) == 0 {
				result.Status = "down"
				return result
			}
		}
	}

	// If we're doing a full port scan, add all the ports we've been asked to scan
	if len(s.Ports) > 0 {
		for _, port := range s.Ports {
			// Skip ports we already checked
			alreadyScanned := false
			for _, p := range commonPorts {
				if p == port {
					alreadyScanned = true
					break
				}
			}

			if !alreadyScanned {
				scanResult := s.ScanPort("tcp", port)

				switch scanResult.State {
				case "open":
					openPorts = append(openPorts, scanResult)
				case "filtered":
					filteredPorts = append(filteredPorts, scanResult)
				case "closed":
					closedPorts = append(closedPorts, scanResult)
				}
			}
		}
	}

	// Store results in the host result
	result.OpenPorts = openPorts
	result.FilteredPorts = filteredPorts
	result.ClosedPorts = closedPorts

	// Perform OS detection if requested and we found at least one open port
	if s.osDetection && len(openPorts) > 0 {
		os, accuracy := s.detectOS()
		result.OS = os
		result.OSAccuracy = accuracy
	}

	return result
}
