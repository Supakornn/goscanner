package scanner

import (
	"net"
	"time"
)

// scans a host and returns detailed information
func (s *Scanner) ScanHost() *HostResult {
	startTime := time.Now()

	// initialize the result
	result := &HostResult{
		IP:     s.target,
		Status: "up",
	}

	// hostname lookup
	names, err := net.LookupAddr(s.target)
	if err == nil && len(names) > 0 {
		result.Hostname = names
	} else {
		result.Hostname = []string{}
	}

	// measure latency with a simple ping if possible
	if canUseICMP() {
		// in a real implementation, we would use ping here
		// for now, just record the time since starting
		result.RTT = time.Since(startTime)
	}

	// scan the most common ports to determine if host is up
	commonPorts := getCommonPorts(20) // get 20 most common ports

	// track open, filtered, and closed ports
	var openPorts, filteredPorts, closedPorts []ScanResult

	// scan common ports first
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

	// check if we can actually reach the host
	if len(openPorts) == 0 && s.hostDiscovery {
		if canUseICMP() {
			// if we got no open ports and no filtered or closed ports, assume host is down
			if len(filteredPorts) == 0 && len(closedPorts) == 0 {
				result.Status = "down"
				return result
			}
		}
	}

	// if we are doing a full port scan, add all the ports we've been asked to scan
	if len(s.Ports) > 0 {
		for _, port := range s.Ports {
			// skip ports we already checked
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

	// store results in the host result
	result.OpenPorts = openPorts
	result.FilteredPorts = filteredPorts
	result.ClosedPorts = closedPorts

	// perform OS detection if requested and we found at least one open port
	if s.osDetection && len(openPorts) > 0 {
		os, accuracy := s.detectOS()
		result.OS = os
		result.OSAccuracy = accuracy
	}

	return result
}
