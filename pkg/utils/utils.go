package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// OutputToFile writes scan results to a file in the specified format
func OutputToFile(filename string, format string, data any) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	case "xml":
		encoder := xml.NewEncoder(file)
		encoder.Indent("", "  ")
		return encoder.Encode(data)
	default: // text
		fmt.Fprintf(file, "%v", data)
		return nil
	}
}

// GetReverseDNS gets the hostname for an IP address
func GetReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// GetMACVendor returns the vendor of a MAC address
func GetMACVendor(mac string) string {
	// In a real implementation, would query an OUI database
	return "Unknown Vendor"
}

// ParseSpecificPorts parses a comma-separated list of port numbers
func ParseSpecificPorts(portList string) ([]int, error) {
	if portList == "" {
		return nil, fmt.Errorf("empty port list")
	}

	// Split by commas and initialize result slice with appropriate capacity
	parts := strings.Split(portList, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]bool, len(parts)) // Track unique ports

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Check if this is a range like "80-100"
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			// Parse start and end ports
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range: %s", rangeParts[1])
			}

			// Validate port range
			if start < 1 || start > 65535 || end < 1 || end > 65535 {
				return nil, fmt.Errorf("port range %d-%d contains values outside valid range (1-65535)", start, end)
			}

			// Ensure start <= end
			if start > end {
				start, end = end, start
			}

			// Add each port in the range
			for port := start; port <= end; port++ {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			}
			continue
		}

		// Handle single port
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", part)
		}

		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}

		// Only add unique ports
		if !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}

	return ports, nil
}

// GeneratePortRange generates a slice of integers representing a range of ports
func GeneratePortRange(startPort, endPort int) []int {
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	count := endPort - startPort + 1
	ports := make([]int, count)

	for i := 0; i < count; i++ {
		ports[i] = startPort + i
	}

	return ports
}
