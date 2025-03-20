package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseTarget converts a hostname to an IP address
func ParseTarget(target string) (string, error) {
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err == nil {
			return target, nil
		}
	}

	if net.ParseIP(target) != nil {
		return target, nil
	}

	ips, err := net.LookupHost(target)
	if err != nil {
		return "", err
	}

	return ips[0], nil
}

// ParsePortRange parses a port range string
func ParsePortRange(portsStr string) (start, end int, err error) {
	// Handle comma-separated port list
	if strings.Contains(portsStr, ",") {
		ports := []int{}
		parts := strings.Split(portsStr, ",")
		for _, part := range parts {
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return 0, 0, &net.ParseError{Type: "port", Text: part}
			}
			ports = append(ports, port)
		}

		min, max := ports[0], ports[0]
		for _, port := range ports {
			if port < min {
				min = port
			}
			if port > max {
				max = port
			}
		}
		return min, max, nil
	}

	// Handle named port groups
	if strings.HasPrefix(portsStr, "top-") {
		numStr := strings.TrimPrefix(portsStr, "top-")
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, 0, err
		}

		return 1, num, nil
	}

	// Check if it's a range
	if strings.Contains(portsStr, "-") {
		parts := strings.Split(portsStr, "-")
		if len(parts) != 2 {
			return 0, 0, &net.ParseError{Type: "port range", Text: portsStr}
		}

		start, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, err
		}

		end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, err
		}

		return start, end, nil
	}

	// Single port
	port, err := strconv.Atoi(strings.TrimSpace(portsStr))
	if err != nil {
		return 0, 0, err
	}

	return port, port, nil
}

// ParseTargetSpec parses a target specification
func ParseTargetSpec(targetSpec string) ([]string, error) {
	if strings.Contains(targetSpec, "/") {
		return ExpandCIDR(targetSpec)
	}

	if match, _ := regexp.MatchString(`\d+\.\d+\.\d+\.\d+-\d+`, targetSpec); match {
		return ExpandIPRange(targetSpec)
	}

	return []string{targetSpec}, nil
}

// ExpandCIDR expands a CIDR notation to a list of IP addresses
func ExpandCIDR(cidrStr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); IncrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 && !strings.Contains(cidrStr, ":") {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// ExpandIPRange expands an IP range to a list of IP addresses
func ExpandIPRange(ipRange string) ([]string, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}

	baseIP := parts[0]
	endRange, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	ipParts := strings.Split(baseIP, ".")
	if len(ipParts) != 4 {
		return nil, fmt.Errorf("invalid IP address: %s", baseIP)
	}

	startRange, err := strconv.Atoi(ipParts[3])
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("%s.%s.%s.", ipParts[0], ipParts[1], ipParts[2])

	var ips []string
	for i := startRange; i <= endRange; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", prefix, i))
	}

	return ips, nil
}

// IncrementIP increments an IP address by 1
func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GenerateRandomIP generates a random IP address
func GenerateRandomIP() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("%d.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
}

// ReadLinesFromFile reads lines from a file
func ReadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}
