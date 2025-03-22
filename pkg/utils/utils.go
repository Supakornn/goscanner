package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// output the scan results to a file in the specified format
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

// get the hostname for an IP address
func GetReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// get the vendor of a MAC address
func GetMACVendor(mac string) string {
	// In a real implementation, would query an OUI database
	return "Unknown Vendor"
}

// IMPORTANT: parse the specific ports into a slice of integers
// it handles ports in any order and returns a sorted list of unique port numbers
// examples: "80,443,8080" -> [80, 443, 8080]
//
//	"22-25,80,443" -> [22, 23, 24, 25, 80, 443]
func ParseSpecificPorts(portsStr string) ([]int, error) {
	if portsStr == "" {
		return []int{}, nil
	}

	var uniquePorts = make(map[int]bool)
	var result []int

	// split by comma
	portsList := strings.Split(portsStr, ",")

	for _, portItem := range portsList {
		portItem = strings.TrimSpace(portItem)

		// check if it's a range (contains hyphen)
		if strings.Contains(portItem, "-") {
			rangeParts := strings.Split(portItem, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", portItem)
			}

			// parse the start and end of the range
			startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range: %s", rangeParts[0])
			}

			endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range: %s", rangeParts[1])
			}

			// validate the port range
			if startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 {
				return nil, fmt.Errorf("ports must be between 1 and 65535")
			}

			if startPort > endPort {
				return nil, fmt.Errorf("start port must be less than or equal to end port")
			}

			// add all ports in the range
			for port := startPort; port <= endPort; port++ {
				uniquePorts[port] = true
			}
		} else {
			// single port
			port, err := strconv.Atoi(portItem)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", portItem)
			}

			// validate the port
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be between 1 and 65535")
			}

			uniquePorts[port] = true
		}
	}

	// convert the map to a slice
	for port := range uniquePorts {
		result = append(result, port)
	}

	// sort the result
	sort.Ints(result)

	return result, nil
}

// parse the port range string
// returns the start and end port as integers
// examples: "1-1000" -> 1, 1000
//
//	"80-80" -> 80, 80 (single port)
func ParsePortRangeString(rangeStr string) (int, int, error) {
	rangeStr = strings.TrimSpace(rangeStr)

	// split by hyphen
	rangeParts := strings.Split(rangeStr, "-")
	if len(rangeParts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format (should be 'start-end')")
	}

	// parse the start port
	startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %s", rangeParts[0])
	}

	// parse the end port
	endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %s", rangeParts[1])
	}

	// validate the port range
	if startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 {
		return 0, 0, fmt.Errorf("ports must be between 1 and 65535")
	}

	if startPort > endPort {
		return 0, 0, fmt.Errorf("start port must be less than or equal to end port")
	}

	return startPort, endPort, nil
}

// generate a slice of integers representing a range of ports
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

// check if it's a valid IPv4 address
func IsIPv4(ip string) bool {
	ipv4Regex := regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$`)
	return ipv4Regex.MatchString(ip)
}

// check if it's a valid IPv6 address
func IsIPv6(ip string) bool {
	ipv6Regex := regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`)
	return ipv6Regex.MatchString(ip)
}

// check if it's a valid CIDR notation
func IsCIDR(cidr string) bool {
	// IPv4 CIDR regex
	ipv4CIDRRegex := regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/([0-9]|[12][0-9]|3[0-2])$`)

	// IPv6 CIDR regex (simplified)
	ipv6CIDRRegex := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$`)

	return ipv4CIDRRegex.MatchString(cidr) || ipv6CIDRRegex.MatchString(cidr)
}

// check if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// read a file and return its lines as a slice of strings
func ReadLines(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var result []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result, nil
}
