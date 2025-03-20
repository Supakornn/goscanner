package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
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
