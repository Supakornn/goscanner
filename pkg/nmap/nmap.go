package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
)

// NmapRun represents the root of nmap XML output
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a host in nmap XML output
type NmapHost struct {
	Status NmapStatus `xml:"status"`
	Addr   NmapAddr   `xml:"address"`
	Ports  NmapPorts  `xml:"ports"`
	Os     NmapOs     `xml:"os"`
}

// NmapStatus represents host status
type NmapStatus struct {
	State string `xml:"state,attr"`
}

// NmapAddr represents a host address
type NmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// NmapPorts represents a collection of ports
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// NmapPort represents a port
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents service information
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// NmapOs represents OS detection information
type NmapOs struct {
	OsMatches []NmapOsMatch `xml:"osmatch"`
}

// NmapOsMatch represents an OS match
type NmapOsMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// RunNmap executes nmap with the given arguments
func RunNmap(target string, args []string) (*scanner.HostResult, error) {
	// Check if nmap is available
	if !isNmapAvailable() {
		return nil, fmt.Errorf("nmap is not installed or not in the path")
	}

	// Prepare the command
	allArgs := append([]string{"-oX", "-"}, args...)
	if target != "" && !containsTarget(args) {
		allArgs = append(allArgs, target)
	}

	cmd := exec.Command("nmap", allArgs...)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	fmt.Println("Executing nmap:", cmd.String())
	startTime := time.Now()
	err := cmd.Run()

	// Print any stderr output for debugging
	if stderr.Len() > 0 {
		fmt.Fprintln(os.Stderr, "Nmap stderr output:")
		fmt.Fprintln(os.Stderr, stderr.String())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to run nmap: %v", err)
	}

	// Convert XML output to our format
	hostResult, err := parseNmapXML(stdout.Bytes(), time.Since(startTime))
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %v", err)
	}

	return hostResult, nil
}

// isNmapAvailable checks if nmap is installed and available
func isNmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// containsTarget checks if target is already included in args
func containsTarget(args []string) bool {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return true
		}
	}
	return false
}

// parseNmapXML converts nmap XML output to our HostResult format
func parseNmapXML(xmlData []byte, duration time.Duration) (*scanner.HostResult, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return nil, err
	}

	result := &scanner.HostResult{
		Status: "down", // Default to down
		RTT:    duration,
	}

	// Process only the first host (we expect only one in most cases)
	if len(nmapRun.Hosts) > 0 {
		host := nmapRun.Hosts[0]

		// Use host info
		result.IP = host.Addr.Addr
		result.Status = host.Status.State

		// Parse ports
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				scanResult := scanner.ScanResult{
					Port:     port.PortID,
					Protocol: port.Protocol,
					State:    port.State.State,
					Service:  port.Service.Name,
				}

				// Combine product and version if available
				if port.Service.Product != "" {
					if port.Service.Version != "" {
						scanResult.Version = port.Service.Product + " " + port.Service.Version
					} else {
						scanResult.Version = port.Service.Product
					}
				}

				result.OpenPorts = append(result.OpenPorts, scanResult)
			}
		}

		// Parse OS detection
		if len(host.Os.OsMatches) > 0 {
			result.OS = host.Os.OsMatches[0].Name
			accuracy, _ := strconv.Atoi(host.Os.OsMatches[0].Accuracy)
			result.OSAccuracy = accuracy
		}

		// We found a host, mark it as up
		if len(result.OpenPorts) > 0 {
			result.Status = "up"
		}
	}

	return result, nil
}
