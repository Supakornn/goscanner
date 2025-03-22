// Package nmap provides functions for integrating with the Nmap security scanner
package nmap

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
)

// represents the root of nmap XML output
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// represents a host in nmap XML output
type NmapHost struct {
	Status NmapStatus `xml:"status"`
	Addr   NmapAddr   `xml:"address"`
	Ports  NmapPorts  `xml:"ports"`
	Os     NmapOs     `xml:"os"`
}

// represents host status
type NmapStatus struct {
	State string `xml:"state,attr"`
}

// represents a host address
type NmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// represents a collection of ports
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// represents a port
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// represents service information
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// represents OS detection information
type NmapOs struct {
	OsMatches []NmapOsMatch `xml:"osmatch"`
}

// represents an OS match
type NmapOsMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// runs nmap
func RunNmap(target string, args []string) (*scanner.HostResult, error) {
	// validate target
	if target == "" && !containsTarget(args) {
		return nil, fmt.Errorf("target is required for nmap scan")
	}

	// check if nmap is installed
	_, err := exec.LookPath("nmap")
	if err != nil {
		return nil, fmt.Errorf("nmap is not installed or not in the PATH")
	}

	// start with basic arguments
	finalArgs := []string{"-oX", "-"} // output XML to stdout

	// add any user-specified arguments first
	finalArgs = append(finalArgs, args...)

	// always add the target at the end if it's not empty
	if target != "" && !containsTarget(args) {
		finalArgs = append(finalArgs, target)
	}

	// print command for user reference
	fmt.Println("\nRunning nmap:", "nmap", strings.Join(finalArgs, " "))
	fmt.Println("----------------------------------------------------")

	// configure the command
	startTime := time.Now()
	cmd := exec.Command("nmap", finalArgs...)

	// capture stdout for XML parsing
	output, err := cmd.Output()
	if err != nil {
		// handle error more gracefully, still print stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Println(string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("error executing nmap: %v", err)
	}

	// calculate duration
	duration := time.Since(startTime)

	// parse the XML output
	result, err := parseNmapXML(output, duration)
	if err != nil {
		return nil, fmt.Errorf("error parsing nmap output: %v", err)
	}

	return result, nil
}

// helper function to check if a target is already in the args
func containsTarget(args []string) bool {
	// common nmap args that take additional parameters (not targets)
	nonTargetArgs := map[string]bool{
		"-p": true, "--ports": true,
		"-iL": true, "--input-filename": true,
		"-oA": true, "-oN": true, "-oX": true, "-oG": true, "-oS": true,
		"--script": true, "--script-args": true,
		"-D": true, "--proxies": true,
		"-e": true, "--source-port": true,
	}

	for i, arg := range args {
		// skip this arg if it's a flag that takes a parameter
		if nonTargetArgs[arg] && i < len(args)-1 {
			i++ // skip the next item too as it's the parameter
			continue
		}

		// if the arg doesn't start with - and isn't a parameter for a previous flag
		if !strings.HasPrefix(arg, "-") {
			prev := ""
			if i > 0 {
				prev = args[i-1]
			}
			if !nonTargetArgs[prev] {
				return true
			}
		}
	}

	return false
}

// converts nmap XML output to our HostResult format
func parseNmapXML(xmlData []byte, duration time.Duration) (*scanner.HostResult, error) {
	var nmapRun NmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return nil, err
	}

	result := &scanner.HostResult{
		Status: "down", // Default to down
		RTT:    duration,
	}

	// process only the first host (we expect only one in most cases)
	if len(nmapRun.Hosts) > 0 {
		host := nmapRun.Hosts[0]

		// use host info
		result.IP = host.Addr.Addr
		result.Status = host.Status.State

		// parse ports
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				scanResult := scanner.ScanResult{
					Port:     port.PortID,
					Protocol: port.Protocol,
					State:    port.State.State,
					Service:  port.Service.Name,
				}

				// combine product and version if available
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

		// parse OS detection
		if len(host.Os.OsMatches) > 0 {
			result.OS = host.Os.OsMatches[0].Name
			accuracy, _ := strconv.Atoi(host.Os.OsMatches[0].Accuracy)
			result.OSAccuracy = accuracy
		}

		// found a host, mark it as up
		if len(result.OpenPorts) > 0 {
			result.Status = "up"
		}
	}

	return result, nil
}
