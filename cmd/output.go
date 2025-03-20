package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
	"github.com/supakornn/goscanner/pkg/utils"
)

// printPortScanResults prints scan results for a host
func printPortScanResults(hostname, ip string, results []scanner.ScanResult) {
	fmt.Printf("\nScan results for %s (%s):\n", hostname, ip)
	fmt.Printf("%d ports open\n\n", len(results))

	if len(results) > 0 {
		fmt.Println("PORT\tSTATE\tSERVICE\tVERSION")
		for _, result := range results {
			version := result.Version
			if version == "" {
				version = "-"
			}

			fmt.Printf("%d/%s\t%s\t%s\t%s\n",
				result.Port,
				strings.ToLower(result.Protocol),
				result.State,
				result.Service,
				version)
		}

		// Generate report if needed
		if outputFile != "" {
			saveResults(hostname, ip, results)
		}
	} else {
		fmt.Println("No open ports found.")
	}
}

// printDetailedHostResult prints detailed host scan results
func printDetailedHostResult(host *scanner.HostResult) {
	fmt.Printf("\nHost: %s", host.IP)

	if len(host.Hostname) > 0 {
		fmt.Printf(" (%s)", host.Hostname[0])
	}

	fmt.Printf(" Status: %s\n", host.Status)

	if host.Status == "up" {
		if host.OS != "" {
			fmt.Printf("OS: %s (confidence: %d%%)\n", host.OS, host.OSAccuracy)
		}

		if host.MAC != "" {
			fmt.Printf("MAC Address: %s (%s)\n", host.MAC, host.Vendor)
		}

		if host.RTT > 0 {
			fmt.Printf("Latency: %.2fms\n", float64(host.RTT)/float64(time.Millisecond))
		}

		if len(host.OpenPorts) > 0 {
			fmt.Printf("\nPORT\tSTATE\tSERVICE\tVERSION\n")
			for _, result := range host.OpenPorts {
				version := result.Version
				if version == "" {
					version = "-"
				}

				fmt.Printf("%d/%s\t%s\t%s\t%s\n",
					result.Port,
					strings.ToLower(result.Protocol),
					result.State,
					result.Service,
					version)
			}

			// Save to file if needed
			if outputFile != "" {
				saveHostResult(host)
			}
		} else {
			fmt.Println("\nNo open ports found.")
		}
	}
}

// saveResults saves scan results to a file
func saveResults(hostname, ip string, results []scanner.ScanResult) {
	data := struct {
		Hostname string
		IP       string
		Results  []scanner.ScanResult
		Time     string
	}{
		Hostname: hostname,
		IP:       ip,
		Results:  results,
		Time:     time.Now().Format(time.RFC3339),
	}

	utils.OutputToFile(outputFile, outputFormat, data)
}

// saveHostResult saves host scan results to a file
func saveHostResult(host *scanner.HostResult) {
	data := struct {
		Host *scanner.HostResult
		Time string
	}{
		Host: host,
		Time: time.Now().Format(time.RFC3339),
	}

	utils.OutputToFile(outputFile, outputFormat, data)
}
