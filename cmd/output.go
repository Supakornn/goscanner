package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
	"github.com/supakornn/goscanner/pkg/utils"
)

// Prints scan results for a host
func printPortScanResults(hostname, ip string, results []scanner.ScanResult) {
	fmt.Printf("\nScan results for %s (%s):\n", hostname, ip)

	// Count open and filtered ports
	openCount := 0
	filteredCount := 0
	closedCount := 0

	for _, result := range results {
		if result.State == "open" {
			openCount++
		} else if result.State == "filtered" {
			filteredCount++
		} else if result.State == "closed" {
			closedCount++
		}
	}

	// Display count summary
	fmt.Printf("%d ports open, %d filtered, %d closed\n\n", openCount, filteredCount, closedCount)

	// When a specific port is requested with -p, show all results for those specific ports
	// This should NOT include when -s is used for scan technique
	specificPortRequested := GetSpecificPorts() != ""

	// First print open ports
	if openCount > 0 {
		fmt.Println("OPEN PORTS:")
		fmt.Println("PORT\tSTATE\tSERVICE\tVERSION")
		for _, result := range results {
			if result.State == "open" {
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
		}
	}

	// Then print filtered ports if explicitly enabled or if specific ports were requested with -p
	if filteredCount > 0 && (IsVerbose() || ShouldShowFiltered() || specificPortRequested) {
		if openCount > 0 {
			fmt.Println() // Add a newline for separation
		}

		// If showing all ports (specific ones requested), don't limit
		maxFilteredToShow := 20
		if specificPortRequested {
			maxFilteredToShow = len(results) // Show all requested ports
		}

		shownFilteredCount := 0

		fmt.Println("FILTERED PORTS:")
		fmt.Println("PORT\tSTATE\tSERVICE")
		for _, result := range results {
			if result.State == "filtered" {
				if shownFilteredCount < maxFilteredToShow {
					fmt.Printf("%d/%s\t%s\t%s\n",
						result.Port,
						strings.ToLower(result.Protocol),
						result.State,
						result.Service)
					shownFilteredCount++
				} else {
					// Once we hit the limit, stop showing individual ports
					break
				}
			}
		}

		// Show a message if we hit the limit (only for non-specific port scans)
		if !specificPortRequested && filteredCount > maxFilteredToShow {
			fmt.Printf("... and %d more filtered ports (use --output-file to save full results)\n",
				filteredCount-maxFilteredToShow)
		}
	}

	// Then print closed ports if verbose or if specific ports were requested with -p
	if closedCount > 0 && (IsVerbose() || specificPortRequested) {
		if openCount > 0 || (filteredCount > 0 && (IsVerbose() || ShouldShowFiltered() || specificPortRequested)) {
			fmt.Println() // Add a newline for separation
		}

		// If showing all ports (specific ones requested), don't limit
		maxClosedToShow := 10
		if specificPortRequested {
			maxClosedToShow = len(results) // Show all requested ports
		}

		shownClosedCount := 0

		fmt.Println("CLOSED PORTS:")
		fmt.Println("PORT\tSTATE\tSERVICE")
		for _, result := range results {
			if result.State == "closed" {
				if shownClosedCount < maxClosedToShow {
					fmt.Printf("%d/%s\t%s\t%s\n",
						result.Port,
						strings.ToLower(result.Protocol),
						result.State,
						result.Service)
					shownClosedCount++
				} else {
					// Once we hit the limit, stop showing individual ports
					break
				}
			}
		}

		// Show a message if we hit the limit (only for non-specific port scans)
		if !specificPortRequested && closedCount > maxClosedToShow {
			fmt.Printf("... and %d more closed ports (use --output-file to save full results)\n",
				closedCount-maxClosedToShow)
		}
	}

	// Generate report if needed
	if GetOutputFile() != "" {
		saveResults(hostname, ip, results)
	}

	// Show hint if needed, but not if specific ports were requested
	if !specificPortRequested {
		if openCount == 0 && filteredCount > 0 && !IsVerbose() && !ShouldShowFiltered() {
			fmt.Println("\nHint: Use -V or -F flags to show filtered ports")
		} else if openCount == 0 && filteredCount == 0 && closedCount > 0 {
			fmt.Println("\nNo open or filtered ports found.")
		} else if openCount == 0 && !IsVerbose() && !ShouldShowFiltered() {
			fmt.Println("\nNo open ports found.")
		}
	}
}

// Prints detailed host scan results
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

		// Check if specific ports were requested with -p
		specificPortRequested := GetSpecificPorts() != ""

		// Open ports
		if len(host.OpenPorts) > 0 {
			fmt.Printf("\nOPEN PORTS (%d):\n", len(host.OpenPorts))
			fmt.Printf("PORT\tSTATE\tSERVICE\tVERSION\n")
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
		}

		// Filtered ports - display only if verbose, showFiltered, or specific ports requested with -p
		if (IsVerbose() || ShouldShowFiltered() || specificPortRequested) && len(host.FilteredPorts) > 0 {
			fmt.Printf("\nFILTERED PORTS (%d):\n", len(host.FilteredPorts))
			fmt.Printf("PORT\tSTATE\tSERVICE\n")

			// Limit the number of filtered ports displayed unless specific ports were requested
			maxFilteredToShow := 20
			if specificPortRequested {
				maxFilteredToShow = len(host.FilteredPorts) // Show all requested ports
			}

			filteredCount := len(host.FilteredPorts)

			for i, result := range host.FilteredPorts {
				if i < maxFilteredToShow {
					fmt.Printf("%d/%s\t%s\t%s\n",
						result.Port,
						strings.ToLower(result.Protocol),
						"filtered",
						result.Service)
				} else {
					break
				}
			}

			// Show a message if we hit the limit, but only for non-specific port scans
			if !specificPortRequested && filteredCount > maxFilteredToShow {
				fmt.Printf("... and %d more filtered ports (use --output-file to save full results)\n",
					filteredCount-maxFilteredToShow)
			}
		}

		// Closed ports - display only if verbose or if specific ports were requested with -p
		if (IsVerbose() || specificPortRequested) && len(host.ClosedPorts) > 0 {
			fmt.Printf("\nCLOSED PORTS (%d):\n", len(host.ClosedPorts))
			fmt.Printf("PORT\tSTATE\tSERVICE\n")

			// Limit the number of closed ports displayed unless specific ports were requested
			maxClosedToShow := 10
			if specificPortRequested {
				maxClosedToShow = len(host.ClosedPorts) // Show all requested ports
			}

			closedCount := len(host.ClosedPorts)

			for i, result := range host.ClosedPorts {
				if i < maxClosedToShow {
					fmt.Printf("%d/%s\t%s\t%s\n",
						result.Port,
						strings.ToLower(result.Protocol),
						"closed",
						result.Service)
				} else {
					break
				}
			}

			// Show a message if we hit the limit, but only for non-specific port scans
			if !specificPortRequested && closedCount > maxClosedToShow {
				fmt.Printf("... and %d more closed ports (use --output-file to save full results)\n",
					closedCount-maxClosedToShow)
			}
		}

		// Save to file if needed
		if GetOutputFile() != "" {
			saveHostResult(host)
		}

		// Print summary
		fmt.Printf("\nScan summary: %d open port(s), %d filtered port(s), %d closed port(s)\n",
			len(host.OpenPorts), len(host.FilteredPorts), len(host.ClosedPorts))

		// Only show hints if not specifically requested ports
		if !specificPortRequested {
			if len(host.OpenPorts) == 0 && len(host.FilteredPorts) > 0 && !IsVerbose() && !ShouldShowFiltered() {
				fmt.Println("Hint: Use -V or -F flags to show filtered ports")
			} else if len(host.OpenPorts) == 0 && len(host.FilteredPorts) == 0 {
				fmt.Println("No open or filtered ports found.")
			} else if len(host.OpenPorts) == 0 && !IsVerbose() && !ShouldShowFiltered() {
				fmt.Println("No open ports found.")
			}
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

	utils.OutputToFile(GetOutputFile(), GetOutputFormat(), data)
}

// Saves host scan results to a file
func saveHostResult(host *scanner.HostResult) {
	data := struct {
		Host *scanner.HostResult
		Time string
	}{
		Host: host,
		Time: time.Now().Format(time.RFC3339),
	}

	utils.OutputToFile(GetOutputFile(), GetOutputFormat(), data)
}
