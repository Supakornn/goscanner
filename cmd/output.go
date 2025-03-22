package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
	"github.com/supakornn/goscanner/pkg/utils"
)

// prints scan results for a host
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

	// display count summary
	fmt.Printf("%d ports open, %d filtered, %d closed\n\n", openCount, filteredCount, closedCount)

	// check if specific ports were requested with -p
	specificPortRequested := GetSpecificPorts() != ""

	// Print open ports
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

				// if we have a banner, display it
				if result.Banner != "" {
					bannerPreview := strings.Split(result.Banner, "\n")[0]
					if len(bannerPreview) > 80 {
						bannerPreview = bannerPreview[:80] + "..."
					}
					fmt.Printf("   |_ Banner: %s\n", bannerPreview)
				}
			}
		}
	}

	// print filtered ports
	if filteredCount > 0 && (IsVerbose() || ShouldShowFiltered() || specificPortRequested) {
		if openCount > 0 {
			fmt.Println()
		}

		// Limit the number of filtered ports displayed unless specific ports were requested
		maxFilteredToShow := 20
		if specificPortRequested {
			maxFilteredToShow = len(results)
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
					break
				}
			}
		}

		// Show a message if we hit the limit, but only for non-specific port scans
		if !specificPortRequested && filteredCount > maxFilteredToShow {
			fmt.Printf("... and %d more filtered ports (use --output-file to save full results)\n",
				filteredCount-maxFilteredToShow)
		}
	}

	// Print closed ports
	if closedCount > 0 && (IsVerbose() || specificPortRequested) {
		if openCount > 0 || (filteredCount > 0 && (IsVerbose() || ShouldShowFiltered() || specificPortRequested)) {
			fmt.Println()
		}

		// Limit the number of closed ports displayed unless specific ports were requested
		maxClosedToShow := 10
		if specificPortRequested {
			maxClosedToShow = len(results)
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
					break
				}
			}
		}

		// Show a message if we hit the limit, but only for non-specific port scans
		if !specificPortRequested && closedCount > maxClosedToShow {
			fmt.Printf("... and %d more closed ports (use --output-file to save full results)\n",
				closedCount-maxClosedToShow)
		}
	}

	// Save results to file if needed
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

// print detailed host scan results
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

		// check if specific ports were requested with -p
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

		// Filtered ports
		if (IsVerbose() || ShouldShowFiltered() || specificPortRequested) && len(host.FilteredPorts) > 0 {
			fmt.Printf("\nFILTERED PORTS (%d):\n", len(host.FilteredPorts))
			fmt.Printf("PORT\tSTATE\tSERVICE\n")

			// limit the number of filtered ports displayed unless specific ports were requested
			maxFilteredToShow := 20
			if specificPortRequested {
				maxFilteredToShow = len(host.FilteredPorts)
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

		// Closed ports
		if (IsVerbose() || specificPortRequested) && len(host.ClosedPorts) > 0 {
			fmt.Printf("\nCLOSED PORTS (%d):\n", len(host.ClosedPorts))
			fmt.Printf("PORT\tSTATE\tSERVICE\n")

			// limit the number of closed ports displayed unless specific ports were requested
			maxClosedToShow := 10
			if specificPortRequested {
				maxClosedToShow = len(host.ClosedPorts)
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

			// show a message if we hit the limit, but only for non-specific port scans
			if !specificPortRequested && closedCount > maxClosedToShow {
				fmt.Printf("... and %d more closed ports (use --output-file to save full results)\n",
					closedCount-maxClosedToShow)
			}
		}

		// save to file if needed
		if GetOutputFile() != "" {
			saveHostResult(host)
		}

		// print summary
		fmt.Printf("\nScan summary: %d open port(s), %d filtered port(s), %d closed port(s)\n",
			len(host.OpenPorts), len(host.FilteredPorts), len(host.ClosedPorts))

		// show hints if not specifically requested ports
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

// save scan results to a file
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

// save host scan results to a file
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
