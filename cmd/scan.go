package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/supakornn/goscanner/pkg/nmap"
	"github.com/supakornn/goscanner/pkg/scanner"
	"github.com/supakornn/goscanner/pkg/utils"
)

// Handles target processing from command line or file
func processTargets() ([]string, error) {
	if targetFile != "" {
		return utils.ReadLinesFromFile(targetFile)
	}

	return utils.ParseTargetSpec(target)
}

// buildScanOptions builds a ScanOption struct from command line flags
func buildScanOptions() scanner.ScanOption {
	// Convert timeout from milliseconds to time.Duration
	timeoutDuration := time.Duration(timeout) * time.Millisecond

	// Build the scan options from all command line flags
	scanOptions := scanner.ScanOption{
		Timeout:           timeoutDuration,
		Concurrent:        concurrent,
		ServiceDetection:  serviceDetection,
		OSDetection:       osDetection,
		BannerGrab:        bannerGrab,
		HostDiscovery:     !skipHostDiscovery,
		OutputFormat:      outputFormat,
		Verbose:           verbose,
		Debug:             debug,
		TimingTemplate:    timingTemplate,
		FragmentPackets:   fragmentPackets,
		SourcePort:        sourcePort,
		TTL:               ttl,
		RandomTargets:     randomTargets,
		SkipHostDiscovery: skipHostDiscovery,
		ShowFiltered:      showFiltered,
		TraceRoute:        traceroute,
		IPv4Only:          ipv4Only,
	}

	// Set the scan technique based on command line flags
	if scanTechnique != "" {
		switch strings.ToLower(scanTechnique) {
		case "connect":
			scanOptions.Technique = scanner.TechConnect
		case "syn":
			scanOptions.Technique = scanner.TechSYN
		case "fin":
			scanOptions.Technique = scanner.TechFIN
		case "xmas":
			scanOptions.Technique = scanner.TechXMAS
		case "null":
			scanOptions.Technique = scanner.TechNULL
		case "ack":
			scanOptions.Technique = scanner.TechACK
		case "udp":
			scanOptions.Technique = scanner.TechUDP
		default:
			scanOptions.Technique = scanner.TechConnect
		}
	}

	// Set decoys if provided
	if decoys != "" {
		scanOptions.Decoys = decoys // Now expecting a string, not a slice
	}

	// Set script options if provided
	if scriptScan {
		scanOptions.ScriptScan = true
		if scripts != "" {
			scanOptions.Scripts = scripts // Now expecting a string, not a slice
		}
	}

	return scanOptions
}

// printScanInfo prints information about the scan
func printScanInfo(targets []string, startPort, endPort int) {
	// All necessary header information is already displayed in the banner
	// Just continue without printing duplicate information
}

// Performs a scan on a single host
func performSingleHostScan(target string, startPort, endPort int, options scanner.ScanOption) {
	startTime := time.Now()

	ip, err := utils.ParseTarget(target)
	if err != nil {
		fmt.Printf("Error resolving target %s: %v\n", target, err)
		return
	}

	// Use the exact ports list from options if available
	portsToScan := options.Ports
	numPorts := len(portsToScan)
	if numPorts == 0 {
		numPorts = endPort - startPort + 1
	}

	fmt.Printf("Scanning %s (%s) [%d ports]\n", target, ip, numPorts)

	s := scanner.NewWithOptions(ip, options)
	s.SetShowFiltered(showFiltered)

	var results []scanner.ScanResult
	var openPorts []int

	if skipHostDiscovery {
		// Use user-specified ports if available
		if len(portsToScan) > 0 {
			// Scan only the user-specified ports
			results = make([]scanner.ScanResult, 0, len(portsToScan))
			for _, port := range portsToScan {
				// Always use the ultra-fast scan for initial detection
				result := s.UltraFastScanPort(ip, port)

				// Add protocol information
				result.Protocol = protocol

				// Only scan in detail if port is open
				if result.State == "open" {
					// Print open ports immediately
					fmt.Printf("Open %s:%d\n", ip, port)

					if options.BannerGrab || options.ServiceDetection {
						result = s.ScanPort(protocol, port)
					}
					openPorts = append(openPorts, result.Port)
				}

				results = append(results, result)
			}
		} else {
			// Use ultra-fast port range scanning
			results = s.ScanRange(protocol, startPort, endPort)

			// Extract open ports and print them immediately
			for _, result := range results {
				if result.State == "open" {
					openPorts = append(openPorts, result.Port)
					// Print open ports immediately
					fmt.Printf("Open %s:%d\n", ip, result.Port)
				}
			}
		}

		// Calculate and print scan time
		scanDuration := time.Since(startTime)
		if verbose {
			fmt.Printf("Port scan completed in %.2f seconds\n", scanDuration.Seconds())
		}

		// Only show results if we found open ports
		if len(openPorts) > 0 {
			printPortScanResults(target, ip, results)
		}

		// Run Nmap on open ports if auto-nmap is enabled
		// always run Nmap by default unless disabled
		if (autoNmap || !options.Verbose) && len(openPorts) > 0 {
			fmt.Printf("[~] Starting Script(s)\n")
			runNmapOnOpenPorts(ip, openPorts, nmapFlags)
		}
	} else {
		// For host discovery mode, we need to use the specified ports
		if len(portsToScan) > 0 {
			// Manually scan the specified ports
			results = make([]scanner.ScanResult, 0, len(portsToScan))
			for _, port := range portsToScan {
				result := s.UltraFastScanPort(ip, port)
				result.Protocol = protocol

				if result.State == "open" {
					if options.BannerGrab || options.ServiceDetection {
						result = s.ScanPort(protocol, port)
					}
					openPorts = append(openPorts, result.Port)
				}

				results = append(results, result)
			}

			// Calculate and print scan time
			scanDuration := time.Since(startTime)
			fmt.Printf("Host scan completed in %.2f seconds\n", scanDuration.Seconds())

			printPortScanResults(target, ip, results)
		} else {
			// Use the full host scan with all ports
			hostResult := s.ScanHost()

			// Calculate and print scan time
			scanDuration := time.Since(startTime)
			fmt.Printf("Host scan completed in %.2f seconds\n", scanDuration.Seconds())

			printDetailedHostResult(hostResult)

			// Extract open ports
			for _, result := range hostResult.OpenPorts {
				openPorts = append(openPorts, result.Port)
			}
		}

		// Run Nmap on open ports if auto-nmap is enabled
		if autoNmap && len(openPorts) > 0 {
			fmt.Printf("\nNmap scan on %d open ports...\n", len(openPorts))
			runNmapOnOpenPorts(ip, openPorts, nmapFlags)
		}
	}
}

// Performs a scan on multiple hosts with optimizations
func performMultiHostScan(targets []string, startPort, endPort int, options scanner.ScanOption) {
	// Use the exact ports list from options if available
	portsToScan := options.Ports
	numPorts := len(portsToScan)
	if numPorts == 0 {
		numPorts = endPort - startPort + 1
	}

	if verbose {
		fmt.Printf("Scanning %d targets each with %d ports...\n", len(targets), numPorts)
	}
	totalStartTime := time.Now()

	// Limit output for large scans
	maxHostsToDisplay := 5
	if len(targets) < maxHostsToDisplay {
		maxHostsToDisplay = len(targets)
	}

	for i := 0; i < len(targets); i++ {
		ip, err := utils.ParseTarget(targets[i])
		if err != nil {
			fmt.Printf("Error resolving target %s: %v\n", targets[i], err)
			continue
		}

		if verbose {
			fmt.Printf("\nScanning target %d/%d: %s (%s)...\n", i+1, len(targets), targets[i], ip)
		}
		hostStartTime := time.Now()

		s := scanner.NewWithOptions(ip, options)
		s.SetShowFiltered(showFiltered)

		var results []scanner.ScanResult
		var openPorts []int

		if skipHostDiscovery {
			// Use user-specified ports if available
			if len(portsToScan) > 0 {
				// Scan only the user-specified ports
				results = make([]scanner.ScanResult, 0, len(portsToScan))
				for _, port := range portsToScan {
					// Always use the ultra-fast scan for initial detection
					result := s.UltraFastScanPort(ip, port)

					// Add protocol information
					result.Protocol = protocol

					// Only scan in detail if port is open
					if result.State == "open" {
						// Print open ports immediately
						fmt.Printf("Open %s:%d\n", ip, port)

						if options.BannerGrab || options.ServiceDetection {
							result = s.ScanPort(protocol, port)
						}
						openPorts = append(openPorts, result.Port)
					}

					results = append(results, result)
				}
			} else {
				// Use ultra-fast port range scanning
				results = s.ScanRange(protocol, startPort, endPort)

				// Extract open ports and print them immediately
				for _, result := range results {
					if result.State == "open" {
						openPorts = append(openPorts, result.Port)
						// Print open ports immediately
						fmt.Printf("Open %s:%d\n", ip, result.Port)
					}
				}
			}

			// Calculate and print scan time
			hostScanDuration := time.Since(hostStartTime)
			if verbose {
				fmt.Printf("Port scan completed in %.2f seconds\n", hostScanDuration.Seconds())
				fmt.Printf("Scan rate: ~%.0f ports/second\n", float64(numPorts)/hostScanDuration.Seconds())
			}

			// Only show results if not too many hosts or if we have open ports
			if verbose && (i < maxHostsToDisplay || len(openPorts) > 0) {
				printPortScanResults(targets[i], ip, results)
			} else if verbose && i == maxHostsToDisplay {
				fmt.Printf("Output limited for remaining %d hosts. Use --output-file for complete results.\n",
					len(targets)-maxHostsToDisplay)
			}

			// Run Nmap on open ports
			if (autoNmap || !options.Verbose) && len(openPorts) > 0 {
				fmt.Printf("[~] Starting Script(s)\n")
				runNmapOnOpenPorts(ip, openPorts, nmapFlags)
			}
		} else {
			// For host discovery mode, we need to use the specified ports
			if len(portsToScan) > 0 {
				// Manually scan the specified ports
				results = make([]scanner.ScanResult, 0, len(portsToScan))
				for _, port := range portsToScan {
					result := s.UltraFastScanPort(ip, port)
					result.Protocol = protocol

					if result.State == "open" {
						if options.BannerGrab || options.ServiceDetection {
							result = s.ScanPort(protocol, port)
						}
						openPorts = append(openPorts, result.Port)
					}

					results = append(results, result)
				}

				// Calculate and print scan time
				hostScanDuration := time.Since(hostStartTime)
				fmt.Printf("Host scan completed in %.2f seconds\n", hostScanDuration.Seconds())

				// Only show results if not too many hosts or if we have open ports
				if i < maxHostsToDisplay || len(openPorts) > 0 {
					printPortScanResults(targets[i], ip, results)
				} else if i == maxHostsToDisplay {
					fmt.Printf("Output limited for remaining %d hosts. Use --output-file for complete results.\n",
						len(targets)-maxHostsToDisplay)
				}
			} else {
				// Use the full host scan with all ports
				hostResult := s.ScanHost()

				// Calculate and print scan time
				hostScanDuration := time.Since(hostStartTime)
				fmt.Printf("Host scan completed in %.2f seconds\n", hostScanDuration.Seconds())

				// Only show results if not too many hosts or if we have open ports
				if i < maxHostsToDisplay || len(hostResult.OpenPorts) > 0 {
					printDetailedHostResult(hostResult)
				} else if i == maxHostsToDisplay {
					fmt.Printf("Output limited for remaining %d hosts. Use --output-file for complete results.\n",
						len(targets)-maxHostsToDisplay)
				}

				// Extract open ports
				for _, result := range hostResult.OpenPorts {
					openPorts = append(openPorts, result.Port)
				}
			}

			// Run Nmap on open ports if auto-nmap is enabled
			if autoNmap && len(openPorts) > 0 {
				fmt.Printf("\nNmap scan on %d open ports...\n", len(openPorts))
				runNmapOnOpenPorts(ip, openPorts, nmapFlags)
			}
		}
	}

	// Print total scan time if verbose
	if verbose {
		totalScanDuration := time.Since(totalStartTime)
		fmt.Printf("\nTotal scan time for %d hosts: %.2f seconds\n", len(targets), totalScanDuration.Seconds())
		fmt.Printf("Average time per host: %.2f seconds\n", totalScanDuration.Seconds()/float64(len(targets)))

		if len(targets) > maxHostsToDisplay {
			fmt.Printf("Scan summary: Scanned %d hosts, %d ports per host\n", len(targets), numPorts)
		}
	}
}

// Handles scanning with the nmap binary
func runNmapScan(targetStr string, nmapArgs []string) {
	fmt.Println("Using nmap for advanced scanning...")

	hostResult, err := nmap.RunNmap(targetStr, nmapArgs)
	if err != nil {
		fmt.Printf("Nmap scan failed: %v\n", err)
		os.Exit(1)
	}

	// Print results
	printDetailedHostResult(hostResult)
}

// runNmapOnOpenPorts runs nmap on discovered open ports
func runNmapOnOpenPorts(target string, openPorts []int, customFlags string) {
	if len(openPorts) == 0 {
		fmt.Println("No open ports found for Nmap scanning.")
		return
	}

	// Convert open ports to port specification string
	portsStr := ""
	for i, port := range openPorts {
		if i > 0 {
			portsStr += ","
		}
		portsStr += fmt.Sprintf("%d", port)
	}

	fmt.Printf("Running Nmap on %s with %d open ports: %s\n", target, len(openPorts), portsStr)

	// Build nmap arguments
	var nmapArgs []string
	nmapArgs = append(nmapArgs, "-p", portsStr)

	// Add custom flags if provided
	if customFlags != "" {
		// Split the flags string into individual arguments
		flagArgs := strings.Fields(customFlags)
		nmapArgs = append(nmapArgs, flagArgs...)
	} else {
		// Default flags for service and script scanning
		nmapArgs = append(nmapArgs, "-sC", "-sV")
	}

	hostResult, err := nmap.RunNmap(target, nmapArgs)
	if err != nil {
		fmt.Printf("Nmap scan failed: %v\n", err)
		return
	}

	// Print detailed results
	printDetailedHostResult(hostResult)
}

// printDetailedHostResult prints the details of a host scan
