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

// process targets from command line or file
func processTargets() ([]string, error) {
	if targetFile != "" {
		return utils.ReadLinesFromFile(targetFile)
	}

	return utils.ParseTargetSpec(target)
}

// buildScanOptions builds a ScanOption struct from command line flags
func buildScanOptions() scanner.ScanOption {
	// convert timeout to time.Duration
	timeoutDuration := time.Duration(timeout) * time.Millisecond

	// build scan options from all command line flags
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

	// set scan technique based on command line flags
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

	// set decoys if provided
	if decoys != "" {
		scanOptions.Decoys = decoys // now expecting a string, not a slice
	}

	// set script options if provided
	if scriptScan {
		scanOptions.ScriptScan = true
		if scripts != "" {
			scanOptions.Scripts = scripts // now expecting a string, not a slice
		}
	}

	return scanOptions
}

// perform a scan on a single host
func performSingleHostScan(target string, startPort, endPort int, options scanner.ScanOption) {
	startTime := time.Now()

	ip, err := utils.ParseTarget(target)
	if err != nil {
		fmt.Printf("Error resolving target %s: %v\n", target, err)
		return
	}

	// use the exact ports list from options if available
	portsToScan := options.Ports
	numPorts := len(portsToScan)

	// show the actual number of ports being scanned
	fmt.Printf("Scanning %s (%s) [%d ports]\n", target, ip, numPorts)

	s := scanner.NewWithOptions(ip, options)
	s.SetShowFiltered(showFiltered)

	var results []scanner.ScanResult
	var openPorts []int

	if skipHostDiscovery {
		// use user-specified ports if available
		if len(portsToScan) > 0 {
			// scan only the user-specified ports
			results = make([]scanner.ScanResult, 0, len(portsToScan))
			for _, port := range portsToScan {
				// Always use the ultra-fast scan for initial detection
				result := s.UltraFastScanPort(ip, port)

				// Add protocol information
				result.Protocol = protocol

				// only scan in detail if port is open
				if result.State == "open" {
					// print open ports immediately with [+] format
					fmt.Printf("[+] Open %s:%d (%s)\n", ip, port, result.Service)

					if options.BannerGrab || options.ServiceDetection {
						// Keep the open state by setting it explicitly
						detailedResult := s.ScanPort(protocol, port)
						// Preserve the open state from the fast scan
						detailedResult.State = "open"
						result = detailedResult

						// Display additional information if banner or service info was found
						if result.Banner != "" || result.Version != "" {
							if result.Banner != "" {
								fmt.Printf("    Banner: %s\n", strings.Split(result.Banner, "\n")[0])
							}
							if result.Version != "" {
								fmt.Printf("    Version: %s\n", result.Version)
							}
						}
					}
					openPorts = append(openPorts, result.Port)
				}

				results = append(results, result)
			}
		} else {
			// use ultra-fast port range scanning
			results = s.ScanRange(protocol, startPort, endPort)

			// extract open ports and print them immediately
			for _, result := range results {
				if result.State == "open" {
					openPorts = append(openPorts, result.Port)
					// print open ports immediately with [+] format
					fmt.Printf("[+] Open %s:%d (%s)\n", ip, result.Port, result.Service)
				}
			}
		}

		// calculate and print scan time
		scanDuration := time.Since(startTime)
		if verbose {
			fmt.Printf("Port scan completed in %.2f seconds\n", scanDuration.Seconds())
		}

		// always print results, even if we didn't find open ports
		printPortScanResults(target, ip, results)

		// run Nmap on open ports if auto-nmap is enabled
		// always run Nmap by default unless disabled
		if (autoNmap || !options.Verbose) && len(openPorts) > 0 {
			fmt.Printf("[~] Starting Script(s)\n")
			runNmapOnOpenPorts(ip, openPorts, nmapFlags)
		}
	} else {
		// for host discovery mode, we need to use the specified ports
		if len(portsToScan) > 0 {
			// manually scan the specified ports
			results = make([]scanner.ScanResult, 0, len(portsToScan))
			for _, port := range portsToScan {
				result := s.UltraFastScanPort(ip, port)
				result.Protocol = protocol

				if result.State == "open" {
					if options.BannerGrab || options.ServiceDetection {
						// Keep the open state by setting it explicitly
						detailedResult := s.ScanPort(protocol, port)
						// Preserve the open state from the fast scan
						detailedResult.State = "open"
						result = detailedResult

						// Display additional information if banner or service info was found
						if result.Banner != "" || result.Version != "" {
							if result.Banner != "" {
								fmt.Printf("    Banner: %s\n", strings.Split(result.Banner, "\n")[0])
							}
							if result.Version != "" {
								fmt.Printf("    Version: %s\n", result.Version)
							}
						}
					}
					openPorts = append(openPorts, result.Port)
				}

				results = append(results, result)
			}

			// calculate and print scan time
			scanDuration := time.Since(startTime)
			fmt.Printf("Host scan completed in %.2f seconds\n", scanDuration.Seconds())

			printPortScanResults(target, ip, results)
		} else {
			// use the full host scan with all ports
			hostResult := s.ScanHost()

			// calculate and print scan time
			scanDuration := time.Since(startTime)
			fmt.Printf("Host scan completed in %.2f seconds\n", scanDuration.Seconds())

			printDetailedHostResult(hostResult)

			// extract open ports
			for _, result := range hostResult.OpenPorts {
				openPorts = append(openPorts, result.Port)
			}
		}

		// run Nmap on open ports if auto-nmap is enabled
		if autoNmap && len(openPorts) > 0 {
			fmt.Printf("\nNmap scan on %d open ports...\n", len(openPorts))
			runNmapOnOpenPorts(ip, openPorts, nmapFlags)
		}
	}
}

// perform a scan on multiple hosts with optimizations
func performMultiHostScan(targets []string, startPort, endPort int, options scanner.ScanOption) {
	// use the exact ports list from options if available
	portsToScan := options.Ports
	numPorts := len(portsToScan)
	if numPorts == 0 {
		numPorts = endPort - startPort + 1
	}

	if verbose {
		fmt.Printf("Scanning %d targets each with %d ports...\n", len(targets), numPorts)
	}
	totalStartTime := time.Now()

	// limit output for large scans
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
			// use user-specified ports if available
			if len(portsToScan) > 0 {
				// scan only the user-specified ports
				results = make([]scanner.ScanResult, 0, len(portsToScan))
				for _, port := range portsToScan {
					// always use the ultra-fast scan for initial detection
					result := s.UltraFastScanPort(ip, port)

					// Add protocol information
					result.Protocol = protocol

					// only scan in detail if port is open
					if result.State == "open" {
						// print open ports immediately with [+] format
						fmt.Printf("[+] Open %s:%d (%s)\n", ip, port, result.Service)

						if options.BannerGrab || options.ServiceDetection {
							// Keep the open state by setting it explicitly
							detailedResult := s.ScanPort(protocol, port)
							// Preserve the open state from the fast scan
							detailedResult.State = "open"
							result = detailedResult

							// Display additional information if banner or service info was found
							if result.Banner != "" || result.Version != "" {
								if result.Banner != "" {
									fmt.Printf("    Banner: %s\n", strings.Split(result.Banner, "\n")[0])
								}
								if result.Version != "" {
									fmt.Printf("    Version: %s\n", result.Version)
								}
							}
						}
						openPorts = append(openPorts, result.Port)
					}

					results = append(results, result)
				}
			} else {
				// use ultra-fast port range scanning
				results = s.ScanRange(protocol, startPort, endPort)

				// extract open ports and print them immediately
				for _, result := range results {
					if result.State == "open" {
						openPorts = append(openPorts, result.Port)
						// print open ports immediately with [+] format
						fmt.Printf("[+] Open %s:%d (%s)\n", ip, result.Port, result.Service)
					}
				}
			}

			// calculate and print scan time
			hostScanDuration := time.Since(hostStartTime)
			if verbose {
				fmt.Printf("Port scan completed in %.2f seconds\n", hostScanDuration.Seconds())
				fmt.Printf("Scan rate: ~%.0f ports/second\n", float64(numPorts)/hostScanDuration.Seconds())
			}

			// Always print summary results if we have open ports
			if len(openPorts) > 0 || verbose {
				printPortScanResults(targets[i], ip, results)
			}

			// run Nmap on open ports if auto-nmap is enabled
			if (autoNmap || !options.Verbose) && len(openPorts) > 0 {
				fmt.Printf("[~] Starting Script(s)\n")
				runNmapOnOpenPorts(ip, openPorts, nmapFlags)
			}
		} else {
			// for host discovery mode, we need to use the specified ports
			if len(portsToScan) > 0 {
				// manually scan the specified ports
				results = make([]scanner.ScanResult, 0, len(portsToScan))
				for _, port := range portsToScan {
					result := s.UltraFastScanPort(ip, port)
					result.Protocol = protocol

					if result.State == "open" {
						if options.BannerGrab || options.ServiceDetection {
							// Keep the open state by setting it explicitly
							detailedResult := s.ScanPort(protocol, port)
							// Preserve the open state from the fast scan
							detailedResult.State = "open"
							result = detailedResult

							// Display additional information if banner or service info was found
							if result.Banner != "" || result.Version != "" {
								if result.Banner != "" {
									fmt.Printf("    Banner: %s\n", strings.Split(result.Banner, "\n")[0])
								}
								if result.Version != "" {
									fmt.Printf("    Version: %s\n", result.Version)
								}
							}
						}
						openPorts = append(openPorts, result.Port)
					}

					results = append(results, result)
				}

				// calculate and print scan time
				hostScanDuration := time.Since(hostStartTime)
				fmt.Printf("Host scan completed in %.2f seconds\n", hostScanDuration.Seconds())

				// Always print summary results if we have open ports
				if len(openPorts) > 0 || verbose {
					printPortScanResults(targets[i], ip, results)
				}
			} else {
				// use the full host scan with all ports
				hostResult := s.ScanHost()

				// calculate and print scan time
				hostScanDuration := time.Since(hostStartTime)
				fmt.Printf("Host scan completed in %.2f seconds\n", hostScanDuration.Seconds())

				// only show results if not too many hosts or if we have open ports
				if i < maxHostsToDisplay || len(hostResult.OpenPorts) > 0 {
					printDetailedHostResult(hostResult)
				} else if i == maxHostsToDisplay {
					fmt.Printf("Output limited for remaining %d hosts. Use --output-file for complete results.\n",
						len(targets)-maxHostsToDisplay)
				}

				// extract open ports
				for _, result := range hostResult.OpenPorts {
					openPorts = append(openPorts, result.Port)
				}
			}

			// run Nmap on open ports if auto-nmap is enabled
			if autoNmap && len(openPorts) > 0 {
				fmt.Printf("\nNmap scan on %d open ports...\n", len(openPorts))
				runNmapOnOpenPorts(ip, openPorts, nmapFlags)
			}
		}
	}

	// print total scan time if verbose
	if verbose {
		totalScanDuration := time.Since(totalStartTime)
		fmt.Printf("\nTotal scan time for %d hosts: %.2f seconds\n", len(targets), totalScanDuration.Seconds())
		fmt.Printf("Average time per host: %.2f seconds\n", totalScanDuration.Seconds()/float64(len(targets)))

		if len(targets) > maxHostsToDisplay {
			fmt.Printf("Scan summary: Scanned %d hosts, %d ports per host\n", len(targets), numPorts)
		}
	}
}

// handles scanning with the nmap binary
func runNmapScan(targetStr string, nmapArgs []string) {
	fmt.Println("Using nmap for advanced scanning...")

	hostResult, err := nmap.RunNmap(targetStr, nmapArgs)
	if err != nil {
		fmt.Printf("Nmap scan failed: %v\n", err)
		os.Exit(1)
	}

	// print results
	printDetailedHostResult(hostResult)
}

// runs nmap on discovered open ports
func runNmapOnOpenPorts(target string, openPorts []int, customFlags string) {
	if len(openPorts) == 0 {
		fmt.Println("No open ports found for Nmap scanning.")
		return
	}

	// convert open ports to port specification string
	portsStr := ""
	for i, port := range openPorts {
		if i > 0 {
			portsStr += ","
		}
		portsStr += fmt.Sprintf("%d", port)
	}

	fmt.Printf("Running Nmap on %s with %d open ports: %s\n", target, len(openPorts), portsStr)

	// build nmap arguments
	var nmapArgs []string
	nmapArgs = append(nmapArgs, "-p", portsStr)

	// add custom flags if provided
	if customFlags != "" {
		// split the flags string into individual arguments
		flagArgs := strings.Fields(customFlags)
		nmapArgs = append(nmapArgs, flagArgs...)
	} else {
		// default flags for service and script scanning
		nmapArgs = append(nmapArgs, "-sC", "-sV")
	}

	hostResult, err := nmap.RunNmap(target, nmapArgs)
	if err != nil {
		fmt.Printf("Nmap scan failed: %v\n", err)
		return
	}

	// print detailed results
	printDetailedHostResult(hostResult)
}
