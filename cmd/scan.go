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

// processTargets handles target processing from command line or file
func processTargets() ([]string, error) {
	if targetFile != "" {
		return utils.ReadLinesFromFile(targetFile)
	}

	return utils.ParseTargetSpec(target)
}

// buildScanOptions builds scanner options from command line flags
func buildScanOptions() scanner.ScanOption {
	options := scanner.ScanOption{
		Technique:         parseScanTechnique(scanTechnique),
		Timeout:           time.Duration(timeout) * time.Millisecond,
		Concurrent:        concurrent,
		BannerGrab:        bannerGrab,
		ServiceDetection:  serviceDetection,
		OSDetection:       osDetection,
		HostDiscovery:     !skipHostDiscovery,
		IPProtocol:        protocol,
		OutputFormat:      outputFormat,
		Verbose:           verbose,
		Debug:             debug,
		TimingTemplate:    timingTemplate,
		FragmentPackets:   fragmentPackets,
		SourcePort:        sourcePort,
		TTL:               ttl,
		TraceRoute:        traceroute,
		RandomTargets:     randomTargets,
		SkipHostDiscovery: skipHostDiscovery,
		ShowFiltered:      showFiltered,
	}

	// Process decoys
	if decoys != "" {
		options.Decoys = strings.Split(decoys, ",")
	}

	// Process scripts
	if scriptScan {
		options.ScriptScan = true
		if scripts != "" {
			options.Scripts = strings.Split(scripts, ",")
		}
	}

	return options
}

// printScanInfo prints information about the scan
func printScanInfo(targets []string, startPort, endPort int) {
	fmt.Printf("Starting GoScanner %s at %s\n", "1.0", time.Now().Format(time.RFC1123))
	fmt.Printf("Scan configuration:\n")
	fmt.Printf("  - Targets: %d hosts\n", len(targets))
	fmt.Printf("  - Ports: %d-%d\n", startPort, endPort)
	fmt.Printf("  - Scan technique: %s\n", scanTechnique)
	fmt.Printf("  - Timing template: T%d\n", timingTemplate)
	fmt.Printf("  - Service detection: %t\n", serviceDetection)
	fmt.Printf("  - OS detection: %t\n", osDetection)
	fmt.Printf("  - Host discovery: %t\n", !skipHostDiscovery)
	fmt.Println()
}

// performSingleHostScan performs a scan on a single host
func performSingleHostScan(target string, startPort, endPort int, options scanner.ScanOption) {
	ip, err := utils.ParseTarget(target)
	if err != nil {
		fmt.Printf("Error resolving target: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning %s (%s) [%d ports]\n", target, ip, endPort-startPort+1)

	s := scanner.NewWithOptions(ip, options)
	if skipHostDiscovery {
		results := s.ScanRange(protocol, startPort, endPort)
		printPortScanResults(target, ip, results)
	} else {
		hostResult := s.ScanHost()
		printDetailedHostResult(hostResult)
	}
}

// performMultiHostScan performs a scan on multiple hosts
func performMultiHostScan(targets []string, startPort, endPort int, options scanner.ScanOption) {
	fmt.Printf("Scanning %d targets...\n", len(targets))

	// Limit output for large scans
	maxHostsToDisplay := 5
	if len(targets) < maxHostsToDisplay {
		maxHostsToDisplay = len(targets)
	}

	for i := 0; i < maxHostsToDisplay; i++ {
		ip, err := utils.ParseTarget(targets[i])
		if err != nil {
			fmt.Printf("Error resolving target %s: %v\n", targets[i], err)
			continue
		}

		fmt.Printf("\nScanning %s (%s)...\n", targets[i], ip)

		s := scanner.NewWithOptions(ip, options)
		if skipHostDiscovery {
			results := s.ScanRange(protocol, startPort, endPort)
			printPortScanResults(targets[i], ip, results)
		} else {
			hostResult := s.ScanHost()
			printDetailedHostResult(hostResult)
		}
	}

	if len(targets) > maxHostsToDisplay {
		fmt.Printf("\nOutput limited to %d hosts. Full scan results available if using -oX or -oJ options.\n", maxHostsToDisplay)
	}
}

// runNmapScan handles scanning with the nmap binary
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
