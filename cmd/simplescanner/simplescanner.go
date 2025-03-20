package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
)

func printHelp() {
	fmt.Print(`
SimpleScanner - A basic port scanner

Usage:
  simplescanner [options] <target>

Options:
  -p, --ports string    Port range to scan (default "1-1000")
  -t, --timeout int     Timeout in milliseconds (default 500)
  -c, --concurrent int  Number of concurrent scans (default 100)
  -h, --help            Show this help message

Examples:
  simplescanner 192.168.1.1
  simplescanner -p 22,80,443 example.com
  simplescanner -p 1-10000 -t 1000 -c 200 10.0.0.1
`)
}

func main() {
	// Parse command line flags with standard flag package
	var (
		showHelp   = flag.Bool("help", false, "Show help")
		shortHelp  = flag.Bool("h", false, "Show help")
		portRange  = flag.String("ports", "1-1000", "Port range to scan")
		shortPorts = flag.String("p", "1-1000", "Port range to scan")
		timeout    = flag.Int("timeout", 500, "Timeout in milliseconds")
		shortTime  = flag.Int("t", 500, "Timeout in milliseconds")
		concurrent = flag.Int("concurrent", 100, "Number of concurrent scans")
		shortConc  = flag.Int("c", 100, "Number of concurrent scans")
	)

	flag.Parse()

	// Show help if requested or if no arguments provided
	if *showHelp || *shortHelp || flag.NArg() == 0 {
		printHelp()
		os.Exit(0)
	}

	target := flag.Arg(0)

	// Use short flag values if the long ones weren't specified
	ports := *portRange
	if ports == "1-1000" && *shortPorts != "1-1000" {
		ports = *shortPorts
	}

	timeoutValue := *timeout
	if timeoutValue == 500 && *shortTime != 500 {
		timeoutValue = *shortTime
	}

	concurrentValue := *concurrent
	if concurrentValue == 100 && *shortConc != 100 {
		concurrentValue = *shortConc
	}

	fmt.Printf("Scanning %s (ports: %s)...\n", target, ports)
	startTime := time.Now()

	// Extract start and end port from range - simplified for this example
	startPort, endPort := 1, 1000

	s := scanner.New(target, time.Duration(timeoutValue)*time.Millisecond, concurrentValue)
	results := s.ScanRange("tcp", startPort, endPort)

	fmt.Printf("\nCompleted in %.2f seconds\n", time.Since(startTime).Seconds())
	fmt.Printf("Found %d open ports\n\n", len(results))

	if len(results) > 0 {
		fmt.Println("PORT\tSTATE\tSERVICE")
		for _, result := range results {
			fmt.Printf("%d/%s\t%s\t%s\n",
				result.Port,
				result.Protocol,
				result.State,
				result.Service)
		}
	}
}
