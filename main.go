package main

import (
	"fmt"
	"os"
	"time"

	"github.com/supakornn/goscanner/cmd"
)

// version information
const (
	Version   = "1.0.0"
	BuildDate = "2023-03-22"
)

func main() {
	startTime := time.Now()

	// check if help flag is present
	helpRequested := false
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			helpRequested = true
			break
		}
	}

	// execute the main scanner command
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// calculate and display performance metrics based on total ports scanned
	elapsed := time.Since(startTime)
	if elapsed.Seconds() > 5 {
		fmt.Printf("\nTotal scan time: %s\n", elapsed.Round(time.Millisecond))
	}

	// only display scan time if actually performing a scan
	if !helpRequested {
		// calculate ports per second based on total ports scanned
		portsPerSecond := 65535 / elapsed.Seconds()

		fmt.Println()
		fmt.Printf("Scan completed in %.2f seconds\n", elapsed.Seconds())
		fmt.Printf("Overall scanning rate: ~%.0f ports per second\n", portsPerSecond)

		if portsPerSecond > 10000 {
			fmt.Println("🚀 Fast Scan completed!")
		}
	}
}
