package main

import (
	"fmt"
	"os"
	"time"

	"github.com/supakornn/goscanner/cmd"
)

func main() {
	startTime := time.Now()

	// Check if help flag is present
	helpRequested := false
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			helpRequested = true
			break
		}
	}

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Only display scan time if actually performing a scan
	if !helpRequested {
		elapsed := time.Since(startTime)
		// Calculate ports per second based on total ports (65535)
		portsPerSecond := 65535 / elapsed.Seconds()

		fmt.Println()
		fmt.Printf("Scan completed in %.2f seconds\n", elapsed.Seconds())
		fmt.Printf("Overall scanning rate: ~%.0f ports per second\n", portsPerSecond)

		if portsPerSecond > 10000 {
			fmt.Println("🚀 Fast scan completed! Consider adding --nmap for automatic service detection on open ports.")
		}
	}
}
