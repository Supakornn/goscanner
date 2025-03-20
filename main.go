package main

import (
	"fmt"
	"os"
	"time"

	"github.com/supakornn/goscanner/cmd"
)

func main() {
	startTime := time.Now()

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(startTime)
	fmt.Printf("Total scan time: %.2f seconds\n", elapsed.Seconds())
}
