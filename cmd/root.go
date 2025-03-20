package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/supakornn/goscanner/pkg/scanner"
	"github.com/supakornn/goscanner/pkg/utils"
)

var (
	// Scan targets and ports
	target         string
	targetFile     string
	excludeTargets string
	portRange      string
	portFile       string
	excludePorts   string

	// Scan techniques and performance
	timeout        int
	concurrent     int
	protocol       string
	scanTechnique  string
	timingTemplate int

	// Discovery options
	skipHostDiscovery bool
	traceroute        bool

	// Service detection
	serviceDetection bool
	bannerGrab       bool
	osDetection      bool

	// Output options
	outputFormat string
	outputFile   string
	verbose      bool
	debug        bool
	showFiltered bool

	// Advanced options
	sourcePort      int
	fragmentPackets bool
	ttl             int
	decoys          string
	randomTargets   bool
	scriptScan      bool
	scripts         string

	// Nmap integration
	useNmap  bool
	nmapArgs []string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "goscanner [flags] [target] [-- nmap-flags...]",
	Short: "A powerful port scanner written in Go",
	Long: `GoScanner is a feature-rich, high-performance port scanner built in Go.
It provides similar functionality to Nmap but with improved performance using Go's concurrency.

Examples:
  goscanner -t 192.168.1.1
  goscanner -t 192.168.1.0/24 -p 22,80,443 -T 4
  goscanner -t example.com -p 1-1000 -sV -O
  goscanner 192.168.1.1 -- -A -sV -sC    (uses nmap directly)`,
	Example: `  # Basic scan of a single host
  goscanner -t 192.168.1.1

  # Scan specific ports on multiple hosts
  goscanner -t 192.168.1.0/24 -p 22,80,443

  # Full scan with service detection
  goscanner -t example.com -p 1-1000 --service-detection -O
  
  # Use nmap directly with advanced flags
  goscanner 192.168.1.1 -- -A -sV -sC`,
	Args: func(cmd *cobra.Command, args []string) error {
		// Check for -- separator which indicates nmap mode
		for i, arg := range args {
			if arg == "--" {
				if i > 0 {
					// Set first arg before -- as target if not already set
					if target == "" {
						target = args[0]
					}
				}
				if i+1 < len(args) {
					// Store all args after -- as nmap args
					nmapArgs = args[i+1:]
					useNmap = true
				}
				// Remove args from cobra's processing
				cmd.SetArgs(args[:i])
				break
			}
		}

		// If no -- but has at least one argument, treat first as target
		if !useNmap && len(args) > 0 && target == "" {
			target = args[0]
		}

		return nil
	},
	Run: runScan,
}

// Execute adds all child commands to the root command and sets flags appropriately
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Target specification
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target to scan (IP, hostname, CIDR, or range)")
	rootCmd.Flags().StringVar(&targetFile, "iL", "", "Input from list of hosts/networks")
	rootCmd.Flags().StringVar(&excludeTargets, "exclude", "", "Exclude hosts/networks")

	// Port specification
	rootCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1000", "Port ranges to scan (e.g., 22-25,80,443-445)")
	rootCmd.Flags().StringVar(&portFile, "iP", "", "Read port list from file")
	rootCmd.Flags().StringVar(&excludePorts, "exclude-ports", "", "Ports to exclude")

	// Scan techniques
	rootCmd.Flags().StringVar(&scanTechnique, "scan-type", "connect", "Scan technique (connect, syn, fin, xmas, null, ack, udp)")
	rootCmd.Flags().StringVarP(&protocol, "protocol", "P", "tcp", "Protocol to scan (tcp/udp)")

	// Scan timing and performance
	rootCmd.Flags().IntVar(&timeout, "timeout", 300, "Timeout in milliseconds")
	rootCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 500, "Number of concurrent scans")
	rootCmd.Flags().IntVar(&timingTemplate, "timing", 4, "Timing template (0-5)")

	// Host discovery options
	rootCmd.Flags().BoolVarP(&skipHostDiscovery, "skip-host-discovery", "n", false, "Skip host discovery")
	rootCmd.Flags().BoolVarP(&traceroute, "traceroute", "", false, "Trace hop path to target")

	// Service detection
	rootCmd.Flags().BoolVarP(&serviceDetection, "service-detection", "V", false, "Probe open ports for service info")
	rootCmd.Flags().BoolVarP(&bannerGrab, "banner", "b", false, "Perform banner grabbing")
	rootCmd.Flags().BoolVarP(&osDetection, "os-detection", "O", false, "Enable OS detection")

	// Script scanning
	rootCmd.Flags().BoolVarP(&scriptScan, "script", "C", false, "Perform script scanning")
	rootCmd.Flags().StringVar(&scripts, "script-args", "", "Provide arguments to scripts")

	// Output options
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "normal", "Output format (normal, json, xml)")
	rootCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Write output to file")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Increase verbosity level")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debugging")
	rootCmd.Flags().BoolVar(&showFiltered, "show-filtered", false, "Show filtered results")

	// Advanced options
	rootCmd.Flags().IntVar(&sourcePort, "source-port", 0, "Use specified source port")
	rootCmd.Flags().BoolVar(&fragmentPackets, "fragment", false, "Fragment packets")
	rootCmd.Flags().IntVar(&ttl, "ttl", 64, "Set IP time-to-live field")
	rootCmd.Flags().StringVar(&decoys, "decoys", "", "Cloak a scan with decoys (comma-separated)")
	rootCmd.Flags().BoolVarP(&randomTargets, "randomize-hosts", "r", false, "Randomize target scan order")

	// Add groups to organize the help output better
	targetGroup := &cobra.Group{
		ID:    "target",
		Title: "Target Selection:",
	}

	portGroup := &cobra.Group{
		ID:    "port",
		Title: "Port Selection:",
	}

	scanGroup := &cobra.Group{
		ID:    "scan",
		Title: "Scan Techniques:",
	}

	discoveryGroup := &cobra.Group{
		ID:    "discovery",
		Title: "Host Discovery:",
	}

	outputGroup := &cobra.Group{
		ID:    "output",
		Title: "Output Options:",
	}

	rootCmd.AddGroup(targetGroup, portGroup, scanGroup, discoveryGroup, outputGroup)

	// Assign flags to groups
	rootCmd.Flags().SetAnnotation("target", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("iL", "group", []string{"target"})
	// ...Set more flag annotations as needed

	// Add footer with additional help info
	rootCmd.Flags().SortFlags = false
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

// printBanner prints a cool banner
func printBanner() {
	banner := `
 _____       _____                                
|  __ \     / ____|                               
| |  \/ ___ | (___   ___ __ _ _ __  _ __   ___ _ __ 
| | __ / _ \ \___ \ / __/ _' | '_ \| '_ \ / _ \ '__|
| |_\ \ (_) |____) | (_| (_| | | | | | | |  __/ |   
 \____/\___/|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                    
A powerful port scanner written in Go
`
	fmt.Println(banner)
}

// parseScanTechnique converts scan technique string to enum
func parseScanTechnique(technique string) scanner.ScanTechnique {
	switch strings.ToLower(technique) {
	case "syn":
		return scanner.TechSYN
	case "fin":
		return scanner.TechFIN
	case "xmas":
		return scanner.TechXMAS
	case "null":
		return scanner.TechNULL
	case "ack":
		return scanner.TechACK
	case "udp":
		return scanner.TechUDP
	default:
		return scanner.TechConnect
	}
}

// runScan executes the scan based on command line args
func runScan(cmd *cobra.Command, args []string) {
	printBanner()

	// Check if we should use nmap
	if useNmap {
		if target == "" {
			fmt.Println("Error: target is required for nmap mode")
			os.Exit(1)
		}
		runNmapScan(target, nmapArgs)
		return
	}

	// Traditional goscanner mode
	if target == "" && targetFile == "" {
		fmt.Println("Error: target or target-file is required")
		cmd.Help()
		os.Exit(1)
	}

	// Process targets
	targets, err := processTargets()
	if err != nil {
		fmt.Printf("Error processing targets: %v\n", err)
		os.Exit(1)
	}

	// Process ports
	startPort, endPort, err := utils.ParsePortRange(portRange)
	if err != nil {
		fmt.Printf("Error parsing port range: %v\n", err)
		os.Exit(1)
	}

	// Configure scanner options
	scanOptions := buildScanOptions()

	// Print scan info
	printScanInfo(targets, startPort, endPort)

	// Perform the scan
	if len(targets) == 1 {
		performSingleHostScan(targets[0], startPort, endPort, scanOptions)
	} else {
		performMultiHostScan(targets, startPort, endPort, scanOptions)
	}

	// Output to file if specified
	if outputFile != "" {
		fmt.Printf("\nResults written to %s\n", outputFile)
	}
}
