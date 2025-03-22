package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/supakornn/goscanner/pkg/utils"
)

var (
	// Scan targets and ports
	target         string
	targetFile     string
	excludeTargets string
	portRange      string
	specificPorts  string
	portFile       string
	excludePorts   string

	// Scan techniques and performance
	timeout        int
	concurrent     int
	protocol       string
	scanTechnique  string = "syn" // Default to SYN scan since we're using half-open technique
	timingTemplate int
	ipv4Only       bool // Force IPv4 scanning

	// Discovery options
	skipHostDiscovery bool
	noPing            bool
	traceroute        bool

	// Service detection
	serviceDetection bool
	bannerGrab       bool
	osDetection      bool
	aggressiveScan   bool

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
	useNmap   bool
	nmapArgs  []string
	autoNmap  bool
	noNmap    bool
	nmapFlags string
)

// Root command
var rootCmd = &cobra.Command{
	Use:   "goscanner [flags] [target] [-- nmap-flags...]",
	Short: "A powerful port scanner written in Go",
	Long: `GoScanner is an ultra-fast, high-performance port scanner built in Go.

- Blazing fast scans with half-open TCP connections
- Ultra-minimal timeout (15μs) for maximum throughput  
- Full IPv6 support
- Adaptive concurrency with up to 65,000 simultaneous workers
- Smart port prioritization (scans common ports first)
- Early exit after finding sufficient open ports
- Memory-optimized for minimal allocations
- Accurate state detection (open/closed/filtered)
- Automatic Nmap integration for service detection`,
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
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add help flag explicitly
	rootCmd.Flags().BoolP("help", "h", false, "Display help information")

	// Target options
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target to scan (IP, hostname, CIDR)")
	rootCmd.Flags().StringVar(&targetFile, "target-file", "", "File containing targets (one per line)")
	rootCmd.Flags().StringVar(&excludeTargets, "exclude", "", "Exclude targets (comma-separated)")

	// Port options - Default to all ports instead of just 1000
	rootCmd.Flags().StringVarP(&portRange, "port-range", "p", "1-65535", "Port range (e.g. 1-1000)")
	rootCmd.Flags().StringVar(&specificPorts, "ports", "", "Specific ports to scan (comma-separated)")
	rootCmd.Flags().StringVar(&portFile, "port-file", "", "File containing ports (one per line)")
	rootCmd.Flags().StringVar(&excludePorts, "exclude-ports", "", "Exclude ports (comma-separated)")

	// Performance options
	rootCmd.Flags().IntVarP(&timeout, "timeout", "z", 1000, "Timeout in milliseconds")
	rootCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 5000, "Number of concurrent connections (default: 5000)")
	rootCmd.Flags().StringVarP(&protocol, "protocol", "P", "tcp", "Protocol (tcp, udp)")
	rootCmd.Flags().StringVarP(&scanTechnique, "scan-technique", "s", "syn", "Scan technique (connect, syn, fin, xmas, null)")
	rootCmd.Flags().IntVarP(&timingTemplate, "timing", "T", 5, "Timing template (0-5, higher is faster)")

	// Host discovery options
	rootCmd.Flags().BoolVarP(&skipHostDiscovery, "skip-host-discovery", "n", false, "Skip host discovery")
	rootCmd.Flags().BoolVarP(&noPing, "no-ping", "N", false, "Skip ICMP ping discovery (treat all hosts as online)")
	rootCmd.Flags().BoolVar(&traceroute, "traceroute", false, "Perform traceroute to targets")

	// Service detection
	rootCmd.Flags().BoolVarP(&serviceDetection, "service-detection", "V", false, "Probe open ports for service info")
	rootCmd.Flags().BoolVarP(&bannerGrab, "banner", "b", false, "Perform banner grabbing")
	rootCmd.Flags().BoolVarP(&osDetection, "os-detection", "O", false, "Enable OS detection")
	rootCmd.Flags().BoolVarP(&aggressiveScan, "aggressive", "A", false, "Enable aggressive scan (service + OS detection)")

	// Script scanning
	rootCmd.Flags().BoolVarP(&scriptScan, "script", "C", false, "Perform script scanning")
	rootCmd.Flags().StringVar(&scripts, "script-args", "", "Provide arguments to scripts")

	// Output options
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "normal", "Output format (normal, json, xml)")
	rootCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Write output to file")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Increase verbosity level")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debugging")
	rootCmd.Flags().BoolVarP(&showFiltered, "show-filtered", "F", false, "Show filtered ports in results")

	// Advanced options
	rootCmd.Flags().IntVar(&sourcePort, "source-port", 0, "Use specified source port")
	rootCmd.Flags().BoolVar(&fragmentPackets, "fragment", false, "Fragment packets")
	rootCmd.Flags().IntVar(&ttl, "ttl", 64, "Set IP time-to-live field")
	rootCmd.Flags().StringVar(&decoys, "decoys", "", "Cloak a scan with decoys (comma-separated)")
	rootCmd.Flags().BoolVar(&randomTargets, "randomize-hosts", false, "Randomize target scan order")

	// Nmap integration
	rootCmd.Flags().BoolVar(&autoNmap, "nmap", true, "Automatically run Nmap on open ports (default: true)")
	rootCmd.Flags().BoolVar(&noNmap, "no-nmap", false, "Disable automatic Nmap scanning")
	rootCmd.Flags().StringVar(&nmapFlags, "nmap-flags", "-sC -sV", "Flags to pass to Nmap when using --nmap")

	// Add IPv4 only flag
	rootCmd.Flags().BoolVarP(&ipv4Only, "ipv4", "4", false, "Force IPv4 scanning only")

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
	rootCmd.Flags().SetAnnotation("target-file", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("exclude", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("p", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("P", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("port-file", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("exclude-ports", "group", []string{"port"})

	// Add footer with additional help info
	rootCmd.Flags().SortFlags = false
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
                                                    `
	fmt.Println(banner)
	fmt.Println("A powerful port scanner written in Go")

	fmt.Printf("Starting GoScanner 1.0 at %s\n", time.Now().Format("Mon, 02 Jan 2006 15:04:05 -07"))
	fmt.Println("Scan configuration:")
	fmt.Printf("  - Targets: %s\n", getTargetSummary())
	fmt.Printf("  - Ports: %s\n", getPortSummary())
	fmt.Printf("  - Scan technique: %s\n", scanTechnique)
	fmt.Printf("  - Timing template: T%d\n", timingTemplate)
	fmt.Printf("  - Service detection: %t\n", serviceDetection)
	fmt.Printf("  - OS detection: %t\n", osDetection)
	fmt.Printf("  - Host discovery: %t\n", !skipHostDiscovery)
	fmt.Println()
}

// getTargetSummary returns a summary of targets
func getTargetSummary() string {
	if targetFile != "" {
		return fmt.Sprintf("from file %s", targetFile)
	} else if target != "" {
		// Count hosts in target spec
		targets, err := processTargets()
		if err == nil {
			return fmt.Sprintf("%d hosts", len(targets))
		}
	}
	return "unspecified"
}

// getPortSummary returns a summary of ports
func getPortSummary() string {
	if specificPorts != "" {
		return specificPorts
	} else if portRange != "" {
		return portRange
	}
	return "1-65535"
}

func runScan(cmd *cobra.Command, args []string) {
	printBanner()

	// Process aggressive scan option
	if aggressiveScan {
		serviceDetection = true
		osDetection = true
	}

	// If noNmap flag is set, disable autoNmap
	if noNmap {
		autoNmap = false
	}

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
	var ports []int
	if specificPorts != "" {
		// Parse specific ports (comma-separated list)
		ports, err = utils.ParseSpecificPorts(specificPorts)
		if err != nil {
			fmt.Printf("Error parsing specific ports: %v\n", err)
			os.Exit(1)
		}
	} else if portRange != "" {
		// Parse port range (like 1-1000)
		startPort, endPort, err := utils.ParsePortRange(portRange)
		if err != nil {
			fmt.Printf("Error parsing port range: %v\n", err)
			os.Exit(1)
		}

		// Handle special case of single port specified as range (e.g., 22-22)
		if startPort == endPort {
			ports = []int{startPort}
		} else {
			// Generate list of all ports in range with step=1
			ports = make([]int, 0, endPort-startPort+1)
			for port := startPort; port <= endPort; port++ {
				ports = append(ports, port)
			}
		}
	} else {
		// Default port range if neither specific ports nor port range is specified
		// Use a smaller default range for faster scanning
		startPort, endPort, _ := utils.ParsePortRange("1-1000")
		ports = make([]int, 0, endPort-startPort+1)
		for port := startPort; port <= endPort; port++ {
			ports = append(ports, port)
		}
	}

	// Verify we have the correct ports for debugging
	if verbose || debug {
		if len(ports) <= 20 {
			fmt.Println("Ports to scan:", ports)
		} else {
			fmt.Printf("Ports to scan: %d ports from %d to %d\n", len(ports), ports[0], ports[len(ports)-1])
		}
	}

	// Configure scanner options
	scanOptions := buildScanOptions()

	// Both skipHostDiscovery and noPing should have the same effect
	if noPing {
		scanOptions.SkipHostDiscovery = true
	}

	// Set ShowFiltered based on user flags - should only show filtered ports if requested
	scanOptions.ShowFiltered = showFiltered || verbose

	// Pass the user-specified ports to the scanner options
	scanOptions.Ports = ports

	// Print scan info
	startPort := ports[0]
	endPort := ports[len(ports)-1]
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
