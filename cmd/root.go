package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/supakornn/goscanner/pkg/utils"
)

var (
	// scan targets and ports
	target         string
	targetFile     string
	excludeTargets string
	portRange      string
	specificPorts  string
	portFile       string
	excludePorts   string

	// scan techniques and performance
	timeout        int
	concurrent     int
	protocol       string
	scanTechnique  string = "syn" // default to SYN scan
	timingTemplate int
	ipv4Only       bool // force IPv4 scanning

	// discovery options
	skipHostDiscovery bool
	noPing            bool
	traceroute        bool

	// service detection
	serviceDetection bool
	bannerGrab       bool
	osDetection      bool
	aggressiveScan   bool

	// output options
	outputFormat string
	outputFile   string
	verbose      bool
	debug        bool
	showFiltered bool

	// advanced options
	sourcePort      int
	fragmentPackets bool
	ttl             int
	decoys          string
	randomTargets   bool
	scriptScan      bool
	scripts         string

	// nmap integration
	useNmap   bool
	nmapArgs  []string
	autoNmap  bool
	noNmap    bool
	nmapFlags string
)

// root command
var rootCmd = &cobra.Command{
	Use:   "goscanner [flags] [target] [-- nmap-flags...]",
	Short: "A powerful port scanner written in Go",
	Long:  `GoScanner is an ultra-fast, high-performance port scanner built in Go.`,

	Args: func(cmd *cobra.Command, args []string) error {
		// check for -- separator which indicates nmap mode
		for i, arg := range args {
			if arg == "--" {
				if i > 0 {
					// set first arg before -- as target if not already set
					if target == "" {
						target = args[0]
					}
				}
				if i+1 < len(args) {
					// store all args after -- as nmap args
					nmapArgs = args[i+1:]
					useNmap = true
				}
				// remove args from cobra's processing
				cmd.SetArgs(args[:i])
				break
			}
		}

		// if no -- but has at least one argument, treat first as target
		if !useNmap && len(args) > 0 && target == "" {
			target = args[0]
		}

		return nil
	},
	Run: runScan,
}

// execute adds all child commands to the root command and sets flags appropriately
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// add help flag explicitly
	rootCmd.Flags().BoolP("help", "h", false, "Display help information")

	// target options
	rootCmd.Flags().StringVarP(&target, "target", "t", "", "target to scan (IP, hostname, CIDR)")
	rootCmd.Flags().StringVar(&targetFile, "target-file", "", "file containing targets (one per line)")
	rootCmd.Flags().StringVar(&excludeTargets, "exclude", "", "exclude targets (comma-separated)")

	// port options - default to all ports
	rootCmd.Flags().StringVarP(&portRange, "port-range", "p", "1-65535", "port range (e.g. 1-65535)")
	rootCmd.Flags().StringVar(&specificPorts, "ports", "", "specific ports to scan (comma-separated)")
	rootCmd.Flags().StringVar(&portFile, "port-file", "", "file containing ports (one per line)")
	rootCmd.Flags().StringVar(&excludePorts, "exclude-ports", "", "exclude ports (comma-separated)")

	// performance options
	rootCmd.Flags().IntVarP(&timeout, "timeout", "z", 50, "timeout in milliseconds (default: 50 - ultra-fast)")
	rootCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 65535, "number of concurrent connections (default: 65535 - maximum)")
	rootCmd.Flags().StringVarP(&protocol, "protocol", "P", "tcp", "protocol (tcp, udp)")
	rootCmd.Flags().StringVarP(&scanTechnique, "scan-technique", "s", "syn", "scan technique (connect, syn, fin, xmas, null)")
	rootCmd.Flags().IntVarP(&timingTemplate, "timing", "T", 5, "timing template (0-5, higher is faster)")

	// host discovery options
	rootCmd.Flags().BoolVarP(&skipHostDiscovery, "skip-host-discovery", "n", true, "skip host discovery (default: true for optimized speed)")
	rootCmd.Flags().BoolVarP(&noPing, "no-ping", "N", true, "skip ICMP ping discovery (default: true for optimized speed)")
	rootCmd.Flags().BoolVar(&traceroute, "traceroute", false, "perform traceroute to targets")

	// service detection
	rootCmd.Flags().BoolVarP(&serviceDetection, "service-detection", "V", false, "probe open ports for service info")
	rootCmd.Flags().BoolVarP(&bannerGrab, "banner", "b", false, "perform banner grabbing")
	rootCmd.Flags().BoolVarP(&osDetection, "os-detection", "O", false, "enable OS detection")
	rootCmd.Flags().BoolVarP(&aggressiveScan, "aggressive", "A", false, "Enable aggressive scan (service + OS detection)")

	// script scanning
	rootCmd.Flags().BoolVarP(&scriptScan, "script", "C", false, "perform script scanning")
	rootCmd.Flags().StringVar(&scripts, "script-args", "", "provide arguments to scripts")

	// output options
	rootCmd.Flags().StringVarP(&outputFormat, "output-format", "o", "normal", "output format (normal, json, xml)")
	rootCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "write output to file")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "increase verbosity level")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "enable debugging")
	rootCmd.Flags().BoolVarP(&showFiltered, "show-filtered", "F", false, "show filtered ports in results")

	// advanced options
	rootCmd.Flags().IntVar(&sourcePort, "source-port", 0, "use specified source port")
	rootCmd.Flags().BoolVar(&fragmentPackets, "fragment", false, "fragment packets")
	rootCmd.Flags().IntVar(&ttl, "ttl", 64, "set IP time-to-live field")
	rootCmd.Flags().StringVar(&decoys, "decoys", "", "cloak a scan with decoys (comma-separated)")
	rootCmd.Flags().BoolVar(&randomTargets, "randomize-hosts", false, "randomize target scan order")

	// Nmap integration
	rootCmd.Flags().BoolVar(&autoNmap, "nmap", true, "Automatically run Nmap on open ports (default: true)")
	rootCmd.Flags().BoolVar(&noNmap, "no-nmap", false, "disable automatic Nmap scanning")
	rootCmd.Flags().StringVar(&nmapFlags, "nmap-flags", "-sC -sV", "flags to pass to Nmap when using --nmap")

	// ipv4 only flag
	rootCmd.Flags().BoolVarP(&ipv4Only, "ipv4", "4", false, "force IPv4 scanning only")

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

	// assign flags to groups
	rootCmd.Flags().SetAnnotation("target", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("target-file", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("exclude", "group", []string{"target"})
	rootCmd.Flags().SetAnnotation("p", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("P", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("port-file", "group", []string{"port"})
	rootCmd.Flags().SetAnnotation("exclude-ports", "group", []string{"port"})

	// add footer with additional help info
	rootCmd.Flags().SortFlags = false
}

// prints a cool banner
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
	fmt.Printf("Starting GoScanner")
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

// returns a summary of targets
func getTargetSummary() string {
	if targetFile != "" {
		return fmt.Sprintf("from file %s", targetFile)
	} else if target != "" {
		// count hosts in target spec
		targets, err := processTargets()
		if err == nil {
			return fmt.Sprintf("%d hosts", len(targets))
		}
	}
	return "unspecified"
}

// returns a summary of ports
func getPortSummary() string {
	if specificPorts != "" {
		return specificPorts
	} else if portRange != "" {
		// if portRange has commas, it's a comma-separated list, not a range
		if strings.Contains(portRange, ",") {
			ports, err := utils.ParseSpecificPorts(portRange)
			if err == nil && len(ports) > 0 {
				return fmt.Sprintf("%s (%d ports)", portRange, len(ports))
			}
		}
		return portRange
	}
	return "1-65535"
}

// executes the main scan functionality
func runScan(cmd *cobra.Command, args []string) {
	printBanner()

	// process aggressive scan option
	if aggressiveScan {
		serviceDetection = true
		osDetection = true
	}

	// if noNmap flag is set, disable autoNmap
	if noNmap {
		autoNmap = false
	}

	// check if we should use nmap
	if useNmap {
		if target == "" {
			fmt.Println("Error: target is required for nmap mode")
			os.Exit(1)
		}
		runNmapScan(target, nmapArgs)
		return
	}

	// traditional goscanner mode
	if target == "" && targetFile == "" {
		fmt.Println("Error: target or target-file is required")
		cmd.Help()
		os.Exit(1)
	}

	// process targets
	targets, err := processTargets()
	if err != nil {
		fmt.Printf("Error processing targets: %v\n", err)
		os.Exit(1)
	}

	// process ports
	var ports []int
	startPort := 1
	endPort := 65535

	// debug info before port processing
	if debug {
		fmt.Printf("DEBUG: Before processing - specificPorts: %s, portRange: %s\n", specificPorts, portRange)
	}

	// parse specific ports
	if specificPorts != "" {
		ports, err = utils.ParseSpecificPorts(specificPorts)
		if err != nil {
			fmt.Printf("Error parsing specific ports: %v\n", err)
			os.Exit(1)
		}

		// update startPort and endPort for display only
		if len(ports) > 0 {
			startPort = ports[0]
			endPort = ports[len(ports)-1]
		}

		if debug {
			fmt.Printf("DEBUG: Parsed specific ports: %v (count: %d)\n", ports, len(ports))
		}
	} else if portRange != "" {
		// check if portRange contains commas, which would indicate individual ports, not a range
		if strings.Contains(portRange, ",") {
			// treat as comma-separated list of ports
			ports, err = utils.ParseSpecificPorts(portRange)
			if err != nil {
				fmt.Printf("Error parsing specific ports from -p: %v\n", err)
				os.Exit(1)
			}

			// update startPort and endPort for display only
			if len(ports) > 0 {
				startPort = ports[0]
				endPort = ports[len(ports)-1]
			}

			if debug {
				fmt.Printf("DEBUG: Parsed comma-separated ports from -p: %v (count: %d)\n", ports, len(ports))
			}
		} else {
			// check if it's a range (like 1-1000)
			startPort, endPort, err = utils.ParsePortRange(portRange)
			if err != nil {
				fmt.Printf("Error parsing port range: %v\n", err)
				os.Exit(1)
			}

			// handle special case of single port specified as range (e.g., 22-22)
			if startPort == endPort {
				ports = []int{startPort}
			} else {
				// generate list of all ports in range with step=1
				ports = make([]int, 0, endPort-startPort+1)
				for port := startPort; port <= endPort; port++ {
					ports = append(ports, port)
				}
			}

			if debug {
				fmt.Printf("DEBUG: Parsed port range: %d-%d (count: %d)\n", startPort, endPort, len(ports))
			}
		}
	} else {
		// default to full port range
		startPort, endPort, _ = utils.ParsePortRange("1-65535")

		ports = make([]int, 0, endPort-startPort+1)
		for port := startPort; port <= endPort; port++ {
			ports = append(ports, port)
		}

		if debug {
			fmt.Printf("DEBUG: Using default port range: %d-%d (count: %d)\n", startPort, endPort, len(ports))
		}
	}

	// debug info after port processing
	if verbose || debug {
		if len(ports) <= 20 {
			fmt.Println("Ports to scan:", ports)
		} else {
			fmt.Printf("Ports to scan: %d ports from %d to %d\n", len(ports), ports[0], ports[len(ports)-1])
		}
	}

	// configure scanner options
	scanOptions := buildScanOptions()

	// both skipHostDiscovery and noPing should have the same effect
	if noPing {
		scanOptions.SkipHostDiscovery = true
	}

	// show filtered ports if requested
	scanOptions.ShowFiltered = showFiltered || verbose

	// pass scanner ports to options
	scanOptions.Ports = ports

	if debug {
		fmt.Printf("DEBUG: Final port count in options: %d\n", len(scanOptions.Ports))
	}

	// perform scan
	if len(targets) == 1 {
		performSingleHostScan(targets[0], startPort, endPort, scanOptions)
	} else {
		performMultiHostScan(targets, startPort, endPort, scanOptions)
	}

	// output to file if specified
	if outputFile != "" {
		fmt.Printf("\nResults written to %s\n", outputFile)
	}
}
