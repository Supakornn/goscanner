// Package scanner provides high-performance port scanning functionality
// with support for multiple scan techniques, service detection, and banner grabbing.
// It's designed for network security assessments, penetration testing, and system administration.
package scanner

import "time"

// ScanTechnique represents the type of scanning technique used for port discovery
type ScanTechnique int

const (
	// TechConnect performs a full TCP connection (3-way handshake)
	TechConnect ScanTechnique = iota
	// TechSYN performs a SYN scan (half-open scanning)
	TechSYN
	// TechFIN performs a FIN scan for firewall evasion
	TechFIN
	// TechXMAS performs a XMAS scan with FIN, URG, and PUSH flags set
	TechXMAS
	// TechNULL performs a NULL scan with no flags set
	TechNULL
	// TechACK performs an ACK scan to map firewall rulesets
	TechACK
	// TechUDP performs UDP scanning for discovering UDP services
	TechUDP
)

// Scanner represents a port scanner with configurable options
// for timeout, concurrency, and various scanning techniques.
type Scanner struct {
	target            string
	timeout           time.Duration
	concurrent        int
	technique         ScanTechnique
	bannerGrab        bool
	serviceDetection  bool
	osDetection       bool
	hostDiscovery     bool
	outputFormat      string
	verbose           bool
	debug             bool
	timingTemplate    int
	fragmentPackets   bool
	sourcePort        int
	ttl               int
	decoys            string
	scriptScan        bool
	scripts           string
	scriptArgs        string
	traceRoute        bool
	randomTargets     bool
	skipHostDiscovery bool
	showFiltered      bool
	ipv4Only          bool  // force IPv4 scanning
	Ports             []int // public for direct access
}

// ScanResult represents the result of scanning a single port.
// It contains information about port state, service, version, and banner.
type ScanResult struct {
	Port     int           // Port number
	State    string        // Status of port: "open", "closed", or "filtered"
	Service  string        // Identified service name
	Version  string        // Service version if detected
	Protocol string        // Protocol used (tcp/udp)
	Banner   string        // Banner information retrieved
	RTT      time.Duration // Round-trip time for the scan
}

// HostResult represents the result of scanning a single host,
// including open/filtered/closed ports and host information.
type HostResult struct {
	IP            string        // IP address of the host
	Hostname      []string      // Resolved hostnames
	Status        string        // Host status (up/down)
	OS            string        // Detected operating system
	OSAccuracy    int           // Accuracy of OS detection (percentage)
	MAC           string        // MAC address if available
	Vendor        string        // Hardware vendor based on MAC
	OpenPorts     []ScanResult  // List of open ports
	FilteredPorts []ScanResult  // List of filtered ports
	ClosedPorts   []ScanResult  // List of closed ports
	RTT           time.Duration // Round-trip time to host
	HopCount      int           // Number of network hops to host
}

// NetworkScan represents a subnet scan containing multiple host results
// and overall statistics about the scan.
type NetworkScan struct {
	CIDR      string        // Target CIDR range
	Hosts     []HostResult  // Results for each host
	StartTime time.Time     // When the scan started
	EndTime   time.Time     // When the scan completed
	Duration  time.Duration // Total scan duration
	HostsUp   int           // Number of hosts found up
	HostsDown int           // Number of hosts found down
}

// ScanOption represents options for configuring a scanner.
// This struct is used when creating a new scanner with advanced options.
type ScanOption struct {
	Timeout           time.Duration // Connection timeout
	Concurrent        int           // Number of concurrent scans
	Technique         ScanTechnique // Scan technique to use
	BannerGrab        bool          // Whether to grab service banners
	ServiceDetection  bool          // Whether to detect services
	OSDetection       bool          // Whether to detect operating systems
	HostDiscovery     bool          // Whether to perform host discovery
	OutputFormat      string        // Output format (normal, json, xml)
	Verbose           bool          // Verbose output
	Debug             bool          // Debug output
	TimingTemplate    int           // Timing template (0-5)
	FragmentPackets   bool          // Whether to fragment packets
	SourcePort        int           // Custom source port
	TTL               int           // Time-to-live value
	Decoys            string        // Decoy addresses to use
	ScriptScan        bool          // Whether to run scripts
	Scripts           string        // Scripts to run
	ScriptArgs        string        // Script arguments
	TraceRoute        bool          // Whether to perform traceroute
	RandomTargets     bool          // Whether to randomize targets
	SkipHostDiscovery bool          // Whether to skip host discovery
	ShowFiltered      bool          // Whether to show filtered ports
	IPv4Only          bool          // Force IPv4 only mode
	Ports             []int         // Specific ports to scan
}
