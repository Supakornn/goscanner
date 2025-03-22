package scanner

import "time"

// ScanTechnique represents the type of scanning technique
type ScanTechnique int

const (
	// TechConnect is a basic TCP connect scan
	TechConnect ScanTechnique = iota
	// TechSYN is a SYN scan (half-open)
	TechSYN
	// TechFIN is a FIN scan
	TechFIN
	// TechXMAS is a XMAS scan
	TechXMAS
	// TechNULL is a NULL scan
	TechNULL
	// TechACK is an ACK scan
	TechACK
	// TechUDP is a UDP scan
	TechUDP
)

// Scanner represents a port scanner
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
	ipv4Only          bool  // Force IPv4 scanning
	Ports             []int // Public for direct access
}

// ScanResult represents the result of scanning a single port
type ScanResult struct {
	Port     int
	State    string
	Service  string
	Version  string
	Protocol string
	Banner   string
	RTT      time.Duration
}

// HostResult represents the result of scanning a single host
type HostResult struct {
	IP            string
	Hostname      []string
	Status        string
	OS            string
	OSAccuracy    int
	MAC           string
	Vendor        string
	OpenPorts     []ScanResult
	FilteredPorts []ScanResult
	ClosedPorts   []ScanResult
	RTT           time.Duration
	HopCount      int // Added for traceroute functionality
}

// NetworkScan represents a subnet scan
type NetworkScan struct {
	CIDR      string
	Hosts     []HostResult
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	HostsUp   int
	HostsDown int
}

// ScanOption represents options for the scanner
type ScanOption struct {
	Timeout           time.Duration
	Concurrent        int
	Technique         ScanTechnique
	BannerGrab        bool
	ServiceDetection  bool
	OSDetection       bool
	HostDiscovery     bool
	OutputFormat      string
	Verbose           bool
	Debug             bool
	TimingTemplate    int
	FragmentPackets   bool
	SourcePort        int
	TTL               int
	Decoys            string
	ScriptScan        bool
	Scripts           string
	ScriptArgs        string
	TraceRoute        bool
	RandomTargets     bool
	SkipHostDiscovery bool
	ShowFiltered      bool
	IPv4Only          bool // Force IPv4 only mode
	Ports             []int
}
