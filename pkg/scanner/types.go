package scanner

import "time"

// ScanTechnique represents the type of scanning technique
type ScanTechnique int

const (
	// TCP connect scan
	TechConnect ScanTechnique = iota
	// SYN scan (half-open)
	TechSYN
	// FIN scan
	TechFIN
	// XMAS scan
	TechXMAS
	// NULL scan
	TechNULL
	// ACK scan
	TechACK
	// UDP scan
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
	ipv4Only          bool  // force IPv4 scanning
	Ports             []int // public for direct access
}

// represents the result of scanning a single port
type ScanResult struct {
	Port     int
	State    string
	Service  string
	Version  string
	Protocol string
	Banner   string
	RTT      time.Duration
}

// represents the result of scanning a single host
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

// represents a subnet scan
type NetworkScan struct {
	CIDR      string
	Hosts     []HostResult
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	HostsUp   int
	HostsDown int
}

// represents options for the scanner
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
