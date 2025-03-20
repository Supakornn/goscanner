package scanner

import "time"

// ScanTechnique represents different scan techniques
type ScanTechnique string

const (
	TechConnect ScanTechnique = "connect"
	TechSYN     ScanTechnique = "syn"
	TechFIN     ScanTechnique = "fin"
	TechXMAS    ScanTechnique = "xmas"
	TechNULL    ScanTechnique = "null"
	TechACK     ScanTechnique = "ack"
	TechUDP     ScanTechnique = "udp"
)

// ScanResult represents the result of a port scan with extended information
type ScanResult struct {
	Port            int
	State           string
	Service         string
	Version         string
	Banner          string
	RTT             time.Duration
	Protocol        string
	Confidence      int // Version detection confidence (0-10)
	ExtraInfo       string
	CPE             string // Common Platform Enumeration
	TTL             int
	WindowSize      int
	Fingerprint     string // TCP/IP fingerprint
	TcpFlags        string
	TcpSequence     string
	IPIDSequence    string
	TcpTimestampSeq string
	TcpOptions      []string
}

// HostResult represents a host scan result
type HostResult struct {
	IP            string
	Hostname      []string
	Status        string // up or down
	MAC           string
	Vendor        string
	OS            string
	OSAccuracy    int // 0-100
	OSClass       []string
	RTT           time.Duration
	HopCount      int
	OpenPorts     []ScanResult
	FilteredPorts []ScanResult
	ClosedPorts   []ScanResult
	LastBoot      time.Duration
	Distance      int // traceroute distance
	ICMP          bool
	TCPPorts      []int // Ports that responded to TCP ping
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

// ScanOption represents the options for scanning
type ScanOption struct {
	Technique         ScanTechnique
	Timeout           time.Duration
	Concurrent        int
	BannerGrab        bool
	ServiceDetection  bool
	OSDetection       bool
	HostDiscovery     bool
	IPProtocol        string // IPv4, IPv6, or both
	OutputFormat      string // normal, json, xml
	Verbose           bool
	Debug             bool
	TimingTemplate    int // 0-5 (paranoid to insane)
	FragmentPackets   bool
	SourcePort        int
	TTL               int
	Decoys            []string // Decoy IPs
	ScriptScan        bool
	Scripts           []string
	ScriptArgs        map[string]string
	TraceRoute        bool
	RandomTargets     bool
	SkipHostDiscovery bool
	ShowFiltered      bool // Whether to include filtered ports in the results
}

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
	decoys            []string
	scriptScan        bool
	scripts           []string
	scriptArgs        map[string]string
	traceRoute        bool
	randomTargets     bool
	skipHostDiscovery bool
	showFiltered      bool // Whether to include filtered ports in the results
}
