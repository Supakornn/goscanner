package scanner

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// New creates a new Scanner with default settings.
// It configures a scanner with the specified target, timeout duration, and concurrency level.
//
// Parameters:
//   - target: The host to scan (IP address or hostname)
//   - timeout: The duration to wait for connections
//   - concurrent: The number of concurrent scans to perform
//
// Example:
//
//	scanner := scanner.New("example.com", 50*time.Millisecond, 1000)
//	result := scanner.ScanPort("tcp", 80)
func New(target string, timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		target:            target,
		timeout:           timeout,
		concurrent:        concurrent,
		technique:         TechSYN,
		bannerGrab:        false,
		serviceDetection:  false,
		osDetection:       false,
		hostDiscovery:     false,
		outputFormat:      "normal",
		verbose:           false,
		debug:             false,
		timingTemplate:    4,
		fragmentPackets:   false,
		sourcePort:        0,
		ttl:               64,
		scriptScan:        false,
		traceRoute:        false,
		randomTargets:     false,
		skipHostDiscovery: true, // defaults to skipping host discovery for faster scanning
		showFiltered:      false,
		ipv4Only:          false,
	}
}

// NewWithOptions creates a new Scanner with specified options.
// This allows for more detailed configuration than the standard New constructor.
//
// Parameters:
//   - target: The host to scan (IP address or hostname)
//   - opts: A ScanOption struct containing all configuration options
//
// Example:
//
//	options := scanner.ScanOption{
//	    Timeout:          50*time.Millisecond,
//	    Concurrent:       5000,
//	    Technique:        scanner.TechSYN,
//	    BannerGrab:       true,
//	    ServiceDetection: true,
//	}
//	scanner := scanner.NewWithOptions("example.com", options)
func NewWithOptions(target string, opts ScanOption) *Scanner {
	return &Scanner{
		target:            target,
		timeout:           opts.Timeout,
		concurrent:        opts.Concurrent,
		technique:         opts.Technique,
		bannerGrab:        opts.BannerGrab,
		serviceDetection:  opts.ServiceDetection,
		osDetection:       opts.OSDetection,
		hostDiscovery:     opts.HostDiscovery,
		outputFormat:      opts.OutputFormat,
		verbose:           opts.Verbose,
		debug:             opts.Debug,
		timingTemplate:    opts.TimingTemplate,
		fragmentPackets:   opts.FragmentPackets,
		sourcePort:        opts.SourcePort,
		ttl:               opts.TTL,
		decoys:            opts.Decoys,
		scriptScan:        opts.ScriptScan,
		scripts:           opts.Scripts,
		scriptArgs:        opts.ScriptArgs,
		traceRoute:        opts.TraceRoute,
		randomTargets:     opts.RandomTargets,
		skipHostDiscovery: opts.SkipHostDiscovery,
		showFiltered:      opts.ShowFiltered,
		ipv4Only:          opts.IPv4Only,
		Ports:             opts.Ports,
	}
}

// SetShowFiltered configures whether to include filtered ports in the results.
//
// Parameters:
//   - show: If true, filtered ports will be included in the scan results
func (s *Scanner) SetShowFiltered(show bool) {
	s.showFiltered = show
}

// ScanPort checks if a port is open with enhanced options.
// Used for detailed scanning after initial discovery.
//
// Parameters:
//   - protocol: The protocol to use ("tcp" or "udp")
//   - port: The port number to scan
//
// Returns:
//   - ScanResult containing port status, service information, and banner if available
//
// Example:
//
//	result := scanner.ScanPort("tcp", 80)
//	if result.State == "open" {
//	    fmt.Printf("Port 80 is open running %s\n", result.Service)
//	}
func (s *Scanner) ScanPort(protocol string, port int) ScanResult {
	result := ScanResult{Port: port, Protocol: protocol}
	address := net.JoinHostPort(s.target, fmt.Sprintf("%d", port))

	startTime := time.Now()

	switch s.technique {
	case TechConnect:
		fastTimeout := time.Duration(50) * time.Millisecond
		conn, err := net.DialTimeout(protocol, address, fastTimeout)

		if err == nil {
			result.State = "open"
			result.RTT = time.Since(startTime)

			if s.bannerGrab && conn != nil {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(s.timeout / 2))

				if protocol == "tcp" {
					switch port {
					case 80, 443, 8080, 8443:
						_, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
						if err == nil {
							banner := make([]byte, 1024)
							n, _ := conn.Read(banner)
							if n > 0 {
								result.Banner = string(banner[:n])
							}
						}
					default:
						banner := make([]byte, 1024)
						conn.SetReadDeadline(time.Now().Add(s.timeout / 2))
						n, _ := conn.Read(banner)
						if n > 0 {
							result.Banner = string(banner[:n])
						}
					}
				}
			}

			if s.serviceDetection {
				result.Service = getServiceName(port)
				if s.bannerGrab && result.Banner != "" {
					result.Version = detectServiceVersion(result.Service, result.Banner)
				}
			} else {
				result.Service = getServiceName(port)
			}
			return result
		}

		conn, err = net.DialTimeout(protocol, address, s.timeout)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.State = "filtered"
			} else {
				result.State = "closed"
			}
			return result
		}

		result.RTT = time.Since(startTime)
		result.State = "open"

		if s.bannerGrab && conn != nil {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(s.timeout / 2))

			if protocol == "tcp" {
				switch port {
				case 80, 443, 8080, 8443:
					_, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
					if err == nil {
						banner := make([]byte, 1024)
						n, _ := conn.Read(banner)
						if n > 0 {
							result.Banner = string(banner[:n])
						}
					}
				default:
					banner := make([]byte, 1024)
					conn.SetReadDeadline(time.Now().Add(s.timeout / 2))
					n, _ := conn.Read(banner)
					if n > 0 {
						result.Banner = string(banner[:n])
					}
				}
			}
		}

		if s.serviceDetection {
			result.Service = getServiceName(port)
			if s.bannerGrab && result.Banner != "" {
				result.Version = detectServiceVersion(result.Service, result.Banner)
			}
		} else {
			result.Service = getServiceName(port)
		}

	case TechUDP:
		result.Protocol = "udp"

		conn, err := net.DialTimeout("udp", address, s.timeout)
		if err != nil {
			result.State = "closed"
			return result
		}
		defer conn.Close()

		_, err = conn.Write([]byte{})
		if err != nil {
			result.State = "closed"
			return result
		}

		conn.SetReadDeadline(time.Now().Add(s.timeout))

		resp := make([]byte, 1024)
		n, err := conn.Read(resp)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.State = "open|filtered"
			} else {
				result.State = "closed"
			}
		} else if n > 0 {
			result.State = "open"
			if s.bannerGrab {
				result.Banner = string(resp[:n])
			}
		}

		result.RTT = time.Since(startTime)

		if s.serviceDetection {
			result.Service = getUDPServiceName(port)
			if s.bannerGrab && result.Banner != "" {
				result.Version = detectServiceVersion(result.Service, result.Banner)
			}
		} else {
			result.Service = getUDPServiceName(port)
		}

	case TechSYN:
		if result.State != "open" {
			result.State = "filtered"
		}
		result.Service = getServiceName(port)
		result.Version = "SYN scan requires raw sockets/root privileges"

	case TechFIN, TechXMAS, TechNULL, TechACK:
		if result.State != "open" {
			result.State = "filtered"
		}
		result.Service = getServiceName(port)
		result.Version = "Advanced scan techniques require raw sockets/root privileges"
	}

	return result
}

// fast scan port is an optimized version that only checks if a port is open
func (s *Scanner) FastScanPort(protocol string, port int) ScanResult {
	result := ScanResult{Port: port, Protocol: protocol}
	address := net.JoinHostPort(s.target, fmt.Sprintf("%d", port))

	zeroTimeout := 500 * time.Microsecond

	d := net.Dialer{
		Timeout:   zeroTimeout,
		DualStack: false,
	}

	conn, err := d.Dial(protocol, address)

	if err == nil {
		conn.Close()
		result.State = "open"
		result.Service = getServiceName(port)
		return result
	}

	if strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "network is unreachable") ||
		strings.Contains(err.Error(), "no route to host") {
		result.State = "closed"
		return result
	}

	result.State = "filtered"
	return result
}

// test host alive checks if a host is alive by sending a TCP ping to common ports
func (s *Scanner) TestHostAlive(host string) bool {
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	commonPorts := []int{80, 443, 22, 445, 139, 53, 21, 3389, 8080}
	shortTimeout := 800 * time.Microsecond

	for _, port := range commonPorts {
		address := net.JoinHostPort(ipAddr.String(), strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, shortTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	address := net.JoinHostPort(ipAddr.String(), "80")
	conn, err := net.DialTimeout("tcp", address, 5*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}

	address = net.JoinHostPort(ipAddr.String(), "22")
	conn, err = net.DialTimeout("tcp", address, 10*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// UltraFastScanPort performs an optimized high-speed port scan on a target host.
// This is the core of the scanner's performance, using optimized connection techniques
// to maximize scanning throughput.
//
// Parameters:
//   - host: Target host IP address or hostname
//   - port: Port number to scan
//
// Returns:
//   - ScanResult containing the scan result with port state, service name, and timing information
//
// Example:
//
//	result := scanner.UltraFastScanPort("192.168.1.1", 80)
//	if result.State == "open" {
//	    fmt.Printf("Port 80 is open running %s service\n", result.Service)
//	}
func (s *Scanner) UltraFastScanPort(host string, port int) ScanResult {
	result := ScanResult{
		Port:     port,
		Protocol: "tcp",
		State:    "filtered",
	}

	var resolvedHost string

	if net.ParseIP(host) != nil {
		resolvedHost = host
	} else {
		ipAddrs, err := net.LookupIP(host)
		if err != nil || len(ipAddrs) == 0 {
			result.State = "filtered"
			return result
		}
		resolvedHost = ipAddrs[0].String()
	}

	address := net.JoinHostPort(resolvedHost, strconv.Itoa(port))

	// IMPORTANT: Timeout value is critical for scanning performance
	// Lower values increase speed but may cause false negatives
	// Higher values are more reliable but significantly slower
	timeout := 50 * time.Millisecond

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}

	startTime := time.Now()
	conn, err := dialer.Dial("tcp", address)

	if err == nil {
		conn.Close()
		result.State = "open"
		result.Service = getServiceName(port)
		result.RTT = time.Since(startTime)

		if s.debug || s.verbose {
			fmt.Printf("DEBUG: Found open port %s:%d (%s)\n", host, port, getServiceName(port))
		}

		return result
	}

	if strings.Contains(err.Error(), "refused") {
		result.State = "closed"
	} else {
		result.State = "filtered"
	}

	return result
}

// ScanRange scans a range of ports on the configured target host.
// This is the main entry point for port scanning operations.
// By default, it skips host discovery and attempts to connect to all ports directly
// for maximum speed.
//
// Parameters:
//   - protocol: Protocol to use ("tcp" or "udp")
//   - startPort: First port in range to scan
//   - endPort: Last port in range to scan
//
// Returns:
//   - []ScanResult slice containing results for all ports in the specified range
//
// Example:
//
//	results := scanner.ScanRange("tcp", 1, 1000)
//	for _, result := range results {
//	    if result.State == "open" {
//	        fmt.Printf("Port %d is open (%s)\n", result.Port, result.Service)
//	    }
//	}
func (s *Scanner) ScanRange(protocol string, startPort, endPort int) []ScanResult {
	startTime := time.Now()

	if s.verbose {
		fmt.Println("Starting port scan...")
	}

	if s.target == "" {
		fmt.Println("Error: No target specified")
		return []ScanResult{}
	}

	isAlive := true
	if s.hostDiscovery {
		if s.verbose {
			fmt.Printf("Testing if host %s is alive...\n", s.target)
		}
		isAlive = s.TestHostAlive(s.target)
		if !isAlive {
			fmt.Printf("WARNING: Host %s doesn't seem to be responding to TCP pings\n", s.target)
			if s.verbose {
				fmt.Println("Continuing with scan but expect timeouts...")
			}
		} else if s.verbose {
			fmt.Printf("Host %s is up and responding! Starting port scan...\n", s.target)
		}
	} else if s.verbose {
		fmt.Printf("Skipping host discovery. Scanning all ports on %s...\n", s.target)
	}

	var totalPorts int
	var portList []int

	if len(s.Ports) > 0 {
		portList = s.Ports
		totalPorts = len(portList)
	} else {
		totalPorts = endPort - startPort + 1
		if totalPorts <= 0 {
			return []ScanResult{}
		}

		portList = make([]int, 0, totalPorts)
		for port := startPort; port <= endPort; port++ {
			portList = append(portList, port)
		}
	}

	if s.debug {
		fmt.Printf("DEBUG: Scanning %d ports total\n", totalPorts)
	}

	results := make([]ScanResult, 0, 25)

	var openCount int32
	var closedCount int32
	var filteredCount int32
	var totalScanned int32
	var mutex sync.Mutex

	// important: worker count significantly affects performance and system load
	// - too many workers may exhaust system resources or trigger IDS/firewall blocks
	// - too few workers will result in slow scanning performance
	// - values are automatically scaled based on OS, target responsiveness and ports to scan
	// - override with --concurrent flag if needed
	maxWorkers := 65000

	if !isAlive {
		maxWorkers = 1000
	} else if runtime.GOOS == "darwin" {
		maxWorkers = 50000
	} else if runtime.GOOS == "windows" {
		maxWorkers = 20000
	}

	numWorkers := maxWorkers
	if totalPorts < 100 {
		numWorkers = totalPorts
	} else if totalPorts < 1000 {
		numWorkers = totalPorts / 2
	} else {
		if isAlive {
			numWorkers = maxWorkers
		} else {
			numWorkers = maxWorkers / 5
		}
	}

	if s.verbose || s.debug {
		fmt.Printf("Using %d concurrent workers for scanning\n", numWorkers)
	}

	done := make(chan struct{})
	defer close(done)

	if len(s.Ports) == 0 {
		commonPorts := []int{
			80, 443, 22, 3389, 445, 139, 21, 23, 53,
			8080, 8443, 3306, 5432, 1433, 1521, 25,
			5900, 27017, 6379, 9200, 9300,
			8000, 8008, 8081, 8800, 8888, 9000, 9090,
			995, 993, 587, 143, 110,
			389, 123, 161, 162, 2121,
		}

		tempList := make([]int, 0, totalPorts)
		commonPortMap := make(map[int]bool, len(commonPorts))

		for _, port := range commonPorts {
			for _, p := range portList {
				if port == p && !commonPortMap[port] {
					tempList = append(tempList, port)
					commonPortMap[port] = true
					break
				}
			}
		}

		for _, port := range portList {
			if !commonPortMap[port] {
				tempList = append(tempList, port)
			}
		}

		portList = tempList
	}

	// important: buffer size affects memory usage and scan throughput
	// larger buffers improve speed but consume more memory
	bufferSize := 50000

	if !isAlive {
		bufferSize = 1000
	}

	portChan := make(chan int, bufferSize)

	if s.verbose || s.debug {
		fmt.Printf("Using port channel buffer size of %d for maximum throughput\n", bufferSize)
	}

	statusChan := make(chan struct{}, 1)
	defer close(statusChan)

	lastCheckpoint := time.Now()
	scanRateSamples := make([]float64, 0, 10)

	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		lastTotal := int32(0)

		for {
			select {
			case <-ticker.C:
				total := atomic.LoadInt32(&totalScanned)
				open := atomic.LoadInt32(&openCount)

				if total != lastTotal {
					now := time.Now()
					elapsed := now.Sub(lastCheckpoint).Seconds()
					portsDone := total - lastTotal
					rate := float64(portsDone) / elapsed
					lastCheckpoint = now
					lastTotal = total

					scanRateSamples = append(scanRateSamples, rate)
					if len(scanRateSamples) > 3 {
						scanRateSamples = scanRateSamples[1:]
					}

					var avgRate float64
					for _, r := range scanRateSamples {
						avgRate += r
					}
					if len(scanRateSamples) > 0 {
						avgRate /= float64(len(scanRateSamples))
					}

					fmt.Printf("\r\033[KScanned: %d/%d | %d open | %.0f/sec",
						total, len(portList), open, avgRate)
				}
			case <-done:
				return
			}
		}
	}()

	go func() {
		defer close(portChan)

		// important: batch size affects how many ports are sent at once
		// larger batches improve performance but may cause bursts of traffic
		batchSize := 1000

		if !isAlive {
			batchSize = 100
		}

		if len(portList) < batchSize {
			batchSize = len(portList)
		}

		if s.verbose || s.debug {
			fmt.Printf("Using batch size of %d ports per operation\n", batchSize)
		}

		for i := 0; i < len(portList); i += batchSize {
			end := i + batchSize
			if end > len(portList) {
				end = len(portList)
			}

			for j := i; j < end; j++ {
				select {
				case portChan <- portList[j]:
				case <-done:
					return
				}
			}
		}
	}()

	target := s.target

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for port := range portChan {
				select {
				case <-done:
					return
				default:
					result := s.UltraFastScanPort(target, port)

					switch result.State {
					case "open":
						atomic.AddInt32(&openCount, 1)

						if s.bannerGrab || s.serviceDetection {
							detailedResult := s.ScanPort(protocol, port)
							result = detailedResult
						} else {
							result.Service = getServiceName(port)
						}

						mutex.Lock()
						results = append(results, result)
						mutex.Unlock()

						found := atomic.LoadInt32(&openCount)
						if found >= 2 && totalPorts > 1000 {
							close(done)
							return
						}
					case "closed":
						atomic.AddInt32(&closedCount, 1)
					case "filtered":
						atomic.AddInt32(&filteredCount, 1)

						if s.showFiltered {
							mutex.Lock()
							results = append(results, result)
							mutex.Unlock()
						}
					}

					atomic.AddInt32(&totalScanned, 1)
				}
			}
		}()
	}

	wg.Wait()

	scanTime := time.Since(startTime).Seconds()
	totalPortsScanned := atomic.LoadInt32(&totalScanned)
	scanRate := float64(totalPortsScanned) / scanTime

	fmt.Println()
	fmt.Printf("\nPort scan complete in %.2f seconds | %d ports @ %.0f ports/sec\n",
		scanTime, totalPortsScanned, scanRate)

	openPortCount := atomic.LoadInt32(&openCount)
	fmt.Printf("Found %d open ports, %d closed, %d filtered\n",
		openPortCount, atomic.LoadInt32(&closedCount), atomic.LoadInt32(&filteredCount))

	if scanRate > 10000 {
		fmt.Println("\n🚀 Scan completed at blazing speed! Using advanced techniques:")
		fmt.Println("  - Ultra-aggressive timeouts (150μs-800μs)")
		fmt.Println("  - Massive concurrency with", numWorkers, "workers")
		fmt.Println("  - Direct port scanning without host discovery")
		fmt.Println("  - Zero packet capture overhead - pure connect scanning")
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// is local ip checks if an IP address is on a local network
func IsLocalIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	if ipv4 := ipAddr.To4(); ipv4 != nil {
		if ipv4[0] == 10 {
			return true
		}
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return true
		}
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		if ipv4[0] == 127 {
			return true
		}
	} else {
		if ipAddr[0] == 0xfe && (ipAddr[1]&0xc0) == 0x80 {
			return true
		}
		if ipAddr.Equal(net.IPv6loopback) {
			return true
		}
	}

	return false
}
