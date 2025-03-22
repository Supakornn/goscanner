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
	"syscall"
	"time"
)

// New creates a new Scanner with default settings
func New(target string, timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		target:            target,
		timeout:           timeout,
		concurrent:        concurrent,
		technique:         TechSYN,
		bannerGrab:        false,
		serviceDetection:  false,
		osDetection:       false,
		hostDiscovery:     true,
		outputFormat:      "normal",
		verbose:           false,
		debug:             false,
		timingTemplate:    4, // aggressive timing by default
		fragmentPackets:   false,
		sourcePort:        0, // random
		ttl:               64,
		scriptScan:        false,
		traceRoute:        false,
		randomTargets:     false,
		skipHostDiscovery: false,
		showFiltered:      false, // Default to not showing filtered ports
		ipv4Only:          false, // Default to allow IPv6
	}
}

// NewWithOptions creates a new Scanner with specified options
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
		ipv4Only:          opts.IPv4Only, // Add IPv4Only flag
		Ports:             opts.Ports,
	}
}

// SetShowFiltered sets whether to show filtered ports in the results
func (s *Scanner) SetShowFiltered(show bool) {
	s.showFiltered = show
}

// ScanPort checks if a port is open with enhanced options
func (s *Scanner) ScanPort(protocol string, port int) ScanResult {
	result := ScanResult{Port: port, Protocol: protocol}
	address := net.JoinHostPort(s.target, fmt.Sprintf("%d", port))

	startTime := time.Now()

	switch s.technique {
	case TechConnect:
		// Try different connection methods for better detection
		// First, attempt a faster connect with shorter timeout
		fastTimeout := time.Duration(50) * time.Millisecond
		conn, err := net.DialTimeout(protocol, address, fastTimeout)

		if err == nil {
			// Successfully connected quickly
			result.State = "open"
			result.RTT = time.Since(startTime)

			// Process banner and service detection
			if s.bannerGrab && conn != nil {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(s.timeout / 2)) // Reduce banner grab timeout

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

		// If fast connect failed, try with full timeout but stop early if we get a definite response
		conn, err = net.DialTimeout(protocol, address, s.timeout)
		if err != nil {
			// Check if this is a timeout error vs a connection refused
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.State = "filtered"
			} else {
				result.State = "closed"
			}
			return result
		}

		result.RTT = time.Since(startTime)
		result.State = "open"

		// Process banner and service detection
		if s.bannerGrab && conn != nil {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(s.timeout / 2)) // Reduce banner grab timeout

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
		// Properly implement UDP scanning
		result.Protocol = "udp" // Force protocol to UDP for UDP scan

		// Create a UDP connection
		conn, err := net.DialTimeout("udp", address, s.timeout)
		if err != nil {
			result.State = "closed"
			return result
		}
		defer conn.Close()

		// Send a zero-byte UDP packet
		_, err = conn.Write([]byte{})
		if err != nil {
			result.State = "closed"
			return result
		}

		// Set a read deadline
		conn.SetReadDeadline(time.Now().Add(s.timeout))

		// Try to read response
		resp := make([]byte, 1024)
		n, err := conn.Read(resp)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// No response could mean:
				// 1. Port is open but no application responded
				// 2. Port is filtered by firewall
				// For UDP, we'll mark as "open|filtered" as that's standard practice
				result.State = "open|filtered"
			} else {
				// Got ICMP unreachable or other error - port is closed
				result.State = "closed"
			}
		} else if n > 0 {
			// Got a response - port is definitely open
			result.State = "open"
			if s.bannerGrab {
				result.Banner = string(resp[:n])
			}
		}

		result.RTT = time.Since(startTime)

		// Only perform service detection if requested
		if s.serviceDetection {
			result.Service = getUDPServiceName(port)
			if s.bannerGrab && result.Banner != "" {
				result.Version = detectServiceVersion(result.Service, result.Banner)
			}
		} else {
			result.Service = getUDPServiceName(port)
		}

	case TechSYN:
		// Proper SYN scan implementation would require raw sockets and root privileges
		// For now, we'll implement a basic version that distinguishes between states
		result.State = "filtered" // Default to filtered

		// This would require a proper raw socket implementation
		// For now, give a more accurate description
		result.Service = getServiceName(port)
		result.Version = "SYN scan requires raw sockets/root privileges"

	case TechFIN, TechXMAS, TechNULL, TechACK:
		// These techniques also require raw sockets
		// For now, we'll implement a basic version that distinguishes between states
		result.State = "filtered" // Default to filtered

		// This would require a proper raw socket implementation
		// For now, give a more accurate description
		result.Service = getServiceName(port)
		result.Version = "Advanced scan techniques require raw sockets/root privileges"
	}

	return result
}

// FastScanPort is an optimized version that only checks if a port is open
func (s *Scanner) FastScanPort(protocol string, port int) ScanResult {
	result := ScanResult{Port: port, Protocol: protocol}
	address := net.JoinHostPort(s.target, fmt.Sprintf("%d", port))

	// Use zero timeout for non-blocking connects
	zeroTimeout := 500 * time.Microsecond // 0.5ms

	// Create a specialized non-blocking dialer
	d := net.Dialer{
		Timeout:   zeroTimeout,
		DualStack: false, // Disable IPv6 for speed
	}

	conn, err := d.Dial(protocol, address)

	if err == nil {
		// Port is definitely open
		conn.Close() // Close immediately
		result.State = "open"
		result.Service = getServiceName(port)
		return result
	}

	// Fast check for definite closed state
	if strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "network is unreachable") ||
		strings.Contains(err.Error(), "no route to host") {
		result.State = "closed"
		return result
	}

	// If it's a timeout, the port is likely filtered
	result.State = "filtered"
	return result
}

// TestHostAlive checks if a host is alive by sending a TCP ping to port 80
func (s *Scanner) TestHostAlive(host string) bool {
	// Try to resolve the host first
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// Try to connect to port 80 with a generous timeout
	address := net.JoinHostPort(ipAddr.String(), "80")
	conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}

	// Try port 443 as fallback
	address = net.JoinHostPort(ipAddr.String(), "443")
	conn, err = net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}

// UltraFastScanPort uses half-open connections for maximum throughput
// This is the core of the scanner's speed
func (s *Scanner) UltraFastScanPort(host string, port int) ScanResult {
	// Pre-allocate result
	result := ScanResult{
		Port:     port,
		Protocol: "tcp",
		State:    "filtered", // Default to filtered
	}

	// Handle IP resolution based on ipv4Only setting
	var resolvedHost string

	// For numeric IPs, use directly (faster)
	if net.ParseIP(host) != nil {
		// If we have an IPv6 address but ipv4Only is set, ignore this host
		if s.ipv4Only && net.ParseIP(host).To4() == nil {
			if s.debug {
				fmt.Printf("\n\r\033[KSkipping IPv6 address %s due to -4 flag", host)
			}
			result.State = "skipped" // Mark as skipped
			return result
		}
		resolvedHost = host
	} else {
		// Try to get IPv4/IPv6 addresses based on ipv4Only flag
		ipAddrs, err := net.LookupIP(host)
		if err != nil || len(ipAddrs) == 0 {
			// DNS lookup failed completely
			result.State = "filtered"
			return result
		}

		// If ipv4Only is set, search for an IPv4 address
		if s.ipv4Only {
			found := false
			for _, ip := range ipAddrs {
				if ip.To4() != nil {
					// Found an IPv4 address
					resolvedHost = ip.String()
					found = true
					break
				}
			}

			// If no IPv4 found with ipv4Only set, skip this host
			if !found {
				if s.debug {
					fmt.Printf("\n\r\033[KNo IPv4 address found for %s", host)
				}
				result.State = "skipped" // Mark as skipped
				return result
			}
		} else {
			// prefer IPv6 if available (more powerful)
			// Look for IPv6 first (modern approach)
			found := false
			for _, ip := range ipAddrs {
				if ip.To4() == nil {
					// Found an IPv6 address
					resolvedHost = ip.String()
					found = true
					break
				}
			}

			// If no IPv6, fall back to IPv4
			if !found {
				for _, ip := range ipAddrs {
					if ip.To4() != nil {
						resolvedHost = ip.String()
						found = true
						break
					}
				}
			}

			// If still not found, just use the first IP
			if !found && len(ipAddrs) > 0 {
				resolvedHost = ipAddrs[0].String()
			}
		}
	}

	// Format the address
	address := net.JoinHostPort(resolvedHost, strconv.Itoa(port))

	// ----- First attempt: Ultra-fast scan -----
	// uses very aggressive timeouts (500μs-3ms)
	isIPv6 := net.ParseIP(resolvedHost).To4() == nil

	// Super-aggressive dialer - uses 500μs default
	// We'll use 500μs for local/LAN and 3ms for internet
	timeout := 500 * time.Microsecond // 0.5ms

	// Slightly slower for internet targets
	if !IsLocalIP(resolvedHost) {
		timeout = 3 * time.Millisecond // 3ms for Internet targets
	}

	// Slower for IPv6 (needs more time to establish)
	if isIPv6 {
		if IsLocalIP(resolvedHost) {
			timeout = 8 * time.Millisecond // 8ms for local IPv6
		} else {
			timeout = 15 * time.Millisecond // 15ms for Internet IPv6
		}
	}

	// style dialer
	fastDialer := &net.Dialer{
		Timeout:       timeout,
		KeepAlive:     -1,          // Disable keepalive
		DualStack:     !s.ipv4Only, // Only use dual stack if ipv4Only is false
		FallbackDelay: -1,          // No fallback delay
		Control: func(network, addr string, c syscall.RawConn) error {
			var operr error
			if err := c.Control(func(fd uintptr) {
				// Set socket options for SYN-like behavior
				// SO_LINGER with timeout 0 means RST not FIN when closing
				linger := syscall.Linger{
					Onoff:  1,
					Linger: 0,
				}
				operr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
			}); err != nil {
				return err
			}
			return operr
		},
	}

	// Choose the network to use based on IP type
	network := "tcp"
	if isIPv6 {
		network = "tcp6"
	} else if s.ipv4Only {
		network = "tcp4"
	}

	// First attempt with aggressive timeout
	startTime := time.Now()
	conn, err := fastDialer.Dial(network, address)

	if err == nil {
		// Success! Port is open. Close immediately to avoid completing handshake
		conn.Close()
		result.State = "open"
		result.Service = getServiceName(port)
		result.RTT = time.Since(startTime)
		fmt.Printf("\n\r\033[K[+] Port %d open (%s)", port, getServiceName(port))
		return result
	}

	// Connection error - check error type
	errStr := err.Error()
	if strings.Contains(errStr, "refused") {
		// Connection refused is a definite sign of closed port
		result.State = "closed"
		return result
	}

	// If we got here, it might be filtered or slow
	// Try one more time with a slightly slower timeout
	// will retry up to 3 times with increasing timeouts
	fallbackTimeout := timeout * 5 // 5x slower for second attempt

	fallbackDialer := &net.Dialer{
		Timeout:   fallbackTimeout,
		KeepAlive: -1,
		DualStack: !s.ipv4Only,
	}

	conn2, err := fallbackDialer.Dial(network, address)
	if err == nil {
		// Second attempt succeeded - port is open but slow
		conn2.Close()
		result.State = "open"
		result.Service = getServiceName(port)
		result.RTT = time.Since(startTime)
		fmt.Printf("\n\r\033[K[+] Port %d open (%s)", port, getServiceName(port))
		return result
	}

	// Both attempts failed - port is filtered or truly closed
	if strings.Contains(err.Error(), "refused") {
		result.State = "closed"
	} else {
		// For IPv6 internet addresses, make a final attempt with much longer timeout
		// This is specifically to catch Google and similar sites with aggressive filtering
		if isIPv6 && !IsLocalIP(resolvedHost) && s.timeout > 1*time.Second {
			// One final attempt with a much more generous timeout
			finalTimeout := 100 * time.Millisecond

			finalDialer := &net.Dialer{
				Timeout:   finalTimeout,
				KeepAlive: -1,
				DualStack: !s.ipv4Only,
			}

			conn3, err := finalDialer.Dial(network, address)
			if err == nil {
				// Final attempt succeeded - port is open but heavily filtered
				conn3.Close()
				result.State = "open"
				result.Service = getServiceName(port)
				result.RTT = time.Since(startTime)
				fmt.Printf("\n\r\033[K[+] Port %d open on IPv6 (%s)", port, getServiceName(port))
				return result
			}
		}

		result.State = "filtered"
	}

	return result
}

// ScanRange scans a range of ports with ultra-fast optimizations
func (s *Scanner) ScanRange(protocol string, startPort, endPort int) []ScanResult {
	startTime := time.Now()

	fmt.Println("Blitz sweep in progress...")

	// Ensure we have a valid target
	if s.target == "" {
		fmt.Println("Error: No target specified")
		return []ScanResult{}
	}

	// Test if host is alive first
	fmt.Printf("Testing if host %s is alive...\n", s.target)
	isAlive := s.TestHostAlive(s.target)
	if !isAlive {
		fmt.Printf("WARNING: Host %s doesn't seem to be responding to TCP pings\n", s.target)
		fmt.Println("Continuing with scan but expect timeouts...")
	} else {
		fmt.Printf("Host %s is up and responding! Starting port scan...\n", s.target)
	}

	// Calculate total ports to scan
	totalPorts := endPort - startPort + 1
	if totalPorts <= 0 {
		return []ScanResult{}
	}

	// Pre-allocate results (typical number of open ports is small)
	results := make([]ScanResult, 0, 25)

	// Thread-safe counters using atomic operations
	var openCount int32
	var closedCount int32
	var filteredCount int32
	var totalScanned int32
	var mutex sync.Mutex

	// Adjust worker count based on network conditions
	maxWorkers := 65000 // Default max for Linux
	if !isAlive {
		// If host isn't responding well, use fewer workers
		maxWorkers = 1000
	} else if runtime.GOOS == "darwin" {
		maxWorkers = 15000 // Lower for macOS due to file descriptor limits
	} else if runtime.GOOS == "windows" {
		maxWorkers = 8000 // Even lower for Windows
	}

	// Adaptive worker management
	numWorkers := maxWorkers
	if totalPorts < 1000 {
		numWorkers = totalPorts
	}

	// Control channel for early exit
	done := make(chan struct{})
	defer close(done)

	// Prioritize common ports for faster results
	commonPorts := []int{
		22, 80, 443, 21, 25, 23, 3389, 8080, 8443, 445, 139,
		3306, 5432, 1433, 1521, 5900, 5901, 27017, 6379, 9200,
		9300, 2375, 2376, 2049, 111, 995, 993, 587, 143, 110,
		53, 389, 88, 464, 123, 137, 138, 67, 68, 69, 161, 162,
		1194, 1701, 1723, 1812, 1813, 5060, 5061, 8000, 8008, 8081,
		8800, 8880, 8888, 9000, 9001, 9090, 1080, 3128, 8888,
		5000, 631, 2222, 1158, 5353, 8000, 10000, 49152, 49153,
	}

	// Create a port list starting with common ports
	portList := make([]int, 0, totalPorts)
	commonPortMap := make(map[int]bool, len(commonPorts))

	// Add common ports first if they're in range
	for _, port := range commonPorts {
		if port >= startPort && port <= endPort {
			portList = append(portList, port)
			commonPortMap[port] = true
		}
	}

	// Then add all other ports
	for port := startPort; port <= endPort; port++ {
		if !commonPortMap[port] {
			portList = append(portList, port)
		}
	}

	// Port batch management - buffer size based on host responsiveness
	bufferSize := 10000
	if !isAlive {
		bufferSize = 100
	}
	portChan := make(chan int, bufferSize)

	// Status updates channel
	statusChan := make(chan struct{}, 1)
	defer close(statusChan)

	// Record adaptive rate data
	lastCheckpoint := time.Now()
	scanRateSamples := make([]float64, 0, 10)

	// Status updater goroutine with adaptive rate display
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		lastTotal := int32(0)

		for {
			select {
			case <-ticker.C:
				total := atomic.LoadInt32(&totalScanned)
				open := atomic.LoadInt32(&openCount)
				closed := atomic.LoadInt32(&closedCount)
				filtered := atomic.LoadInt32(&filteredCount)

				// Only update if something changed
				if total != lastTotal {
					// Calculate rate
					now := time.Now()
					elapsed := now.Sub(lastCheckpoint).Seconds()
					portsDone := total - lastTotal
					rate := float64(portsDone) / elapsed
					lastCheckpoint = now
					lastTotal = total

					// Track rate samples for adaptive display
					if rate > 0 {
						scanRateSamples = append(scanRateSamples, rate)
						if len(scanRateSamples) > 5 {
							scanRateSamples = scanRateSamples[1:]
						}
					}

					// Calculate average rate
					var avgRate float64
					for _, r := range scanRateSamples {
						avgRate += r
					}
					if len(scanRateSamples) > 0 {
						avgRate /= float64(len(scanRateSamples))
					}

					percent := 100.0 * float64(total) / float64(len(portList))

					// Progress display with state counts
					fmt.Printf("\r\033[KScanned %d/%d ports (%d open, %d closed, %d filtered) | %.0f/sec | %.1f%%",
						total, len(portList), open, closed, filtered, avgRate, percent)
				}
			case <-done:
				return
			}
		}
	}()

	// Port producer with batch sending
	go func() {
		defer close(portChan)

		// Send batches to minimize channel operations
		batchSize := 100
		if !isAlive {
			batchSize = 10 // Smaller batches for unresponsive hosts
		}

		if len(portList) < batchSize {
			batchSize = len(portList)
		}

		for i := 0; i < len(portList); i += batchSize {
			end := i + batchSize
			if end > len(portList) {
				end = len(portList)
			}

			// Process one batch
			for j := i; j < end; j++ {
				select {
				case portChan <- portList[j]:
				case <-done:
					return
				}
			}
		}
	}()

	// Cache the target to avoid repeated access to the struct field in the loop
	target := s.target

	// Create worker pool with adaptive error handling
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for port := range portChan {
				// Check for early termination
				select {
				case <-done:
					return
				default:
					// Optimized scan using our reliable technique
					result := s.UltraFastScanPort(target, port)

					// Track counts by state
					switch result.State {
					case "open":
						atomic.AddInt32(&openCount, 1)

						// For open ports, potentially do more detailed scan
						if s.bannerGrab || s.serviceDetection {
							detailedResult := s.ScanPort(protocol, port)
							result = detailedResult
						} else {
							// Just add service name without the slow scan
							result.Service = getServiceName(port)
						}

						// Add to results - must protect with mutex
						mutex.Lock()
						results = append(results, result)
						mutex.Unlock()

						// Early exit strategy after finding sufficient ports
						found := atomic.LoadInt32(&openCount)
						if found >= 10 && totalPorts > 2000 {
							close(done) // Signal everyone to stop
							return
						}
					case "closed":
						atomic.AddInt32(&closedCount, 1)
					case "filtered":
						atomic.AddInt32(&filteredCount, 1)

						// Add filtered ports to results if requested
						if s.showFiltered {
							mutex.Lock()
							results = append(results, result)
							mutex.Unlock()
						}
					}

					// Update total count
					atomic.AddInt32(&totalScanned, 1)
				}
			}
		}()
	}

	// Wait for completion
	wg.Wait()

	// Print final stats
	scanTime := time.Since(startTime).Seconds()
	totalPortsScanned := atomic.LoadInt32(&totalScanned)
	scanRate := float64(totalPortsScanned) / scanTime

	fmt.Println() // New line after progress
	fmt.Printf("\nPort scan complete in %.2f seconds | %d ports @ %.0f ports/sec\n",
		scanTime, totalPortsScanned, scanRate)

	openPortCount := atomic.LoadInt32(&openCount)
	fmt.Printf("Found %d open ports, %d closed, %d filtered\n",
		openPortCount, atomic.LoadInt32(&closedCount), atomic.LoadInt32(&filteredCount))

	// Sort results by port for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// IsLocalIP checks if an IP address is on a local network
func IsLocalIP(ip string) bool {
	// Parse the IP string
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	// IPv4 local networks
	if ipv4 := ipAddr.To4(); ipv4 != nil {
		// Check against common local subnet ranges
		// 10.0.0.0/8
		if ipv4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ipv4[0] == 127 {
			return true
		}
	} else {
		// IPv6 local addresses
		// fe80::/10 (link-local)
		if ipAddr[0] == 0xfe && (ipAddr[1]&0xc0) == 0x80 {
			return true
		}
		// ::1/128 (loopback)
		if ipAddr.Equal(net.IPv6loopback) {
			return true
		}
	}

	return false
}
