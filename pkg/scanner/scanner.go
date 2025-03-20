package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// New creates a new Scanner with default settings
func New(target string, timeout time.Duration, concurrent int) *Scanner {
	return &Scanner{
		target:            target,
		timeout:           timeout,
		concurrent:        concurrent,
		technique:         TechConnect,
		bannerGrab:        false,
		serviceDetection:  false,
		osDetection:       false,
		hostDiscovery:     true,
		outputFormat:      "normal",
		verbose:           false,
		debug:             false,
		timingTemplate:    3, // normal timing
		fragmentPackets:   false,
		sourcePort:        0, // random
		ttl:               64,
		scriptScan:        false,
		traceRoute:        false,
		randomTargets:     false,
		skipHostDiscovery: false,
		showFiltered:      false, // Default to not showing filtered ports
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
		showFiltered:      opts.ShowFiltered, // Set from options
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
		// Optimize connect scan for speed
		conn, err := net.DialTimeout(protocol, address, s.timeout)
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

		// Only perform banner grabbing if explicitly requested
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

		// Only perform service detection if explicitly requested
		if s.serviceDetection {
			result.Service = getServiceName(port)
			if s.bannerGrab && result.Banner != "" {
				result.Version = detectServiceVersion(result.Service, result.Banner)
			}
		} else {
			result.Service = getServiceName(port)
		}

	case TechSYN, TechFIN, TechXMAS, TechNULL, TechACK, TechUDP:
		// Simplified for demo purposes
		result.State = "open"
		result.Service = getServiceName(port)
	}

	return result
}

// FastScanPort is an optimized version that only checks if a port is open
func (s *Scanner) FastScanPort(protocol string, port int) ScanResult {
	result := ScanResult{Port: port, Protocol: protocol}
	address := net.JoinHostPort(s.target, fmt.Sprintf("%d", port))

	// Use a reasonable timeout that's not too short
	fastTimeout := s.timeout
	if fastTimeout < 200*time.Millisecond {
		fastTimeout = 200 * time.Millisecond // Ensure minimum timeout
	}

	d := net.Dialer{Timeout: fastTimeout}
	conn, err := d.Dial(protocol, address)

	if err != nil {
		// Check if this is a timeout error vs a connection refused
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
		} else {
			result.State = "closed"
		}
		return result
	}

	// Successfully connected
	result.State = "open"
	result.Service = getServiceName(port)

	// Properly close the connection
	if conn != nil {
		conn.Close()
	}

	return result
}

// ScanRange scans a range of ports
func (s *Scanner) ScanRange(protocol string, startPort, endPort int) []ScanResult {
	var results []ScanResult
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Optimize concurrency based on port range
	portCount := endPort - startPort + 1
	actualConcurrent := s.optimizeConcurrency(portCount)

	// Use buffered channels to avoid blocking
	resultChan := make(chan ScanResult, actualConcurrent*2)

	// Worker pool implementation
	portChan := make(chan int, portCount)

	// Fill port channel
	for port := startPort; port <= endPort; port++ {
		portChan <- port
	}
	close(portChan)

	// Start workers
	for i := 0; i < actualConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for port := range portChan {
				// Determine if we should use the fast scan
				var result ScanResult
				if s.bannerGrab || s.serviceDetection || s.debug || s.verbose {
					result = s.ScanPort(protocol, port)
				} else {
					result = s.FastScanPort(protocol, port)
				}

				// Filter results based on showFiltered flag
				if result.State == "open" || (s.showFiltered && result.State == "filtered") {
					resultChan <- result
				}
			}
		}()
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		mutex.Lock()
		results = append(results, result)
		mutex.Unlock()
	}

	return results
}

// optimizeConcurrency returns an optimized concurrency value based on several factors
func (s *Scanner) optimizeConcurrency(portCount int) int {
	// Base concurrency from timing template
	baseConcurrent := s.adjustConcurrency()

	// Don't use more goroutines than ports
	if baseConcurrent > portCount {
		return portCount
	}

	// Increase concurrency for larger port ranges
	if portCount > 1000 && baseConcurrent < 500 {
		return min(portCount/2, 500)
	}

	return baseConcurrent
}

// min returns the smaller of a and b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// adjustConcurrency adjusts concurrency based on timing template
func (s *Scanner) adjustConcurrency() int {
	switch s.timingTemplate {
	case 0:
		return max(10, s.concurrent/8) // Still allow some concurrency even in slowest mode
	case 1:
		return s.concurrent / 2
	case 2:
		return s.concurrent
	case 3:
		return s.concurrent * 2
	case 4:
		return s.concurrent * 4
	case 5:
		return s.concurrent * 8 // Much more aggressive for fastest scans
	default:
		return s.concurrent
	}
}

// max returns the larger of a and b
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
