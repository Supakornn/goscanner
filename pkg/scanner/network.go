package scanner

import (
	"sync"
	"time"
)

// scans a network range (CIDR notation)
func (s *Scanner) ScanNetwork(cidr string) *NetworkScan {
	networkScan := &NetworkScan{
		CIDR:      cidr,
		StartTime: time.Now(),
	}

	ips, err := expandCIDR(cidr)
	if err != nil {
		return networkScan
	}

	var wg sync.WaitGroup
	hostChan := make(chan *HostResult)

	subnetConcurrent := s.concurrent / 4
	if subnetConcurrent < 1 {
		subnetConcurrent = 1
	}

	limiter := make(chan struct{}, subnetConcurrent)

	go func() {
		for host := range hostChan {
			networkScan.Hosts = append(networkScan.Hosts, *host)
			if host.Status == "up" {
				networkScan.HostsUp++
			} else {
				networkScan.HostsDown++
			}
		}
	}()

	for _, ip := range ips {
		wg.Add(1)
		limiter <- struct{}{}

		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-limiter }()

			scanner := NewWithOptions(targetIP, ScanOption{
				Technique:        s.technique,
				Timeout:          s.timeout,
				Concurrent:       s.concurrent,
				BannerGrab:       s.bannerGrab,
				ServiceDetection: s.serviceDetection,
				OSDetection:      s.osDetection,
				HostDiscovery:    s.hostDiscovery,
				TimingTemplate:   s.timingTemplate,
			})

			hostResult := scanner.ScanHost()
			hostChan <- hostResult
		}(ip)
	}

	wg.Wait()
	close(hostChan)

	networkScan.EndTime = time.Now()
	networkScan.Duration = networkScan.EndTime.Sub(networkScan.StartTime)

	return networkScan
}
