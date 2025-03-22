# GoScanner

<p align="center">
  <img src="./assets/img.png" width="200" alt="GoScanner Logo">
</p>

<p align="center" style="font-size: 18px; font-weight: bold;">A powerful, high-performance port scanner written in Go.</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#use-cases">Use Cases</a> •
  <a href="#scan-techniques">Scan Techniques</a> •
  <a href="#api">API</a> •
  <a href="#contributing">Contributing</a>
</p>

## Features

- **Ultra-fast scanning** - Scans thousands of ports per second
- **Multiple techniques** - Connect, SYN, FIN, XMAS, NULL, ACK, and UDP scanning
- **Service detection & fingerprinting** - Identifies services with banner grabbing
- **Flexible output** - Normal, JSON, and XML formats
- **Smart targeting** - Single hosts, IP ranges, CIDR notation, and file input
- **Performance tuning** - Adjustable timeouts, concurrency, and timing templates
- **Evasion capabilities** - Decoys, fragmentation, and custom TTL values
- **Cross-platform** - Linux, macOS, and Windows compatible
- **Nmap integration** - Automatic Nmap scanning of discovered open ports
- **GPL 3.0 licensed** - Free to use, modify, and distribute

## Installation

```bash
# Clone the repository
git clone https://github.com/supakornn/goscanner.git
cd goscanner

# Build the project
go build

# Optional: Install to your GOPATH
go install
```

## Usage

```
GoScanner is a high-performance network port scanner built in Go.

Usage:
  goscanner [flags] [target] [-- nmap-flags...]

Examples:
  # Basic scan of a single host
  goscanner -t 192.168.1.1

  # Scan specific ports on multiple hosts
  goscanner -t 192.168.1.0/24 -p 22,80,443

  # Full scan with service detection
  goscanner -t example.com -p 1-1000 -V -b

  # Use nmap directly with advanced flags
  goscanner 192.168.1.1 -- -A -sV -sC
```

### Command Line Options

```
Flags:
  -t, --target string           Target to scan (IP, hostname, CIDR)
      --target-file string      File containing targets (one per line)
      --exclude string          Exclude targets (comma-separated)
  -p, --port-range string       Port range (e.g. 1-1000) (default "1-65535")
      --ports string            Specific ports to scan (comma-separated)
      --port-file string        File containing ports (one per line)
      --exclude-ports string    Exclude ports (comma-separated)
  -z, --timeout int             Timeout in milliseconds (default: 50ms - ultra-fast) (default 50)
  -c, --concurrent int          Number of concurrent connections (default: 65535 - maximum) (default 65535)
  -P, --protocol string         Protocol (tcp, udp) (default "tcp")
  -s, --scan-technique string   Scan technique (connect, syn, fin, xmas, null) (default "syn")
  -T, --timing int              Timing template (0-5, higher is faster) (default 5)
  -n, --skip-host-discovery     Skip host discovery (default: true for optimized speed) (default true)
  -N, --no-ping                 Skip ICMP ping discovery (default: true for optimized speed) (default true)
      --traceroute              Perform traceroute to targets
  -V, --service-detection       Probe open ports for service info
  -b, --banner                  Perform banner grabbing
  -O, --os-detection            Enable OS detection
  -A, --aggressive              Enable aggressive scan (service + OS detection)
  -C, --script                  Perform script scanning
      --script-args string      Provide arguments to scripts
  -o, --output-format string    Output format (normal, json, xml) (default "normal")
  -f, --output-file string      Write output to file
  -v, --verbose                 Increase verbosity level
      --debug                   Enable debugging
  -F, --show-filtered           Show filtered ports in results
      --source-port int         Use specified source port
      --fragment                Fragment packets
      --ttl int                 Set IP time-to-live field (default 64)
      --decoys string           Cloak a scan with decoys (comma-separated)
      --randomize-hosts         Randomize target scan order
      --nmap                    Automatically run Nmap on open ports (default true)
      --no-nmap                 Disable automatic Nmap scanning
      --nmap-flags string       Flags to pass to Nmap when using --nmap (default "-sC -sV")
  -4, --ipv4                    Force IPv4 scanning only
  -h, --help                    Help for goscanner
```

## Basic Usage Examples

```bash
# Show help information
./goscanner -h

# Scan a single host on default ports (1-65535)
./goscanner -t 192.168.1.1

# Scan multiple hosts
./goscanner -t 192.168.1.1,192.168.1.2

# Scan a network range
./goscanner -t 192.168.1.0/24

# Scan a specific port
./goscanner -t 192.168.1.1 -p 22

# Scan a port range
./goscanner -t 192.168.1.1 -p 20-30

# Enable host discovery (disabled by default for speed)
./goscanner -t 192.168.1.1 -n=false

# Scan from a file containing multiple targets
./goscanner --target-file targets.txt

# Scan common web ports across a subnet
./goscanner -t 10.0.0.0/24 -p 80,443,8080,8443
```

## Advanced Usage Examples

```bash
# Service detection and banner grabbing
./goscanner -t 192.168.1.1 -V -b

# OS detection
./goscanner -t 192.168.1.1 -O

# Aggressive scan (service + OS detection)
./goscanner -t 192.168.1.1 -A

# Output to file in JSON format
./goscanner -t 192.168.1.1 -o json -f results.json

# Increase verbosity
./goscanner -t 192.168.1.1 -v

# Show filtered ports
./goscanner -t 192.168.1.1 -F

# Maximum speed with timing template 5
./goscanner -t 192.168.1.1 -T5

# Use UDP protocol
./goscanner -t 192.168.1.1 -P udp

# Disable automatic Nmap scanning
./goscanner -t 192.168.1.1 --no-nmap

# Use SYN scan technique (requires root/administrator privileges)
sudo ./goscanner -t 192.168.1.1 -s syn

# Scan with decoys to obscure the source
./goscanner -t 192.168.1.1 --decoys 10.0.0.1,10.0.0.2

# Fragment packets to evade some IDS systems
sudo ./goscanner -t 192.168.1.1 --fragment

# Scan with a custom source port
sudo ./goscanner -t 192.168.1.1 --source-port 53

# Run custom scripts against open ports
./goscanner -t 192.168.1.1 -C --script-args "http.useragent=Mozilla/5.0"
```

## Use Cases

### Network Security Assessment

GoScanner is ideal for security professionals performing:

- Security audits and compliance checks
- Penetration testing
- Vulnerability assessments
- Attack surface mapping

```bash
# Comprehensive security assessment
./goscanner -t 10.0.0.0/24 -A -o json -f assessment.json
```

### System Administration

System administrators can use GoScanner for:

- Network inventory and asset discovery
- Service availability monitoring
- Firewall rule verification
- Network troubleshooting

```bash
# Check for unauthorized services
./goscanner -t 10.0.0.0/24 -p 21,22,23,25,3389 -V
```

### DevOps and CI/CD Pipelines

Integrate GoScanner into your CI/CD pipeline:

```bash
# Example CI/CD script
./goscanner -t production-server.example.com -p 1-1000 -o json -f scan-results.json
if grep -q "\"State\":\"open\"" scan-results.json; then
  echo "Warning: Unexpected open ports detected"
  exit 1
fi
```

## Scan Techniques

GoScanner supports multiple scanning techniques:

- **Connect scan** (`-s connect`): Completes a full TCP handshake. Reliable but more detectable.
- **SYN scan** (`-s syn`): Half-open scan that doesn't complete the TCP handshake. Faster and less detectable (requires root/admin privileges).
- **FIN scan** (`-s fin`): Sends a FIN packet to elicit a response (requires root/admin privileges).
- **XMAS scan** (`-s xmas`): Sends a packet with FIN, URG, and PUSH flags set (requires root/admin privileges).
- **NULL scan** (`-s null`): Sends a packet with no flags set (requires root/admin privileges).
- **ACK scan** (`-s ack`): Sends an ACK packet to test firewall rules (requires root/admin privileges).
- **UDP scan** (`-P udp`): Tests UDP ports, which often host critical services like DNS (53) or DHCP (67/68).

### When to Use Each Technique

| Technique | Best Used For                     | Detectability | Speed    | Privileges |
| --------- | --------------------------------- | ------------- | -------- | ---------- |
| Connect   | Accuracy, general scanning        | High          | Moderate | No         |
| SYN       | Fast scanning with low footprint  | Medium        | Fast     | Yes        |
| FIN/NULL  | Firewall evasion                  | Low           | Fast     | Yes        |
| XMAS      | Advanced firewall evasion         | Low           | Fast     | Yes        |
| ACK       | Firewall rule mapping             | Medium        | Fast     | Yes        |
| UDP       | Finding critical non-TCP services | Medium        | Slow     | Yes        |

## Performance

GoScanner uses several optimizations to achieve high-speed scanning:

1. **Ultra-Fast Port Detection**: Uses an extremely short initial timeout (50ms) for initial port probing to maximize throughput.

2. **Maximum Concurrency**: Default configuration uses 65535 concurrent connections to achieve maximum scanning speed.

3. **Optimized Discovery**: Skips host discovery by default to focus on port scanning directly.

4. **Adaptive Scanning**: Uses different scanning techniques based on port response patterns.

5. **Priority Scanning**: Identifies commonly used ports first to quickly find critical services.

### Performance Tips

For maximum scanning performance:

- GoScanner already uses optimal settings by default
- Default scan technique is SYN for best balance of speed and accuracy
- For additional speed, reduce the port range with the `-p` flag
- The default timeout of 50ms is optimized for LAN and high-speed connections

## Output Formats

GoScanner supports multiple output formats:

- **Normal** (default): Human-readable output
- **JSON**: Structured data format, ideal for programmatic processing
- **XML**: Compatible with various security tools and reporting systems

Example JSON output:

```json
{
  "Hostname": "example.com",
  "IP": "93.184.216.34",
  "Results": [
    {
      "Port": 80,
      "State": "open",
      "Service": "http",
      "Version": "nginx",
      "Protocol": "tcp",
      "Banner": "HTTP/1.1 200 OK\r\nServer: nginx",
      "RTT": 42000000
    }
  ],
  "Time": "2023-03-22T12:34:56Z"
}
```

## API

GoScanner can be used as a library in your Go applications:

```go
package main

import (
	"fmt"
	"time"

	"github.com/supakornn/goscanner/pkg/scanner"
)

func main() {
	// Create a new scanner with target, timeout, and concurrency settings
	s := scanner.New("example.com", 50*time.Millisecond, 5000)

	// Or create with detailed options
	options := scanner.ScanOption{
		Timeout:          50 * time.Millisecond,
		Concurrent:       5000,
		Technique:        scanner.TechSYN,
		BannerGrab:       true,
		ServiceDetection: true,
	}
	s = scanner.NewWithOptions("example.com", options)

	// Scan a single port
	result := s.ScanPort("tcp", 80)
	fmt.Printf("Port %d is %s\n", result.Port, result.State)

	// Ultra-fast port scanning
	result = s.UltraFastScanPort("example.com", 443)

	// Scan a port range
	results := s.ScanRange("tcp", 80, 100)
	for _, r := range results {
		if r.State == "open" {
			fmt.Printf("Found open port %d (%s)\n", r.Port, r.Service)
		}
	}
}
```

## Troubleshooting

### Common Issues

**Slow Scanning Speed**

- Try increasing concurrency: `-c 10000`
- Use a faster timing template: `-T5`
- Skip host discovery for known hosts: `-n`

**Permission Errors**

- For SYN/FIN/NULL/XMAS scans, you need root/administrator privileges
- On Linux/macOS: Use `sudo ./goscanner`
- On Windows: Run Command Prompt as Administrator

**False Positives/Negatives**

- Try a different scan technique
- Increase timeout value: `-z 500`
- For UDP scans, try increasing verbosity: `-v`

**Firewall Blocking**

- Try ACK scan to test firewall rules: `-s ack`
- Use fragmentation: `--fragment`
- Try decoy scanning: `--decoys`
- Use a custom source port: `--source-port 53`

## Security Considerations

- Some scan techniques require root/administrator privileges
- Always ensure you have permission to scan the target systems
- Aggressive scanning may trigger security systems (IDS/IPS)
- Use with caution on production networks
- Consider legal implications of scanning systems you don't own

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0) - see the LICENSE file for details.

## Acknowledgements

Inspired by:

- [Nmap](https://nmap.org/) - The industry standard in network scanning
- [RustScan](https://github.com/RustScan/RustScan) - The modern port scanner
- [Masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner for mass scanning

## Disclaimer

GoScanner is designed for legitimate network security assessments, penetration testing, and system administration. Always ensure you have proper authorization before scanning any systems or networks. Unauthorized scanning may violate local and international laws.
