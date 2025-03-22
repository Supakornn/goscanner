# GoScanner

![GoScanner Logo](./assets/logo.png)

A powerful port scanner written in Go.

## Features

- **Ultra-Fast Port Scanning**: Uses half-open connections with minimal 50μs timeouts.
- **Adaptive Batch Sizing**: Automatically adjusts batch sizes based on network conditions
- **Masscan-style Turbo Scanning**: Employs advanced techniques for maximum port scanning throughput
- **High Concurrency**: Default 5000 workers with optimized connection handling
- **Smart Port Prioritization**: Scans common ports first for quicker results
- **Multiple Scan Techniques**: Connect, SYN, FIN, XMAS, NULL, and UDP scanning methods
- **Service Detection**: Identify services running on open ports
- **OS Detection**: Attempt to identify the operating system of target hosts
- **Banner Grabbing**: Capture service banners for version detection
- **Host Discovery**: Ping sweep to identify active hosts
- **Output Formats**: Results in normal text, JSON, or XML format
- **Nmap Integration**: Automatically run Nmap on discovered open ports
- **Early Exit**: Stop scanning after finding a specified number of open ports

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/supakornn/goscanner.git
cd goscanner

# Build the project
go build

# Optional: Install to your GOPATH
go install
```

### Using Go Install

```bash
go install github.com/supakornn/goscanner@latest
```

## Usage

```
GoScanner is a feature-rich, high-performance port scanner built in Go.

Key features:
* Ultra-fast port detection with half-open connections and minimal timeouts (50μs)
* Adaptive batch scanning that automatically adjusts to network conditions
* High-concurrency scanning with up to 5000 workers by default
* Prioritizes common ports first for quicker results
* Masscan-style turbo port sweep for maximum throughput

Usage:
  goscanner [flags] [target] [-- nmap-flags...]

Examples:
  # Basic scan of a single host
  goscanner -t 192.168.1.1

  # Scan specific ports on multiple hosts
  goscanner -t 192.168.1.0/24 -p 22,80,443

  # Full scan with service detection
  goscanner -t example.com -p 1-1000 --service-detection -O

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
  -w, --timeout int             Timeout in milliseconds (default: 100ms) (default 100)
  -c, --concurrent int          Number of concurrent connections (default: 5000) (default 5000)
  -P, --protocol string         Protocol (tcp, udp) (default "tcp")
  -s, --scan-technique string   Scan technique (connect, syn, fin, xmas, null) (default "connect")
  -T, --timing int              Timing template (0-5, higher is faster) (default 5)
  -n, --skip-host-discovery     Skip host discovery
  -N, --no-ping                 Skip ICMP ping discovery (treat all hosts as online)
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
      --nmap                    Automatically run Nmap on open ports
      --nmap-flags string       Flags to pass to Nmap when using --nmap (default "-sC -sV")
  -h, --help                    help for goscanner
```

## Basic Usage Examples

```bash
# Show help information
./goscanner -h

# Scan a single host on default ports (1-65535)
./goscanner -t 192.168.1.1

# Scan multiple hosts
./goscanner -t "192.168.1.1,192.168.1.2"

# Scan a network range
./goscanner -t "192.168.1.0/24"

# Scan a specific port
./goscanner -t 192.168.1.1 -p 22

# Scan a port range
./goscanner -t 192.168.1.1 -p 20-30

# Skip host discovery (faster on known hosts)
./goscanner -t 192.168.1.1 -N
```

## Advanced Usage Examples

```bash
# Service detection
./goscanner -t 192.168.1.1 -V

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

# Banner grabbing
./goscanner -t 192.168.1.1 -b

# Use UDP protocol
./goscanner -t 192.168.1.1 -P udp

# Automatically run Nmap on discovered open ports
./goscanner -t 192.168.1.1 --nmap
```

## Technical Details

GoScanner uses several optimizations to achieve high-speed scanning:

1. **Half-Open Connections**: Unlike full TCP handshakes, GoScanner uses an extremely short timeout of just 50 microseconds to detect potential open ports without completing the handshake.

2. **Adaptive Batch Scanning**: Automatically adjusts batch sizes from 1,000 to 25,000 ports depending on network performance to maximize throughput.

3. **Common Ports First**: Scans the most commonly used ports first (80, 443, 22, etc.) to quickly find services on a typical target.

4. **Worker Optimization**: Uses up to 5,000 concurrent workers by default, but automatically adjusts based on the operating system's capabilities.

5. **Early Exit**: Stops scanning after finding 10 open ports on large scans to save time when only looking for active services.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

Inspired by [nmap](https://nmap.org/), [RustScan](https://github.com/RustScan/RustScan), and [masscan](https://github.com/robertdavidgraham/masscan) - powerful network scanners.
