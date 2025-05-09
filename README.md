# Goscanner

<p align="center">
  <img src="./assets/img.png" width="200" alt="GoScanner Logo">
</p>

<p align="center" style="font-size: 18px; font-weight: bold;">A Port scanner written in Go.</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#command-line-options">Command Line Options</a> •
  <a href="#contributing">Contributing</a>
</p>

## Installation

```bash
# Install the latest version
go install github.com/supakornn/goscanner@latest

# Or specify a version
go install github.com/supakornn/goscanner@v.1.0
```

## Usage

```bash
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

-   [Nmap](https://nmap.org/) - The industry standard in network scanning
-   [RustScan](https://github.com/RustScan/RustScan) - The modern port scanner
-   [Masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner for mass scanning

## Disclaimer

GoScanner is designed for legitimate network security assessments, penetration testing, and system administration. Always ensure you have proper authorization before scanning any systems or networks. Unauthorized scanning may violate local and international laws.
