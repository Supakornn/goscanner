# Goscanner - A Port scanner written in Go.

## Installation

```bash
# Install the latest version
go install github.com/supakornn/goscanner@latest
```

## Build from source

```bash
git clone https://github.com/supakornn/goscanner.git
cd goscanner
go build -o goscanner
```

## Usage

```bash
GoScanner is a high-performance network port scanner built in Go.

Usage:
  goscanner [flags] [target] [-- nmap-flags...]

Show help:
    goscanner -h

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

## Acknowledgements

Inspired by:

-   [Nmap](https://nmap.org/) - The industry standard in network scanning
-   [RustScan](https://github.com/RustScan/RustScan) - The modern port scanner
-   [Masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner for mass scanning

## Disclaimer

GoScanner is designed for legitimate network security assessments, penetration testing, and system administration. Always ensure you have proper authorization before scanning any systems or networks. Unauthorized scanning may violate local and international laws.
