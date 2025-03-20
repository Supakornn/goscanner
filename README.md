# GoScanner

GoScanner is a feature-rich, high-performance network scanning tool built in Go. It provides similar functionality to Nmap but leverages Go's concurrency for improved performance.

## Features

-   Multiple scan techniques: Connect, SYN, FIN, XMAS, NULL, ACK, UDP
-   Fast concurrent scanning
-   Service detection and banner grabbing
-   OS detection
-   Timing templates for stealth or speed
-   Customizable output formats (normal, JSON, XML)
-   Host discovery
-   Direct nmap integration for advanced features

## Installation

```bash
git clone https://github.com/supakornn/goscanner.git
cd goscanner
go build
```

## Usage

Basic usage:

```bash
goscanner -t 192.168.1.1
```

Scan a network range with specific ports:

```bash
goscanner -t 192.168.1.0/24 -p 22,80,443 -T 4
```

Scan with service detection:

```bash
goscanner -t example.com -p 1-1000 -sV -O
```

### Using Nmap Integration

For advanced scanning, you can use nmap directly with all its flags:

```bash
goscanner 192.168.1.1 -- -A -sV -sC
```

Everything after `--` will be passed directly to nmap, giving you the full power of nmap with the GoScanner interface.

## Command-line Options

-   `-t, --target`: Target to scan (IP, hostname, CIDR, or range)
-   `-p, --ports`: Port ranges to scan (e.g., 22-25,80,443-445)
-   `--scan-type`: Scan technique (connect, syn, fin, xmas, null, ack, udp)
-   `-T, --timeout`: Timeout in milliseconds
-   `-c, --concurrent`: Number of concurrent scans
-   `-V, --service-detection`: Probe open ports to determine service/version info
-   `-b, --banner`: Perform banner grabbing
-   `-O, --os-detection`: Enable OS detection
-   `-n, --skip-host-discovery`: Skip host discovery (treat all hosts as online)
-   `-C, --script`: Run default scripts
-   `--traceroute`: Trace hop path to target
-   `-o, --output-format`: Output format (normal, json, xml)
-   `-f, --output-file`: Write output to file
-   `-- [nmap flags]`: Use nmap directly with specified flags

## License

MIT
