# Goscanner

<p align="center" style="font-size: 22px; font-weight: bold;">A Port scanner written in Go.</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
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
