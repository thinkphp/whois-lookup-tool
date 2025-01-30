# WHOIS and DNS Lookup Tool

A command-line interface (CLI) tool written in Rust for performing WHOIS and DNS lookups. This tool provides a simple way to query domain registration information and DNS records.

## Features

- WHOIS lookup for domains and IP addresses
- DNS record lookups (A, AAAA, MX, TXT, NS, CNAME)
- Automatic fallback to IANA WHOIS server
- Support for multiple TLD-specific WHOIS servers
- Colored output for better readability

## Installation

Ensure you have Rust and Cargo installed on your system. Then clone this repository and build the project:

```bash
git clone git@github.com:thinkphp/whois-lookup-tool.git
cd whois-dns-tool
cargo build --release
```

The compiled binary will be available in `target/release/whois-dns`.

## Usage

### WHOIS Lookup

To perform a WHOIS lookup for a domain or IP address:

```bash
whois-dns whois example.com
```

### DNS Lookup

To perform a DNS lookup:

```bash
whois-dns dns example.com A     # Look up A records
whois-dns dns example.com MX    # Look up MX records
whois-dns dns example.com TXT   # Look up TXT records
```

Supported DNS record types:
- A (IPv4 addresses)
- AAAA (IPv6 addresses)
- MX (Mail exchange servers)
- TXT (Text records)
- NS (Nameservers)
- CNAME (Canonical names)

## Dependencies

- `clap`: Command line argument parsing
- `colored`: Terminal text coloring
- `trust-dns-resolver`: DNS resolution
- `anyhow`: Error handling
- `tokio`: Async runtime

## Error Handling

The tool implements robust error handling:
- Timeout handling for WHOIS queries
- Fallback to IANA WHOIS server when TLD-specific servers fail
- Informative error messages for DNS lookup failures
- Validation of DNS record types

## Supported WHOIS Servers

The tool includes built-in support for various TLD WHOIS servers:
- .com and .net (VeriSign)
- .org (Public Interest Registry)
- .edu (EDUCAUSE)
- .it (NIC.it)
- .uk (Nominet)
- .ru (TCINET)
- .de (DENIC)
- .nl (SIDN)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
