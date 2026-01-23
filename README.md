# Packet Inspect Safe

A memory-safe network packet analyzer written in Rust.

## Description

Packet Inspect Safe is a command-line tool for analyzing network packet captures. It provides detailed parsing of Ethernet frames, IP packets, and TCP/UDP transport headers, along with statistical analysis and security anomaly detection.

Built with Rust's memory safety guarantees, this tool ensures:
- No buffer overflows
- No use-after-free vulnerabilities
- No null pointer dereferences
- Thread-safe by default

## Features

- **Packet Parsing**: Parse Ethernet, IPv4, TCP, UDP, and ICMP headers
- **Flow Tracking**: Track network flows and connections
- **Statistics**: Generate comprehensive traffic statistics
- **Security Analysis**: Detect potential security anomalies including:
  - Port scans
  - SYN flood attacks
  - Unusual TTL values
  - Suspicious port usage
  - Large payload detection
- **Multiple Output Formats**: Text and JSON output options
- **Sample Generation**: Generate test packet data for development

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo package manager

### Build from Source

```bash
git clone https://github.com/example/packet-inspect-safe.git
cd packet-inspect-safe
cargo build --release
```

The binary will be available at `target/release/packet-inspect`.

### Install via Cargo

```bash
cargo install --path .
```

## Usage

### Analyze Packet Capture File

```bash
packet-inspect analyze -f capture.txt -v
```

Options:
- `-f, --file <FILE>`: Path to the packet capture file (required)
- `-v, --verbose`: Show detailed packet information
- `--format <FORMAT>`: Output format: text, json (default: text)

### Parse Single Packet from Hex

```bash
packet-inspect parse -x "0x001a2b3c4d5e00112233445508004500..."
```

Options:
- `-x, --hex <HEX>`: Packet data as hex string (required)
- `-r, --raw`: Show raw bytes in hex dump format

### Generate Sample Packets

```bash
packet-inspect generate -c 100 -o packets.txt
```

Options:
- `-c, --count <COUNT>`: Number of packets to generate (default: 10)
- `-o, --output <FILE>`: Output file path (stdout if not specified)

### Display Tool Information

```bash
packet-inspect info
```

## Input File Format

The analyzer accepts text files with one packet per line. Each line should contain:
- Optional `0x` or `0X` prefix
- Hex-encoded packet data (Ethernet frame)
- Comments starting with `#` are ignored
- Empty lines are skipped

Example capture file:
```
# Sample TCP SYN packet
0x001a2b3c4d5e0011223344550800450000280001400040060000c0a80164c0a801c83039005000000001000000005002ffff000000000000

# Sample UDP packet
0x00112233445500aabbccddeeff08004500001c00014000401100000a0000010a0000020035003500080000
```

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│                    (main.rs)                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Packet    │  │  Analyzer   │  │      Error          │ │
│  │   Parser    │  │   Module    │  │     Handling        │ │
│  │  (packet.rs)│  │(analyzer.rs)│  │    (error.rs)       │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Packet Parsing Flow

1. **Ethernet Layer**: Parse 14-byte Ethernet header
   - Extract source/destination MAC addresses
   - Determine EtherType (IPv4, IPv6, ARP)

2. **IP Layer**: Parse IPv4 header (20+ bytes)
   - Extract source/destination IP addresses
   - Verify header checksum
   - Determine transport protocol

3. **Transport Layer**: Parse TCP or UDP header
   - Extract port numbers
   - Parse TCP flags and sequence numbers
   - Calculate header lengths

4. **Payload**: Extract application data

### Security Detection

The analyzer maintains state across packets to detect:

- **Port Scans**: Track unique destination ports per source IP
- **SYN Floods**: Count SYN packets per source IP
- **Suspicious Ports**: Flag traffic on known malicious ports
- **TTL Anomalies**: Alert on unusually low TTL values

## Project Structure

```
packet-inspect-safe/
├── Cargo.toml           # Project configuration
├── Cargo.lock           # Dependency versions
├── README.md            # This file
├── src/
│   ├── main.rs          # CLI entry point
│   ├── packet.rs        # Packet parsing logic
│   ├── analyzer.rs      # Analysis and statistics
│   └── error.rs         # Error types
└── tests/
    └── integration_test.rs  # Integration tests
```

## Testing

Run all tests:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

Run specific test:

```bash
cargo test test_full_packet_parsing
```

## Example Output

```
=== Analysis Summary ===
Packets Processed: 150
Parse Errors: 0
Flows Detected: 23
Security Alerts: 3
Suspicious IPs: 1

=== Security Alerts ===
[MEDIUM] Port Scan: Potential port scan from 192.168.1.50 (25 ports) (192.168.1.50 -> )
[LOW] Unusual TTL: Low TTL value detected: 5 (10.0.0.5 -> 192.168.1.1)

=== Packet Statistics ===
Total Packets: 150
Total Bytes: 12450

--- Ethernet Statistics ---
  IPv4 Packets: 145
  IPv6 Packets: 0
  ARP Packets: 5
  Unique MACs: 12

--- IP Statistics ---
  TCP Packets: 120
  UDP Packets: 25
  ICMP Packets: 0
  Unique Source IPs: 8
  Unique Dest IPs: 15

--- TCP Statistics ---
  SYN Packets: 35
  ACK Packets: 95
  FIN Packets: 12
  RST Packets: 3
  Unique Ports: 45

--- Payload Statistics ---
  Total Bytes: 8500
  Average Size: 70.83
  Max Size: 1460
  Min Size: 0
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Submit a pull request

## Safety Guarantees

This project adheres to Rust's memory safety principles:

- **No `unsafe` blocks**: All code uses safe Rust
- **Bounds checking**: All array/slice access is checked
- **Error handling**: Comprehensive `Result` types throughout
- **No panics in production**: All errors are handled gracefully
