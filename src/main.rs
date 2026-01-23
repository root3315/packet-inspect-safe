mod analyzer;
mod error;
mod packet;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process;

use analyzer::{PacketAnalyzer, SecurityAlert};
use clap::{Parser, Subcommand};
use colored::Colorize;
use packet::{IcmpHeader, Packet};

use error::{PacketError, Result};

#[derive(Parser)]
#[command(name = "packet-inspect")]
#[command(author = "Packet Inspect Team")]
#[command(version = "0.1.0")]
#[command(about = "A memory-safe network packet analyzer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Analyze packets from a pcap-like file")]
    Analyze {
        #[arg(short, long, help = "Path to the packet capture file")]
        file: String,

        #[arg(short, long, help = "Output format: text, json", default_value = "text")]
        format: String,

        #[arg(short, long, help = "Show detailed packet information")]
        verbose: bool,
    },

    #[command(about = "Parse a single packet from hex string")]
    Parse {
        #[arg(short, long, help = "Packet data as hex string")]
        hex: String,

        #[arg(short, long, help = "Show raw bytes")]
        raw: bool,
    },

    #[command(about = "Generate sample packet data for testing")]
    Generate {
        #[arg(short, long, help = "Number of packets to generate", default_value = "10")]
        count: usize,

        #[arg(short, long, help = "Output file path (stdout if not specified)")]
        output: Option<String>,
    },

    #[command(about = "Display tool information and capabilities")]
    Info,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Analyze { file, format, verbose } => cmd_analyze(&file, &format, verbose),
        Commands::Parse { hex, raw } => cmd_parse(&hex, raw),
        Commands::Generate { count, output } => cmd_generate(count, output.as_deref()),
        Commands::Info => cmd_info(),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        process::exit(1);
    }
}

fn cmd_analyze(file_path: &str, format: &str, verbose: bool) -> Result<()> {
    if !Path::new(file_path).exists() {
        return Err(PacketError::IoError {
            message: format!("File not found: {}", file_path),
        });
    }

    let file = File::open(file_path).map_err(|e| PacketError::IoError {
        message: format!("Failed to open file: {}", e),
    })?;

    let reader = BufReader::new(file);
    let mut analyzer = PacketAnalyzer::new();
    let mut packet_count = 0;
    let mut error_count = 0;

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| PacketError::IoError {
            message: format!("Failed to read line {}: {}", line_num + 1, e),
        })?;

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let hex_data = trimmed.trim_start_matches("0x").trim_start_matches("0X");
        let packet_data = match hex::decode(hex_data) {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "{} Line {}: Invalid hex data - {}",
                    "Warning:".yellow().bold(),
                    line_num + 1,
                    e
                );
                error_count += 1;
                continue;
            }
        };

        match Packet::parse(&packet_data) {
            Ok(packet) => {
                if verbose {
                    match format {
                        "json" => {
                            println!("{}", packet_to_json(&packet));
                        }
                        _ => {
                            println!("--- Packet {} ---", packet_count + 1);
                            println!("{}", packet);
                        }
                    }
                }

                if let Err(e) = analyzer.analyze_packet(&packet) {
                    eprintln!(
                        "{} Line {}: Analysis error - {}",
                        "Warning:".yellow().bold(),
                        line_num + 1,
                        e
                    );
                    error_count += 1;
                }

                packet_count += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} Line {}: Parse error - {}",
                    "Warning:".yellow().bold(),
                    line_num + 1,
                    e
                );
                error_count += 1;
            }
        }
    }

    analyzer.finalize_statistics();

    println!("\n{}", "=== Analysis Summary ===".green().bold());
    println!("Packets Processed: {}", packet_count.to_string().cyan());
    println!("Parse Errors: {}", error_count.to_string().yellow());
    println!("Flows Detected: {}", analyzer.get_flow_count().to_string().cyan());
    println!("Security Alerts: {}", analyzer.get_alert_count().to_string().red());
    println!("Suspicious IPs: {}", analyzer.get_suspicious_ip_count().to_string().red());

    if !analyzer.alerts.is_empty() {
        println!("\n{}", "=== Security Alerts ===".red().bold());
        for alert in &analyzer.alerts {
            println!(
                "[{}] {}: {} ({} -> {})",
                format_alert_severity(&alert.severity),
                alert.alert_type,
                alert.description,
                alert.source,
                alert.destination
            );
        }
    }

    println!("\n{}", analyzer.statistics);

    Ok(())
}

fn cmd_parse(hex_data: &str, show_raw: bool) -> Result<()> {
    let clean_hex = hex_data.trim_start_matches("0x").trim_start_matches("0X");
    let packet_data = hex::decode(clean_hex).map_err(|e| PacketError::ParseError {
        message: format!("Invalid hex string: {}", e),
    })?;

    if packet_data.is_empty() {
        return Err(PacketError::InsufficientData {
            expected: 14,
            actual: 0,
        });
    }

    match Packet::parse(&packet_data) {
        Ok(packet) => {
            println!("{}", packet);

            if show_raw {
                println!("{}", "=== Raw Bytes ===".bold());
                print_hex_dump(&packet_data);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    Ok(())
}

fn cmd_generate(count: usize, output: Option<&str>) -> Result<()> {
    let mut packets: Vec<String> = Vec::new();

    for i in 0..count {
        let packet = generate_sample_packet(i as u8);
        packets.push(format!("0x{}", hex::encode(&packet)));
    }

    match output {
        Some(path) => {
            let mut file = File::create(path).map_err(|e| PacketError::IoError {
                message: format!("Failed to create file: {}", e),
            })?;

            for packet in &packets {
                writeln!(file, "{}", packet).map_err(|e| PacketError::IoError {
                    message: format!("Failed to write packet: {}", e),
                })?;
            }

            println!(
                "{} Generated {} packets to {}",
                "Success:".green().bold(),
                count,
                path
            );
        }
        None => {
            println!("{}", "# Sample packet data (hex encoded)".italic());
            println!("{}", "# Each line represents one Ethernet frame".italic());
            println!();
            for packet in &packets {
                println!("{}", packet);
            }
        }
    }

    Ok(())
}

fn cmd_info() -> Result<()> {
    println!("{}", "=== Packet Inspect Safe ===".green().bold());
    println!();
    println!("Version: 0.1.0");
    println!("Description: A memory-safe network packet analyzer written in Rust");
    println!();
    println!("{}", "Features:".bold());
    println!("  - Parse Ethernet frames (IPv4, IPv6, ARP)");
    println!("  - Parse IP headers with checksum verification");
    println!("  - Parse TCP and UDP transport headers");
    println!("  - Track network flows and connections");
    println!("  - Detect security anomalies (port scans, SYN floods)");
    println!("  - Generate sample packet data for testing");
    println!();
    println!("{}", "Supported Protocols:".bold());
    println!("  - Ethernet II");
    println!("  - IPv4");
    println!("  - TCP");
    println!("  - UDP");
    println!("  - ICMP (basic)");
    println!("  - ARP");
    println!();
    println!("{}", "Usage Examples:".bold());
    println!("  packet-inspect analyze -f capture.txt -v");
    println!("  packet-inspect parse -x '0x001a2b3c4d5e...'");
    println!("  packet-inspect generate -c 100 -o packets.txt");
    println!("  packet-inspect info");
    println!();
    println!("{}", "Memory Safety:".bold());
    println!("  - No unsafe blocks");
    println!("  - Bounds-checked array access");
    println!("  - Proper error handling with Result types");
    println!("  - Zero-copy parsing where possible");

    Ok(())
}

fn generate_sample_packet(index: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 54];

    packet[0..6].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, index]);
    packet[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x28;
    packet[18] = (index as u16 >> 8) as u8;
    packet[19] = (index as u16 & 0xFF) as u8;
    packet[20..22].copy_from_slice(&[0x40, 0x00]);
    packet[23] = 64;
    packet[24] = 0x06;
    packet[26..30].copy_from_slice(&[192, 168, 1, index.wrapping_add(1)]);
    packet[30..34].copy_from_slice(&[10, 0, 0, index.wrapping_add(100)]);

    let src_port = 1024 + index as u16;
    let dst_port = 80;
    packet[34] = (src_port >> 8) as u8;
    packet[35] = (src_port & 0xFF) as u8;
    packet[36] = (dst_port >> 8) as u8;
    packet[37] = (dst_port & 0xFF) as u8;
    packet[38..42].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet[42..46].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet[46] = 0x50;
    packet[47] = 0x02;
    packet[48] = 0xFF;
    packet[49] = 0xFF;

    packet
}

fn format_alert_severity(severity: &analyzer::AlertSeverity) -> String {
    match severity {
        analyzer::AlertSeverity::Low => "LOW".blue().to_string(),
        analyzer::AlertSeverity::Medium => "MEDIUM".yellow().to_string(),
        analyzer::AlertSeverity::High => "HIGH".red().to_string(),
        analyzer::AlertSeverity::Critical => "CRITICAL".red().bold().to_string(),
    }
}

fn print_hex_dump(data: &[u8]) {
    const BYTES_PER_LINE: usize = 16;

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let offset = i * BYTES_PER_LINE;
        print!("{:08x}  ", offset);

        for byte in chunk {
            print!("{:02x} ", byte);
        }

        for _ in chunk.len()..BYTES_PER_LINE {
            print!("   ");
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

fn packet_to_json(packet: &Packet) -> String {
    use std::fmt::Write;

    let mut json = String::from("{\n");

    let _ = writeln!(
        json,
        "  \"ethernet\": {{\n    \"source_mac\": \"{}\",\n    \"destination_mac\": \"{}\",\n    \"ether_type\": \"0x{:04x}\"\n  }},",
        packet::EthernetHeader::mac_to_string(&packet.ethernet.source_mac),
        packet::EthernetHeader::mac_to_string(&packet.ethernet.destination_mac),
        packet.ethernet.ether_type
    );

    if let Some(ref ip) = packet.ip {
        let _ = writeln!(
            json,
            "  \"ip\": {{\n    \"source\": \"{}\",\n    \"destination\": \"{}\",\n    \"protocol\": {},\n    \"ttl\": {}\n  }},",
            packet::IpHeader::ip_to_string(&ip.source_ip),
            packet::IpHeader::ip_to_string(&ip.destination_ip),
            ip.protocol,
            ip.ttl
        );
    }

    if let Some(ref tcp) = packet.tcp {
        let _ = writeln!(
            json,
            "  \"tcp\": {{\n    \"source_port\": {},\n    \"destination_port\": {},\n    \"flags\": \"{}\"\n  }},",
            tcp.source_port,
            tcp.destination_port,
            tcp.flag_string()
        );
    }

    let _ = writeln!(json, "  \"payload_size\": {}", packet.payload_size());
    let _ = write!(json, "}}");

    json
}

mod hex {
    pub fn decode(hex_str: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        let hex_str = hex_str.replace(" ", "").replace(":", "").replace("-", "");
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect()
    }

    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        let result = hex::decode("48656c6c6f").unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_hex_encode() {
        let result = hex::encode(b"Hello");
        assert_eq!(result, "48656c6c6f");
    }

    #[test]
    fn test_generate_sample_packet() {
        let packet = generate_sample_packet(1);
        assert_eq!(packet.len(), 54);
        assert_eq!(packet[14], 0x45);
    }

    #[test]
    fn test_format_alert_severity() {
        let low = format_alert_severity(&analyzer::AlertSeverity::Low);
        let high = format_alert_severity(&analyzer::AlertSeverity::High);
        assert!(low.contains("LOW"));
        assert!(high.contains("HIGH"));
    }
}
