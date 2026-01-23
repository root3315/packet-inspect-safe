use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::packet::{EthernetHeader, IcmpHeader, IcmpRest, IpHeader, Packet, TcpHeader, UdpHeader};

/// Statistics collected from packet analysis
#[derive(Debug, Clone, Default)]
pub struct PacketStatistics {
    pub total_packets: usize,
    pub total_bytes: usize,
    pub ethernet_stats: EthernetStatistics,
    pub ip_stats: IpStatistics,
    pub tcp_stats: TcpStatistics,
    pub udp_stats: UdpStatistics,
    pub payload_stats: PayloadStatistics,
}

#[derive(Debug, Clone, Default)]
pub struct EthernetStatistics {
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub arp_packets: usize,
    pub other_packets: usize,
    pub unique_macs: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IpStatistics {
    pub tcp_packets: usize,
    pub udp_packets: usize,
    pub icmp_packets: usize,
    pub other_packets: usize,
    pub unique_source_ips: HashSet<String>,
    pub unique_dest_ips: HashSet<String>,
    pub ttl_values: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct TcpStatistics {
    pub syn_packets: usize,
    pub ack_packets: usize,
    pub fin_packets: usize,
    pub rst_packets: usize,
    pub psh_packets: usize,
    pub unique_ports: HashSet<u16>,
    pub port_counts: HashMap<u16, usize>,
}

#[derive(Debug, Clone, Default)]
pub struct UdpStatistics {
    pub total_packets: usize,
    pub unique_ports: HashSet<u16>,
    pub port_counts: HashMap<u16, usize>,
}

#[derive(Debug, Clone, Default)]
pub struct PayloadStatistics {
    pub total_payload_bytes: usize,
    pub average_payload_size: f64,
    pub max_payload_size: usize,
    pub min_payload_size: usize,
    pub payload_sizes: Vec<usize>,
}

/// Security analysis results
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub severity: AlertSeverity,
    pub alert_type: AlertType,
    pub description: String,
    pub source: String,
    pub destination: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertType {
    PortScan,
    SynFlood,
    UnusualTtl,
    LargePayload,
    SuspiciousPort,
    BroadcastStorm,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertType::PortScan => write!(f, "Port Scan"),
            AlertType::SynFlood => write!(f, "SYN Flood"),
            AlertType::UnusualTtl => write!(f, "Unusual TTL"),
            AlertType::LargePayload => write!(f, "Large Payload"),
            AlertType::SuspiciousPort => write!(f, "Suspicious Port"),
            AlertType::BroadcastStorm => write!(f, "Broadcast Storm"),
        }
    }
}

/// Traffic flow representation
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub key: FlowKey,
    pub packet_count: usize,
    pub byte_count: usize,
    pub first_seen: u64,
    pub last_seen: u64,
    pub flags_seen: u8,
}

/// Main packet analyzer struct
pub struct PacketAnalyzer {
    pub statistics: PacketStatistics,
    pub flows: HashMap<FlowKey, Flow>,
    pub alerts: Vec<SecurityAlert>,
    pub suspicious_ips: HashSet<String>,
    syn_counts: HashMap<String, usize>,
    port_scan_tracker: HashMap<String, HashSet<u16>>,
    icmp_echo_tracker: HashMap<String, usize>,
    icmp_unreachable_tracker: HashMap<String, usize>,
    icmp_time_exceeded_count: usize,
}

impl PacketAnalyzer {
    pub fn new() -> Self {
        PacketAnalyzer {
            statistics: PacketStatistics::default(),
            flows: HashMap::new(),
            alerts: Vec::new(),
            suspicious_ips: HashSet::new(),
            syn_counts: HashMap::new(),
            port_scan_tracker: HashMap::new(),
            icmp_echo_tracker: HashMap::new(),
            icmp_unreachable_tracker: HashMap::new(),
            icmp_time_exceeded_count: 0,
        }
    }

    pub fn analyze_packet(&mut self, packet: &Packet) -> Result<()> {
        self.statistics.total_packets += 1;
        self.statistics.total_bytes += packet.total_size();

        self.analyze_ethernet(&packet.ethernet);

        if let Some(ref ip) = packet.ip {
            self.analyze_ip(ip);

            if let Some(ref tcp) = packet.tcp {
                self.analyze_tcp(tcp, ip);
            }

            if let Some(ref udp) = packet.udp {
                self.analyze_udp(udp, ip);
            }

            if let Some(ref icmp) = packet.icmp {
                self.analyze_icmp(icmp, ip);
            }
        }

        self.analyze_payload(&packet.payload);

        self.detect_anomalies(packet);

        Ok(())
    }

    fn analyze_ethernet(&mut self, ethernet: &EthernetHeader) {
        let src_mac = EthernetHeader::mac_to_string(&ethernet.source_mac);
        let dst_mac = EthernetHeader::mac_to_string(&ethernet.destination_mac);

        self.statistics.ethernet_stats.unique_macs.insert(src_mac);
        self.statistics.ethernet_stats.unique_macs.insert(dst_mac);

        match ethernet.ether_type {
            EthernetHeader::IPV4_ETHER_TYPE => self.statistics.ethernet_stats.ipv4_packets += 1,
            EthernetHeader::IPV6_ETHER_TYPE => self.statistics.ethernet_stats.ipv6_packets += 1,
            EthernetHeader::ARP_ETHER_TYPE => self.statistics.ethernet_stats.arp_packets += 1,
            _ => self.statistics.ethernet_stats.other_packets += 1,
        }
    }

    fn analyze_ip(&mut self, ip: &IpHeader) {
        let src_ip = IpHeader::ip_to_string(&ip.source_ip);
        let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

        self.statistics.ip_stats.unique_source_ips.insert(src_ip.clone());
        self.statistics.ip_stats.unique_dest_ips.insert(dst_ip.clone());
        self.statistics.ip_stats.ttl_values.push(ip.ttl);

        match ip.protocol {
            IpHeader::TCP_PROTOCOL => self.statistics.ip_stats.tcp_packets += 1,
            IpHeader::UDP_PROTOCOL => self.statistics.ip_stats.udp_packets += 1,
            IpHeader::ICMP_PROTOCOL => self.statistics.ip_stats.icmp_packets += 1,
            _ => self.statistics.ip_stats.other_packets += 1,
        }

        if ip.ttl < 10 {
            self.create_alert(
                AlertSeverity::Low,
                AlertType::UnusualTtl,
                format!("Low TTL value detected: {}", ip.ttl),
                src_ip,
                dst_ip,
            );
        }
    }

    fn analyze_tcp(&mut self, tcp: &TcpHeader, ip: &IpHeader) {
        let src_ip = IpHeader::ip_to_string(&ip.source_ip);
        let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

        self.statistics.tcp_stats.unique_ports.insert(tcp.source_port);
        self.statistics.tcp_stats.unique_ports.insert(tcp.destination_port);

        *self.statistics.tcp_stats.port_counts.entry(tcp.source_port).or_insert(0) += 1;
        *self.statistics.tcp_stats.port_counts.entry(tcp.destination_port).or_insert(0) += 1;

        if tcp.flags & TcpHeader::SYN != 0 {
            self.statistics.tcp_stats.syn_packets += 1;

            let syn_count = self.syn_counts.entry(src_ip.clone()).or_insert(0);
            *syn_count += 1;

            if *syn_count > 100 {
                self.create_alert(
                    AlertSeverity::High,
                    AlertType::SynFlood,
                    format!("Potential SYN flood from {}", src_ip),
                    src_ip.clone(),
                    dst_ip.clone(),
                );
                self.suspicious_ips.insert(src_ip.clone());
            }
        }

        if tcp.flags & TcpHeader::ACK != 0 {
            self.statistics.tcp_stats.ack_packets += 1;
        }
        if tcp.flags & TcpHeader::FIN != 0 {
            self.statistics.tcp_stats.fin_packets += 1;
        }
        if tcp.flags & TcpHeader::RST != 0 {
            self.statistics.tcp_stats.rst_packets += 1;
        }
        if tcp.flags & TcpHeader::PSH != 0 {
            self.statistics.tcp_stats.psh_packets += 1;
        }

        self.track_port_scan(&src_ip, tcp.destination_port);
        self.update_flow(ip, tcp.source_port, tcp.destination_port, IpHeader::TCP_PROTOCOL, tcp.flags);
    }

    fn analyze_udp(&mut self, udp: &UdpHeader, ip: &IpHeader) {
        let src_ip = IpHeader::ip_to_string(&ip.source_ip);
        let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

        self.statistics.udp_stats.total_packets += 1;
        self.statistics.udp_stats.unique_ports.insert(udp.source_port);
        self.statistics.udp_stats.unique_ports.insert(udp.destination_port);

        *self.statistics.udp_stats.port_counts.entry(udp.source_port).or_insert(0) += 1;
        *self.statistics.udp_stats.port_counts.entry(udp.destination_port).or_insert(0) += 1;

        self.update_flow(ip, udp.source_port, udp.destination_port, IpHeader::UDP_PROTOCOL, 0);
    }

    fn analyze_icmp(&mut self, icmp: &IcmpHeader, ip: &IpHeader) {
        let src_ip = IpHeader::ip_to_string(&ip.source_ip);
        let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

        match icmp.icmp_type {
            IcmpHeader::ECHO_REQUEST | IcmpHeader::ECHO_REPLY => {
                if let IcmpRest::Echo { identifier, sequence_number } = &icmp.rest {
                    self.icmp_echo_tracker
                        .entry(src_ip.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);

                    if *self.icmp_echo_tracker.get(&src_ip).unwrap_or(&0) > 100 {
                        self.create_alert(
                            AlertSeverity::Medium,
                            AlertType::SuspiciousPort,
                            format!("High rate of ICMP Echo from {}", src_ip),
                            src_ip.clone(),
                            dst_ip.clone(),
                        );
                    }
                }
            }
            IcmpHeader::DESTINATION_UNREACHABLE => {
                self.icmp_unreachable_tracker
                    .entry(dst_ip.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }
            IcmpHeader::TIME_EXCEEDED => {
                self.icmp_time_exceeded_count += 1;
            }
            _ => {}
        }
    }

    fn analyze_payload(&mut self, payload: &[u8]) {
        let payload_size = payload.len();
        self.statistics.payload_stats.total_payload_bytes += payload_size;
        self.statistics.payload_stats.payload_sizes.push(payload_size);

        if payload_size > self.statistics.payload_stats.max_payload_size {
            self.statistics.payload_stats.max_payload_size = payload_size;
        }

        if self.statistics.payload_stats.min_payload_size == 0
            || payload_size < self.statistics.payload_stats.min_payload_size
        {
            self.statistics.payload_stats.min_payload_size = payload_size;
        }
    }

    fn update_flow(
        &mut self,
        ip: &IpHeader,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        flags: u8,
    ) {
        let src_ip = IpHeader::ip_to_string(&ip.source_ip);
        let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

        let key = FlowKey {
            source_ip: src_ip.clone(),
            destination_ip: dst_ip.clone(),
            source_port: src_port,
            destination_port: dst_port,
            protocol,
        };

        let timestamp = self.get_timestamp();

        self.flows
            .entry(key)
            .and_modify(|flow| {
                flow.packet_count += 1;
                flow.byte_count += ip.total_length as usize;
                flow.last_seen = timestamp;
                flow.flags_seen |= flags;
            })
            .or_insert(Flow {
                key,
                packet_count: 1,
                byte_count: ip.total_length as usize,
                first_seen: timestamp,
                last_seen: timestamp,
                flags_seen: flags,
            });
    }

    fn track_port_scan(&mut self, src_ip: &str, dst_port: u16) {
        let ports = self.port_scan_tracker.entry(src_ip.to_string()).or_insert_with(HashSet::new);
        ports.insert(dst_port);

        if ports.len() > 20 {
            self.create_alert(
                AlertSeverity::Medium,
                AlertType::PortScan,
                format!("Potential port scan from {} ({} ports)", src_ip, ports.len()),
                src_ip.to_string(),
                String::new(),
            );
            self.suspicious_ips.insert(src_ip.to_string());
        }
    }

    fn detect_anomalies(&mut self, packet: &Packet) {
        if let Some(ref ip) = packet.ip {
            let src_ip = IpHeader::ip_to_string(&ip.source_ip);
            let dst_ip = IpHeader::ip_to_string(&ip.destination_ip);

            if packet.payload_size() > 9000 {
                self.create_alert(
                    AlertSeverity::Medium,
                    AlertType::LargePayload,
                    format!("Large payload detected: {} bytes", packet.payload_size()),
                    src_ip,
                    dst_ip,
                );
            }

            if self.is_suspicious_port(packet) {
                self.create_alert(
                    AlertSeverity::Low,
                    AlertType::SuspiciousPort,
                    format!("Traffic on suspicious port"),
                    src_ip,
                    dst_ip,
                );
            }
        }
    }

    fn is_suspicious_port(&self, packet: &Packet) -> bool {
        const SUSPICIOUS_PORTS: &[u16] = &[
            23,  // Telnet
            445, // SMB
            3389, // RDP
            4444, // Metasploit default
            5555, // Android Debug Bridge
            6666, // IRC
            6667, // IRC
            31337, // Back Orifice
        ];

        if let Some(ref tcp) = packet.tcp {
            return SUSPICIOUS_PORTS.contains(&tcp.source_port)
                || SUSPICIOUS_PORTS.contains(&tcp.destination_port);
        }

        if let Some(ref udp) = packet.udp {
            return SUSPICIOUS_PORTS.contains(&udp.source_port)
                || SUSPICIOUS_PORTS.contains(&udp.destination_port);
        }

        false
    }

    fn create_alert(
        &mut self,
        severity: AlertSeverity,
        alert_type: AlertType,
        description: String,
        source: String,
        destination: String,
    ) {
        let alert = SecurityAlert {
            severity,
            alert_type,
            description,
            source,
            destination,
            timestamp: self.get_timestamp(),
        };

        if !self.alerts.iter().any(|a| {
            a.alert_type == alert.alert_type
                && a.source == alert.source
                && a.description == alert.description
        }) {
            self.alerts.push(alert);
        }
    }

    fn get_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn finalize_statistics(&mut self) {
        let sizes = &self.statistics.payload_stats.payload_sizes;
        if !sizes.is_empty() {
            let sum: usize = sizes.iter().sum();
            self.statistics.payload_stats.average_payload_size = sum as f64 / sizes.len() as f64;
        }
    }

    pub fn get_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn get_alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn get_suspicious_ip_count(&self) -> usize {
        self.suspicious_ips.len()
    }
}

impl Default for PacketAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PacketStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Packet Statistics ===")?;
        writeln!(f, "Total Packets: {}", self.total_packets)?;
        writeln!(f, "Total Bytes: {}", self.total_bytes)?;
        writeln!(f)?;
        writeln!(f, "--- Ethernet Statistics ---")?;
        writeln!(f, "  IPv4 Packets: {}", self.ethernet_stats.ipv4_packets)?;
        writeln!(f, "  IPv6 Packets: {}", self.ethernet_stats.ipv6_packets)?;
        writeln!(f, "  ARP Packets: {}", self.ethernet_stats.arp_packets)?;
        writeln!(f, "  Unique MACs: {}", self.ethernet_stats.unique_macs.len())?;
        writeln!(f)?;
        writeln!(f, "--- IP Statistics ---")?;
        writeln!(f, "  TCP Packets: {}", self.ip_stats.tcp_packets)?;
        writeln!(f, "  UDP Packets: {}", self.ip_stats.udp_packets)?;
        writeln!(f, "  ICMP Packets: {}", self.ip_stats.icmp_packets)?;
        writeln!(f, "  Unique Source IPs: {}", self.ip_stats.unique_source_ips.len())?;
        writeln!(f, "  Unique Dest IPs: {}", self.ip_stats.unique_dest_ips.len())?;
        writeln!(f)?;
        writeln!(f, "--- TCP Statistics ---")?;
        writeln!(f, "  SYN Packets: {}", self.tcp_stats.syn_packets)?;
        writeln!(f, "  ACK Packets: {}", self.tcp_stats.ack_packets)?;
        writeln!(f, "  FIN Packets: {}", self.tcp_stats.fin_packets)?;
        writeln!(f, "  RST Packets: {}", self.tcp_stats.rst_packets)?;
        writeln!(f, "  Unique Ports: {}", self.tcp_stats.unique_ports.len())?;
        writeln!(f)?;
        writeln!(f, "--- UDP Statistics ---")?;
        writeln!(f, "  Total Packets: {}", self.udp_stats.total_packets)?;
        writeln!(f, "  Unique Ports: {}", self.udp_stats.unique_ports.len())?;
        writeln!(f)?;
        writeln!(f, "--- Payload Statistics ---")?;
        writeln!(f, "  Total Bytes: {}", self.payload_stats.total_payload_bytes)?;
        writeln!(f, "  Average Size: {:.2}", self.payload_stats.average_payload_size)?;
        writeln!(f, "  Max Size: {}", self.payload_stats.max_payload_size)?;
        writeln!(f, "  Min Size: {}", self.payload_stats.min_payload_size)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{EthernetHeader, IpHeader, TcpHeader};

    fn create_test_packet(src_port: u16, dst_port: u16, flags: u8) -> Packet {
        let mut data = vec![0u8; 54];

        data[0..6].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        data[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[12] = 0x08;
        data[13] = 0x00;

        data[14] = 0x45;
        data[15] = 0x00;
        data[16] = 0x00;
        data[17] = 0x28;
        data[23] = 0x06;
        data[26..30].copy_from_slice(&[192, 168, 1, 100]);
        data[30..34].copy_from_slice(&[192, 168, 1, 200]);

        data[34] = (src_port >> 8) as u8;
        data[35] = (src_port & 0xFF) as u8;
        data[36] = (dst_port >> 8) as u8;
        data[37] = (dst_port & 0xFF) as u8;
        data[46] = 0x50;
        data[47] = flags;

        Packet::parse(&data).unwrap()
    }

    #[test]
    fn test_analyzer_initialization() {
        let analyzer = PacketAnalyzer::new();
        assert_eq!(analyzer.statistics.total_packets, 0);
        assert_eq!(analyzer.get_flow_count(), 0);
        assert_eq!(analyzer.get_alert_count(), 0);
    }

    #[test]
    fn test_analyze_single_packet() {
        let mut analyzer = PacketAnalyzer::new();
        let packet = create_test_packet(80, 12345, TcpHeader::SYN);

        analyzer.analyze_packet(&packet).unwrap();

        assert_eq!(analyzer.statistics.total_packets, 1);
        assert_eq!(analyzer.statistics.tcp_stats.syn_packets, 1);
    }

    #[test]
    fn test_flow_tracking() {
        let mut analyzer = PacketAnalyzer::new();
        let packet1 = create_test_packet(80, 12345, TcpHeader::SYN);
        let packet2 = create_test_packet(80, 12345, TcpHeader::ACK);

        analyzer.analyze_packet(&packet1).unwrap();
        analyzer.analyze_packet(&packet2).unwrap();

        assert_eq!(analyzer.get_flow_count(), 1);
        let flow = analyzer.flows.values().next().unwrap();
        assert_eq!(flow.packet_count, 2);
    }

    #[test]
    fn test_statistics_display() {
        let stats = PacketStatistics::default();
        let display = format!("{}", stats);
        assert!(display.contains("Packet Statistics"));
        assert!(display.contains("Total Packets:"));
    }

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(format!("{}", AlertSeverity::High), "HIGH");
        assert_eq!(format!("{}", AlertSeverity::Low), "LOW");
    }

    #[test]
    fn test_alert_type_display() {
        assert_eq!(format!("{}", AlertType::PortScan), "Port Scan");
        assert_eq!(format!("{}", AlertType::SynFlood), "SYN Flood");
    }
}
