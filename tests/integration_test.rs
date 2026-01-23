use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_test_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut packet = vec![0u8; 54];

    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x28;
    packet[18..20].copy_from_slice(&[0x00, 0x01]);
    packet[20..22].copy_from_slice(&[0x40, 0x00]);
    packet[23] = 64;
    packet[24] = 0x06;
    packet[26..30].copy_from_slice(src_ip);
    packet[30..34].copy_from_slice(dst_ip);

    packet[34] = (src_port >> 8) as u8;
    packet[35] = (src_port & 0xFF) as u8;
    packet[36] = (dst_port >> 8) as u8;
    packet[37] = (dst_port & 0xFF) as u8;
    packet[38..42].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet[42..46].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet[46] = 0x50;
    packet[47] = flags;
    packet[48] = 0xFF;
    packet[49] = 0xFF;

    packet
}

fn packet_to_hex(packet: &[u8]) -> String {
    packet.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_full_packet_parsing() {
    let src_mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    let dst_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let src_ip = [192, 168, 1, 100];
    let dst_ip = [192, 168, 1, 200];

    let packet = create_test_packet(&src_mac, &dst_mac, &src_ip, &dst_ip, 12345, 80, 0x02);

    let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();

    assert_eq!(
        packet_inspect_safe::packet::EthernetHeader::mac_to_string(&parsed.ethernet.source_mac),
        "00:1a:2b:3c:4d:5e"
    );
    assert_eq!(
        packet_inspect_safe::packet::EthernetHeader::mac_to_string(&parsed.ethernet.destination_mac),
        "00:11:22:33:44:55"
    );
    assert_eq!(parsed.ethernet.ether_type, 0x0800);

    let ip = parsed.ip.unwrap();
    assert_eq!(
        packet_inspect_safe::packet::IpHeader::ip_to_string(&ip.source_ip),
        "192.168.1.100"
    );
    assert_eq!(
        packet_inspect_safe::packet::IpHeader::ip_to_string(&ip.destination_ip),
        "192.168.1.200"
    );
    assert_eq!(ip.protocol, 6);
    assert_eq!(ip.ttl, 64);

    let tcp = parsed.tcp.unwrap();
    assert_eq!(tcp.source_port, 12345);
    assert_eq!(tcp.destination_port, 80);
    assert!(tcp.flag_string().contains("SYN"));
}

#[test]
fn test_udp_packet_parsing() {
    let mut packet = vec![0u8; 42];

    packet[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[6..12].copy_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x1C;
    packet[18..20].copy_from_slice(&[0x00, 0x01]);
    packet[20..22].copy_from_slice(&[0x40, 0x00]);
    packet[23] = 64;
    packet[24] = 0x11;
    packet[26..30].copy_from_slice(&[10, 0, 0, 1]);
    packet[30..34].copy_from_slice(&[10, 0, 0, 2]);

    packet[34] = 0x00;
    packet[35] = 0x35;
    packet[36] = 0x00;
    packet[37] = 0x35;
    packet[38] = 0x00;
    packet[39] = 0x08;

    let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();

    assert!(parsed.ip.is_some());
    assert!(parsed.udp.is_some());
    assert!(parsed.tcp.is_none());

    let udp = parsed.udp.unwrap();
    assert_eq!(udp.source_port, 53);
    assert_eq!(udp.destination_port, 53);
}

#[test]
fn test_analyzer_with_multiple_packets() {
    let mut analyzer = packet_inspect_safe::analyzer::PacketAnalyzer::new();

    let packet1 = create_test_packet(
        &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        &[192, 168, 1, 100],
        &[192, 168, 1, 200],
        12345,
        80,
        0x02,
    );

    let packet2 = create_test_packet(
        &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        &[192, 168, 1, 100],
        &[192, 168, 1, 200],
        12345,
        80,
        0x10,
    );

    let parsed1 = packet_inspect_safe::packet::Packet::parse(&packet1).unwrap();
    let parsed2 = packet_inspect_safe::packet::Packet::parse(&packet2).unwrap();

    analyzer.analyze_packet(&parsed1).unwrap();
    analyzer.analyze_packet(&parsed2).unwrap();
    analyzer.finalize_statistics();

    assert_eq!(analyzer.statistics.total_packets, 2);
    assert_eq!(analyzer.statistics.tcp_stats.syn_packets, 1);
    assert_eq!(analyzer.statistics.tcp_stats.ack_packets, 1);
    assert_eq!(analyzer.get_flow_count(), 1);
}

#[test]
fn test_file_analysis_workflow() {
    let mut temp_file = NamedTempFile::new().unwrap();

    let packet1 = create_test_packet(
        &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        &[192, 168, 1, 100],
        &[192, 168, 1, 200],
        8080,
        443,
        0x18,
    );

    let packet2 = create_test_packet(
        &[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        &[10, 0, 0, 50],
        &[10, 0, 0, 100],
        22,
        54321,
        0x02,
    );

    writeln!(temp_file, "0x{}", packet_to_hex(&packet1)).unwrap();
    writeln!(temp_file, "0x{}", packet_to_hex(&packet2)).unwrap();
    temp_file.flush().unwrap();

    let file_path = temp_file.path().to_str().unwrap();
    let file = File::open(file_path).unwrap();
    let content = std::fs::read_to_string(file_path).unwrap();

    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    for line in lines {
        let hex_data = line.trim_start_matches("0x").trim_start_matches("0X");
        let packet_data = hex::decode(hex_data).unwrap();
        let parsed = packet_inspect_safe::packet::Packet::parse(&packet_data).unwrap();
        assert!(parsed.ip.is_some());
    }
}

#[test]
fn test_error_handling_invalid_packets() {
    let short_packet = vec![0u8; 10];
    let result = packet_inspect_safe::packet::Packet::parse(&short_packet);
    assert!(result.is_err());

    let empty_packet = vec![];
    let result = packet_inspect_safe::packet::Packet::parse(&empty_packet);
    assert!(result.is_err());
}

#[test]
fn test_ipv6_ether_type() {
    let mut packet = vec![0u8; 14];
    packet[0..6].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    packet[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[12] = 0x86;
    packet[13] = 0xDD;

    let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();
    assert_eq!(parsed.ethernet.ether_type, 0x86DD);
    assert_eq!(parsed.ethernet.protocol_name(), "IPv6");
}

#[test]
fn test_arp_ether_type() {
    let mut packet = vec![0u8; 14];
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    packet[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[12] = 0x08;
    packet[13] = 0x06;

    let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();
    assert_eq!(parsed.ethernet.ether_type, 0x0806);
    assert_eq!(parsed.ethernet.protocol_name(), "ARP");
}

#[test]
fn test_statistics_output() {
    let mut analyzer = packet_inspect_safe::analyzer::PacketAnalyzer::new();

    for i in 0..5 {
        let packet = create_test_packet(
            &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, i],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            &[192, 168, 1, 100 + i],
            &[192, 168, 1, 200],
            10000 + i as u16,
            80,
            0x10,
        );

        let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();
        analyzer.analyze_packet(&parsed).unwrap();
    }

    analyzer.finalize_statistics();

    assert_eq!(analyzer.statistics.total_packets, 5);
    assert_eq!(analyzer.statistics.tcp_stats.ack_packets, 5);
    assert!(analyzer.statistics.ip_stats.unique_source_ips.len() >= 1);

    let stats_str = format!("{}", analyzer.statistics);
    assert!(stats_str.contains("Total Packets: 5"));
    assert!(stats_str.contains("TCP Statistics"));
}

#[test]
fn test_flow_tracking_across_packets() {
    let mut analyzer = packet_inspect_safe::analyzer::PacketAnalyzer::new();

    let src_mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
    let dst_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let src_ip = [192, 168, 1, 100];
    let dst_ip = [192, 168, 1, 200];

    let syn_packet = create_test_packet(&src_mac, &dst_mac, &src_ip, &dst_ip, 45678, 443, 0x02);
    let syn_ack_packet = create_test_packet(&dst_mac, &src_mac, &dst_ip, &src_ip, 443, 45678, 0x12);
    let ack_packet = create_test_packet(&src_mac, &dst_mac, &src_ip, &dst_ip, 45678, 443, 0x10);

    for packet_data in [&syn_packet, &syn_ack_packet, &ack_packet] {
        let parsed = packet_inspect_safe::packet::Packet::parse(packet_data).unwrap();
        analyzer.analyze_packet(&parsed).unwrap();
    }

    analyzer.finalize_statistics();

    assert!(analyzer.get_flow_count() >= 1);
    assert_eq!(analyzer.statistics.tcp_stats.syn_packets, 2);
    assert_eq!(analyzer.statistics.tcp_stats.ack_packets, 2);
}

#[test]
fn test_payload_extraction() {
    let mut packet = vec![0u8; 74];

    packet[0..6].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    packet[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x3C;
    packet[18..20].copy_from_slice(&[0x00, 0x01]);
    packet[20..22].copy_from_slice(&[0x40, 0x00]);
    packet[23] = 64;
    packet[24] = 0x06;
    packet[26..30].copy_from_slice(&[192, 168, 1, 100]);
    packet[30..34].copy_from_slice(&[192, 168, 1, 200]);

    packet[34] = 0x1F;
    packet[35] = 0x90;
    packet[36] = 0x00;
    packet[37] = 0x50;
    packet[38..42].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet[42..46].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet[46] = 0x50;
    packet[47] = 0x18;
    packet[48] = 0xFF;
    packet[49] = 0xFF;

    let payload_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    packet[54..54 + payload_data.len()].copy_from_slice(payload_data);

    let parsed = packet_inspect_safe::packet::Packet::parse(&packet).unwrap();

    assert_eq!(parsed.payload_size(), payload_data.len());
    assert_eq!(&parsed.payload, payload_data);
}

mod hex {
    pub fn decode(hex_str: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        let hex_str = hex_str.replace(" ", "").replace(":", "").replace("-", "");
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect()
    }
}
