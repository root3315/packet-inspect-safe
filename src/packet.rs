use byteorder::{BigEndian, ReadBytesExt};
use std::fmt;
use std::io::Cursor;

use crate::error::{PacketError, Result};

/// Ethernet header structure (14 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct EthernetHeader {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub const HEADER_SIZE: usize = 14;
    pub const IPV4_ETHER_TYPE: u16 = 0x0800;
    pub const IPV6_ETHER_TYPE: u16 = 0x86DD;
    pub const ARP_ETHER_TYPE: u16 = 0x0806;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let mut destination_mac = [0u8; 6];
        let mut source_mac = [0u8; 6];

        cursor.read_exact(&mut destination_mac).map_err(|e| PacketError::ParseError {
            message: format!("Failed to read destination MAC: {}", e),
        })?;
        cursor.read_exact(&mut source_mac).map_err(|e| PacketError::ParseError {
            message: format!("Failed to read source MAC: {}", e),
        })?;
        let ether_type = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read EtherType: {}", e),
        })?;

        Ok(EthernetHeader {
            destination_mac,
            source_mac,
            ether_type,
        })
    }

    pub fn mac_to_string(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.ether_type {
            Self::IPV4_ETHER_TYPE => "IPv4",
            Self::IPV6_ETHER_TYPE => "IPv6",
            Self::ARP_ETHER_TYPE => "ARP",
            _ => "Unknown",
        }
    }
}

/// IPv4 header structure
#[derive(Debug, Clone, PartialEq)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub options: Vec<u8>,
}

impl IpHeader {
    pub const MIN_HEADER_SIZE: usize = 20;
    pub const TCP_PROTOCOL: u8 = 6;
    pub const UDP_PROTOCOL: u8 = 17;
    pub const ICMP_PROTOCOL: u8 = 1;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                expected: Self::MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(PacketError::UnsupportedIpVersion { version });
        }

        let ihl = data[0] & 0x0F;
        let header_length = (ihl as usize) * 4;

        if data.len() < header_length {
            return Err(PacketError::InsufficientData {
                expected: header_length,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let version_ihl = cursor.read_u8().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read version/IHL: {}", e),
        })?;
        let dscp_ecn = cursor.read_u8().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read DSCP/ECN: {}", e),
        })?;
        let total_length = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read total length: {}", e),
        })?;
        let identification = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read identification: {}", e),
        })?;
        let flags_fragment = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read flags/fragment: {}", e),
        })?;
        let ttl = cursor.read_u8().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read TTL: {}", e),
        })?;
        let protocol = cursor.read_u8().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read protocol: {}", e),
        })?;
        let header_checksum = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read checksum: {}", e),
        })?;
        let mut source_ip = [0u8; 4];
        cursor.read_exact(&mut source_ip).map_err(|e| PacketError::ParseError {
            message: format!("Failed to read source IP: {}", e),
        })?;
        let mut destination_ip = [0u8; 4];
        cursor.read_exact(&mut destination_ip).map_err(|e| PacketError::ParseError {
            message: format!("Failed to read destination IP: {}", e),
        })?;

        let mut options = Vec::new();
        if header_length > Self::MIN_HEADER_SIZE {
            let options_len = header_length - Self::MIN_HEADER_SIZE;
            options.resize(options_len, 0);
            cursor.read_exact(&mut options).map_err(|e| PacketError::ParseError {
                message: format!("Failed to read options: {}", e),
            })?;
        }

        Ok(IpHeader {
            version,
            ihl,
            dscp: (dscp_ecn >> 2) & 0x3F,
            ecn: dscp_ecn & 0x03,
            total_length,
            identification,
            flags: ((flags_fragment >> 13) & 0x07) as u8,
            fragment_offset: flags_fragment & 0x1FFF,
            ttl,
            protocol,
            header_checksum,
            source_ip,
            destination_ip,
            options,
        })
    }

    pub fn ip_to_string(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            Self::TCP_PROTOCOL => "TCP",
            Self::UDP_PROTOCOL => "UDP",
            Self::ICMP_PROTOCOL => "ICMP",
            _ => "Unknown",
        }
    }

    pub fn header_length(&self) -> usize {
        (self.ihl as usize) * 4
    }

    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        let header_len = self.header_length();
        if data.len() < header_len {
            return false;
        }

        let mut sum: u32 = 0;
        for i in (0..header_len).step_by(2) {
            if i + 1 < header_len {
                sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            }
        }

        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !((sum ^ 0xFFFF) as u16 != 0 && self.header_checksum != 0)
    }
}

/// TCP header structure
#[derive(Debug, Clone, PartialEq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
}

impl TcpHeader {
    pub const MIN_HEADER_SIZE: usize = 20;
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                expected: Self::MIN_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let source_port = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read source port: {}", e),
        })?;
        let destination_port = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read destination port: {}", e),
        })?;
        let sequence_number = cursor.read_u32::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read sequence number: {}", e),
        })?;
        let acknowledgment_number = cursor.read_u32::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read ACK number: {}", e),
        })?;
        let data_offset_flags = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read data offset/flags: {}", e),
        })?;
        let window_size = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read window size: {}", e),
        })?;
        let checksum = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read checksum: {}", e),
        })?;
        let urgent_pointer = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read urgent pointer: {}", e),
        })?;

        let data_offset = ((data_offset_flags >> 12) & 0x0F) as u8;
        let flags = (data_offset_flags & 0x3F) as u8;
        let header_length = (data_offset as usize) * 4;

        let mut options = Vec::new();
        if header_length > Self::MIN_HEADER_SIZE && data.len() >= header_length {
            let options_len = header_length - Self::MIN_HEADER_SIZE;
            options.resize(options_len, 0);
            cursor.read_exact(&mut options).map_err(|e| PacketError::ParseError {
                message: format!("Failed to read TCP options: {}", e),
            })?;
        }

        Ok(TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        })
    }

    pub fn flag_string(&self) -> String {
        let mut flags = String::new();
        if self.flags & Self::FIN != 0 {
            flags.push_str("FIN ");
        }
        if self.flags & Self::SYN != 0 {
            flags.push_str("SYN ");
        }
        if self.flags & Self::RST != 0 {
            flags.push_str("RST ");
        }
        if self.flags & Self::PSH != 0 {
            flags.push_str("PSH ");
        }
        if self.flags & Self::ACK != 0 {
            flags.push_str("ACK ");
        }
        if self.flags & Self::URG != 0 {
            flags.push_str("URG ");
        }
        flags.trim().to_string()
    }

    pub fn header_length(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// UDP header structure
#[derive(Debug, Clone, PartialEq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub const HEADER_SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let source_port = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read source port: {}", e),
        })?;
        let destination_port = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read destination port: {}", e),
        })?;
        let length = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read length: {}", e),
        })?;
        let checksum = cursor.read_u16::<BigEndian>().map_err(|e| PacketError::ParseError {
            message: format!("Failed to read checksum: {}", e),
        })?;

        Ok(UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        })
    }
}

/// Represents a fully parsed packet with all headers
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub ethernet: EthernetHeader,
    pub ip: Option<IpHeader>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
    pub payload: Vec<u8>,
    pub raw_data: Vec<u8>,
}

impl Packet {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < EthernetHeader::HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                expected: EthernetHeader::HEADER_SIZE,
                actual: data.len(),
            });
        }

        let ethernet = EthernetHeader::parse(data)?;
        let mut ip: Option<IpHeader> = None;
        let mut tcp: Option<TcpHeader> = None;
        let mut udp: Option<UdpHeader> = None;
        let mut payload: Vec<u8> = Vec::new();

        if ethernet.ether_type == EthernetHeader::IPV4_ETHER_TYPE {
            let ip_start = EthernetHeader::HEADER_SIZE;
            if data.len() > ip_start {
                ip = Some(IpHeader::parse(&data[ip_start..])?);

                if let Some(ref ip_header) = ip {
                    let ip_header_len = ip_header.header_length();
                    let transport_start = ip_start + ip_header_len;

                    match ip_header.protocol {
                        IpHeader::TCP_PROTOCOL => {
                            if data.len() > transport_start {
                                tcp = Some(TcpHeader::parse(&data[transport_start..])?);
                                if let Some(ref tcp_header) = tcp {
                                    let tcp_header_len = tcp_header.header_length();
                                    let payload_start = transport_start + tcp_header_len;
                                    if data.len() > payload_start {
                                        payload = data[payload_start..].to_vec();
                                    }
                                }
                            }
                        }
                        IpHeader::UDP_PROTOCOL => {
                            if data.len() > transport_start {
                                udp = Some(UdpHeader::parse(&data[transport_start..])?);
                                if let Some(ref udp_header) = udp {
                                    let payload_start = transport_start + UdpHeader::HEADER_SIZE;
                                    if data.len() > payload_start {
                                        payload = data[payload_start..].to_vec();
                                    }
                                }
                            }
                        }
                        _ => {
                            if data.len() > transport_start {
                                payload = data[transport_start..].to_vec();
                            }
                        }
                    }
                }
            }
        } else {
            payload = data[EthernetHeader::HEADER_SIZE..].to_vec();
        }

        Ok(Packet {
            ethernet,
            ip,
            tcp,
            udp,
            payload,
            raw_data: data.to_vec(),
        })
    }

    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }

    pub fn total_size(&self) -> usize {
        self.raw_data.len()
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Ethernet Frame:")?;
        writeln!(
            f,
            "  Source MAC:      {}",
            EthernetHeader::mac_to_string(&self.ethernet.source_mac)
        )?;
        writeln!(
            f,
            "  Destination MAC: {}",
            EthernetHeader::mac_to_string(&self.ethernet.destination_mac)
        )?;
        writeln!(f, "  EtherType:     {} ({})", self.ethernet.ether_type, self.ethernet.protocol_name())?;

        if let Some(ref ip) = self.ip {
            writeln!(f, "\nIPv4 Header:")?;
            writeln!(f, "  Source IP:      {}", IpHeader::ip_to_string(&ip.source_ip))?;
            writeln!(f, "  Destination IP: {}", IpHeader::ip_to_string(&ip.destination_ip))?;
            writeln!(f, "  TTL:            {}", ip.ttl)?;
            writeln!(f, "  Protocol:       {} ({})", ip.protocol, ip.protocol_name())?;
            writeln!(f, "  Total Length:   {}", ip.total_length)?;
        }

        if let Some(ref tcp) = self.tcp {
            writeln!(f, "\nTCP Header:")?;
            writeln!(f, "  Source Port:      {}", tcp.source_port)?;
            writeln!(f, "  Destination Port: {}", tcp.destination_port)?;
            writeln!(f, "  Sequence Number:  {}", tcp.sequence_number)?;
            writeln!(f, "  Ack Number:       {}", tcp.acknowledgment_number)?;
            writeln!(f, "  Flags:            {}", tcp.flag_string())?;
            writeln!(f, "  Window Size:      {}", tcp.window_size)?;
        }

        if let Some(ref udp) = self.udp {
            writeln!(f, "\nUDP Header:")?;
            writeln!(f, "  Source Port:      {}", udp.source_port)?;
            writeln!(f, "  Destination Port: {}", udp.destination_port)?;
            writeln!(f, "  Length:           {}", udp.length)?;
        }

        writeln!(f, "\nPayload: {} bytes", self.payload_size())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_header_parse() {
        let mut data = vec![0u8; 14];
        data[0..6].copy_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        data[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[12] = 0x08;
        data[13] = 0x00;

        let header = EthernetHeader::parse(&data).unwrap();
        assert_eq!(header.ether_type, 0x0800);
        assert_eq!(EthernetHeader::mac_to_string(&header.source_mac), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_insufficient_ethernet_data() {
        let data = vec![0u8; 10];
        let result = EthernetHeader::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_header_parse() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45;
        data[2] = 0x00;
        data[3] = 0x28;
        data[9] = 0x06;
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[192, 168, 1, 2]);

        let header = IpHeader::parse(&data).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.protocol, 6);
        assert_eq!(IpHeader::ip_to_string(&header.source_ip), "192.168.1.1");
    }

    #[test]
    fn test_tcp_header_parse() {
        let mut data = vec![0u8; 20];
        data[0] = 0x00;
        data[1] = 0x50;
        data[2] = 0x00;
        data[3] = 0x1F;
        data[12] = 0x50;
        data[13] = 0x02;
        data[14] = 0xFF;
        data[15] = 0xFF;

        let header = TcpHeader::parse(&data).unwrap();
        assert_eq!(header.source_port, 80);
        assert_eq!(header.destination_port, 31);
    }

    #[test]
    fn test_udp_header_parse() {
        let mut data = vec![0u8; 8];
        data[0] = 0x00;
        data[1] = 0x35;
        data[2] = 0x00;
        data[3] = 0x35;
        data[4] = 0x00;
        data[5] = 0x08;

        let header = UdpHeader::parse(&data).unwrap();
        assert_eq!(header.source_port, 53);
        assert_eq!(header.destination_port, 53);
    }

    #[test]
    fn test_tcp_flag_string() {
        let mut data = vec![0u8; 20];
        data[12] = 0x50;
        data[13] = 0x12;

        let header = TcpHeader::parse(&data).unwrap();
        let flags = header.flag_string();
        assert!(flags.contains("SYN"));
        assert!(flags.contains("ACK"));
    }
}
