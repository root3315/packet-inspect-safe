use thiserror::Error;

/// Custom error types for packet parsing and analysis operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum PacketError {
    #[error("Insufficient packet data: expected {expected} bytes, got {actual} bytes")]
    InsufficientData { expected: usize, actual: usize },

    #[error("Invalid Ethernet frame: {message}")]
    InvalidEthernetFrame { message: String },

    #[error("Invalid IP header: {message}")]
    InvalidIpHeader { message: String },

    #[error("Unsupported IP version: {version}")]
    UnsupportedIpVersion { version: u8 },

    #[error("Invalid IP address: {address}")]
    InvalidIpAddress { address: String },

    #[error("Invalid TCP header: {message}")]
    InvalidTcpHeader { message: String },

    #[error("Invalid UDP header: {message}")]
    InvalidUdpHeader { message: String },

    #[error("Unknown protocol: {protocol}")]
    UnknownProtocol { protocol: u8 },

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: u16, actual: u16 },

    #[error("Invalid packet length: {length} bytes")]
    InvalidPacketLength { length: usize },

    #[error("IO error: {message}")]
    IoError { message: String },

    #[error("Parse error: {message}")]
    ParseError { message: String },
}

impl PacketError {
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            PacketError::InsufficientData { .. }
                | PacketError::InvalidEthernetFrame { .. }
                | PacketError::InvalidIpHeader { .. }
                | PacketError::UnsupportedIpVersion { .. }
        )
    }

    pub fn error_code(&self) -> u8 {
        match self {
            PacketError::InsufficientData { .. } => 1,
            PacketError::InvalidEthernetFrame { .. } => 2,
            PacketError::InvalidIpHeader { .. } => 3,
            PacketError::UnsupportedIpVersion { .. } => 4,
            PacketError::InvalidIpAddress { .. } => 5,
            PacketError::InvalidTcpHeader { .. } => 6,
            PacketError::InvalidUdpHeader { .. } => 7,
            PacketError::UnknownProtocol { .. } => 8,
            PacketError::ChecksumMismatch { .. } => 9,
            PacketError::InvalidPacketLength { .. } => 10,
            PacketError::IoError { .. } => 11,
            PacketError::ParseError { .. } => 12,
        }
    }
}

pub type Result<T> = std::result::Result<T, PacketError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PacketError::InsufficientData {
            expected: 14,
            actual: 10,
        };
        assert_eq!(
            format!("{}", err),
            "Insufficient packet data: expected 14 bytes, got 10 bytes"
        );
    }

    #[test]
    fn test_error_is_fatal() {
        let fatal_err = PacketError::InsufficientData {
            expected: 14,
            actual: 10,
        };
        assert!(fatal_err.is_fatal());

        let non_fatal_err = PacketError::UnknownProtocol { protocol: 99 };
        assert!(!non_fatal_err.is_fatal());
    }

    #[test]
    fn test_error_codes() {
        let err = PacketError::InvalidTcpHeader {
            message: "test".to_string(),
        };
        assert_eq!(err.error_code(), 6);
    }
}
