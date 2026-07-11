use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("PPTP protocol error: {0}")]
    Protocol(#[from] crate::pptp::codec::CodecError),
    #[error("network I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no IPv4 address resolved for {0}")]
    NoIpv4Address(String),
    #[error("PPTP control handshake timed out after {0} seconds")]
    Timeout(u64),
    #[error("PPTP control connection rejected: result={result}, error={error}")]
    ControlRejected { result: u8, error: u8 },
    #[error("unsupported PPTP protocol version 0x{0:04x}")]
    UnsupportedVersion(u16),
    #[error("expected Start-Control-Connection-Reply, received {0}")]
    UnexpectedControlMessage(&'static str),
    #[error("PPTP outgoing call rejected: result={result}, error={error}, cause={cause}")]
    CallRejected { result: u8, error: u8, cause: u16 },
    #[error("GRE protocol error: {0}")]
    Gre(String),
    #[error("PPP protocol error: {0}")]
    Ppp(String),
    #[error("MS-CHAPv2 authentication failed: {0}")]
    Authentication(String),
    #[error("missing environment variable {0}")]
    MissingSecret(String),
    #[error("network configuration failed: {0}")]
    NetworkConfiguration(String),
    #[error("command is planned for a later milestone: {0}")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
