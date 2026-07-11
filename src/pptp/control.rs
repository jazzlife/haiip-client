use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tracing::{debug, info};

use crate::error::{Error, Result};

use super::{
    codec::{encode, read_message},
    messages::{
        ControlMessage, StartControlConnectionReply, StartControlConnectionRequest,
        PROTOCOL_VERSION_1_0,
    },
};

#[derive(Clone, Debug)]
pub struct ControlConnectOptions {
    pub server: String,
    pub port: u16,
    pub timeout: Duration,
}

pub struct EstablishedControl {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    pub server: StartControlConnectionReply,
}

pub async fn establish(options: &ControlConnectOptions) -> Result<EstablishedControl> {
    let operation = async {
        let peer = resolve_ipv4(&options.server, options.port).await?;
        info!(%peer, "PPTP TCP control connection opening");
        let mut stream = TcpStream::connect(peer).await?;
        stream.set_nodelay(true)?;

        let request = ControlMessage::StartRequest(StartControlConnectionRequest::default());
        stream.write_all(&encode(&request)).await?;
        info!(message = request.name(), "TX PPTP control");

        loop {
            let response = read_message(&mut stream).await?;
            info!(message = response.name(), "RX PPTP control");
            match response {
                ControlMessage::StartReply(reply) => {
                    validate_start_reply(&reply)?;
                    return Ok(EstablishedControl {
                        stream,
                        peer,
                        server: reply,
                    });
                }
                ControlMessage::EchoRequest { identifier } => {
                    let reply = ControlMessage::EchoReply {
                        identifier,
                        result_code: 1,
                        error_code: 0,
                    };
                    stream.write_all(&encode(&reply)).await?;
                    debug!(identifier, "TX PPTP Echo-Reply during handshake");
                }
                other => return Err(Error::UnexpectedControlMessage(other.name())),
            }
        }
    };

    timeout(options.timeout, operation)
        .await
        .map_err(|_| Error::Timeout(options.timeout.as_secs()))?
}

pub struct EstablishedCall {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    pub local_call_id: u16,
    pub peer_call_id: u16,
}

pub async fn establish_call(
    mut control: EstablishedControl,
    local_call_id: u16,
) -> Result<EstablishedCall> {
    use super::messages::{fixed_text, OutgoingCallRequest};
    let request = ControlMessage::OutgoingCallRequest(OutgoingCallRequest {
        call_id: local_call_id,
        call_serial_number: 1,
        minimum_bps: 300,
        maximum_bps: 100_000_000,
        bearer_type: 3,
        framing_type: 3,
        receive_window: 64,
        processing_delay: 0,
        phone_number: fixed_text(""),
        subaddress: fixed_text(""),
    });
    control.stream.write_all(&encode(&request)).await?;
    info!(local_call_id, "TX PPTP Outgoing-Call-Request");
    loop {
        match read_message(&mut control.stream).await? {
            ControlMessage::OutgoingCallReply(reply) => {
                if reply.peer_call_id != local_call_id {
                    return Err(Error::UnexpectedControlMessage(
                        "Outgoing-Call-Reply with mismatched Peer Call ID",
                    ));
                }
                if reply.result_code != 1 {
                    return Err(Error::CallRejected {
                        result: reply.result_code,
                        error: reply.error_code,
                        cause: reply.cause_code,
                    });
                }
                info!(
                    peer_call_id = reply.call_id,
                    local_call_id, "PPTP outgoing call established"
                );
                return Ok(EstablishedCall {
                    stream: control.stream,
                    peer: control.peer,
                    local_call_id,
                    peer_call_id: reply.call_id,
                });
            }
            ControlMessage::EchoRequest { identifier } => {
                let reply = ControlMessage::EchoReply {
                    identifier,
                    result_code: 1,
                    error_code: 0,
                };
                control.stream.write_all(&encode(&reply)).await?;
            }
            other => return Err(Error::UnexpectedControlMessage(other.name())),
        }
    }
}

pub async fn maintain(mut stream: TcpStream) -> Result<()> {
    let mut next_identifier = 1_u32;
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await;
    loop {
        tokio::select! {
            message = read_message(&mut stream) => match message? {
                ControlMessage::EchoRequest { identifier } => {
                    let reply = ControlMessage::EchoReply { identifier, result_code: 1, error_code: 0 };
                    stream.write_all(&encode(&reply)).await?;
                }
                ControlMessage::StopRequest { .. } => {
                    let reply = ControlMessage::StopReply { result_code: 1, error_code: 0 };
                    stream.write_all(&encode(&reply)).await?;
                    return Err(Error::Ppp("server stopped PPTP control connection".into()));
                }
                ControlMessage::CallDisconnectNotify(notify) => {
                    return Err(Error::Ppp(format!("PPTP call disconnected: result={} error={} cause={}", notify.result_code, notify.error_code, notify.cause_code)));
                }
                _ => {}
            },
            _ = interval.tick() => {
                let echo = ControlMessage::EchoRequest { identifier: next_identifier };
                stream.write_all(&encode(&echo)).await?;
                next_identifier = next_identifier.wrapping_add(1);
            }
        }
    }
}

async fn resolve_ipv4(server: &str, port: u16) -> Result<SocketAddr> {
    lookup_host((server, port))
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| Error::NoIpv4Address(server.to_owned()))
}

fn validate_start_reply(reply: &StartControlConnectionReply) -> Result<()> {
    if reply.result_code != 1 {
        return Err(Error::ControlRejected {
            result: reply.result_code,
            error: reply.error_code,
        });
    }
    if reply.protocol_version != PROTOCOL_VERSION_1_0 {
        return Err(Error::UnsupportedVersion(reply.protocol_version));
    }
    Ok(())
}
