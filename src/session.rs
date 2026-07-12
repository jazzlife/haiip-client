use std::{collections::BTreeMap, net::Ipv4Addr, time::Duration};

use rand::{rngs::OsRng, RngCore};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::{
    error::{Error, Result},
    gre::{packet, socket::GreSocket},
    ppp::{
        decode_frame, encode_frame,
        machine::{Event, Machine},
        IPV4,
    },
    pptp::control::{self, establish, establish_call, ControlConnectOptions},
    tun::TunDevice,
};

pub struct SessionOptions {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tun_name: String,
    pub mtu: u16,
}

struct GreState {
    send_sequence: u32,
    expected_receive: Option<u32>,
    last_received: Option<u32>,
    reorder: BTreeMap<u32, Vec<u8>>,
}

impl GreState {
    fn new() -> Self {
        Self {
            send_sequence: 1,
            expected_receive: None,
            last_received: None,
            reorder: BTreeMap::new(),
        }
    }
}

pub async fn connect(options: SessionOptions) -> Result<()> {
    let control = establish(&ControlConnectOptions {
        server: options.server,
        port: options.port,
        timeout: Duration::from_secs(15),
    })
    .await?;
    let local_call_id = loop {
        let value = (OsRng.next_u32() & 0xffff) as u16;
        if value != 0 {
            break value;
        }
    };
    let call = establish_call(control, local_call_id).await?;
    let peer_ip = match call.peer.ip() {
        std::net::IpAddr::V4(address) => address,
        _ => return Err(Error::Gre("PPTP peer resolved to IPv6".into())),
    };
    let mut control_task = tokio::spawn(control::maintain(call.stream));
    let gre = GreSocket::open(peer_ip)?;
    let mut gre_state = GreState::new();
    let mut machine = Machine::new(options.username, options.password);
    send_event(&gre, call.peer_call_id, &mut gre_state, machine.start()).await?;

    let negotiation = async {
        let mut receive_buffer = vec![0_u8; 65_535];
        loop {
            let (length, source) = gre.receive(&mut receive_buffer).await?;
            if source != peer_ip {
                continue;
            }
            let decoded = packet::decode_ipv4(&receive_buffer[..length])?;
            if decoded.call_id != call.local_call_id {
                continue;
            }
            debug!(
                phase = "negotiation",
                call_id = decoded.call_id,
                sequence = ?decoded.sequence,
                acknowledgement = ?decoded.acknowledgement,
                payload_length = decoded.payload.len(),
                "RX GRE"
            );
            if let Some(sequence) = decoded.sequence {
                if let Some(expected) = gre_state.expected_receive {
                    if sequence != expected {
                        warn!(sequence, expected, "GRE gap detected during negotiation; advancing and retransmitting LCP Configure-Request");
                        gre_state.reorder.clear();
                        gre_state.expected_receive = Some(sequence);
                        send_event(&gre, call.peer_call_id, &mut gre_state, machine.start())
                            .await?;
                    }
                }
                gre_state.expected_receive = Some(sequence.wrapping_add(1));
                gre_state.last_received = Some(sequence);
                if let Some(connected) = process_ppp(
                    &gre,
                    call.peer_call_id,
                    &mut gre_state,
                    &mut machine,
                    decoded.payload,
                )
                .await?
                {
                    return Ok::<_, Error>(connected);
                }
                while let Some(expected) = gre_state.expected_receive {
                    let Some(payload) = gre_state.reorder.remove(&expected) else {
                        break;
                    };
                    gre_state.expected_receive = Some(expected.wrapping_add(1));
                    gre_state.last_received = Some(expected);
                    if let Some(connected) = process_ppp(
                        &gre,
                        call.peer_call_id,
                        &mut gre_state,
                        &mut machine,
                        &payload,
                    )
                    .await?
                    {
                        return Ok::<_, Error>(connected);
                    }
                }
            }
        }
    };

    let negotiated = tokio::select! {
        result = timeout(Duration::from_secs(30), negotiation) => match result {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(30)),
        },
        result = &mut control_task => match result {
            Ok(Ok(())) => Err(Error::Ppp("PPTP control task ended unexpectedly".into())),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(Error::Ppp(format!("control task failed: {error}"))),
        },
    };
    let (local, remote) = match negotiated {
        Ok(connected) => connected,
        Err(error) => {
            control_task.abort();
            let _ = control_task.await;
            return Err(error);
        }
    };
    info!(%local, peer = %remote, "IPCP opened");
    let tun = TunDevice::create(&options.tun_name, local, remote, options.mtu)?;
    info!(interface = %tun.name, "Hai-IP tunnel connected");
    let result = pump(
        gre,
        call.peer_call_id,
        call.local_call_id,
        peer_ip,
        gre_state,
        machine,
        tun,
    )
    .await;
    control_task.abort();
    let _ = control_task.await;
    result
}

async fn process_ppp(
    gre: &GreSocket,
    call_id: u16,
    state: &mut GreState,
    machine: &mut Machine,
    frame: &[u8],
) -> Result<Option<(Ipv4Addr, Ipv4Addr)>> {
    let (protocol, payload) = decode_frame(frame)?;
    debug!(
        protocol = format_args!("0x{protocol:04x}"),
        length = payload.len(),
        "RX PPP"
    );
    for event in machine.handle(protocol, payload)? {
        match event {
            Event::Connected { local, peer } => return Ok(Some((local, peer))),
            Event::Terminated(reason) => {
                return Err(Error::Ppp(format!("peer terminated LCP: {reason}")))
            }
            Event::Ipv4(_) => {}
            send @ Event::Send { .. } => send_event(gre, call_id, state, send).await?,
        }
    }
    Ok(None)
}

async fn send_event(
    gre: &GreSocket,
    call_id: u16,
    state: &mut GreState,
    event: Event,
) -> Result<()> {
    if let Event::Send { protocol, payload } = event {
        // Both peers Ack ACFC before sequence 3. Keep Configure packets
        // uncompressed, then use the negotiated form expected by Hai-IP.
        let frame = encode_frame(protocol, &payload, state.send_sequence <= 2);
        let packet =
            packet::encode_payload(call_id, state.send_sequence, state.last_received, &frame)?;
        debug!(
            sequence = state.send_sequence,
            acknowledgement = ?state.last_received,
            protocol = format_args!("0x{protocol:04x}"),
            payload_length = frame.len(),
            "TX PPP/GRE"
        );
        gre.send(&packet).await?;
        state.send_sequence = state.send_sequence.wrapping_add(1);
    }
    Ok(())
}

async fn send_ack(gre: &GreSocket, call_id: u16, acknowledgement: u32) -> Result<()> {
    debug!(call_id, acknowledgement, "TX GRE ACK-only");
    gre.send(&packet::encode_ack(call_id, acknowledgement))
        .await
}

async fn pump(
    gre: GreSocket,
    peer_call_id: u16,
    local_call_id: u16,
    peer_ip: Ipv4Addr,
    mut state: GreState,
    mut machine: Machine,
    tun: TunDevice,
) -> Result<()> {
    let mut gre_buffer = vec![0_u8; 65_535];
    let mut tun_buffer = vec![0_u8; 65_535];
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            received = gre.receive(&mut gre_buffer) => {
                let (length, source) = received?;
                if source != peer_ip { continue; }
                let decoded = packet::decode_ipv4(&gre_buffer[..length])?;
                if decoded.call_id != local_call_id { continue; }
                debug!(
                    phase = "pump",
                    call_id = decoded.call_id,
                    sequence = ?decoded.sequence,
                    acknowledgement = ?decoded.acknowledgement,
                    payload_length = decoded.payload.len(),
                    "RX GRE"
                );
                let Some(sequence) = decoded.sequence else { continue; };
                if state.expected_receive.is_some() && state.expected_receive != Some(sequence) {
                    warn!(sequence, expected = ?state.expected_receive, "dropping out-of-order GRE packet during pump");
                    continue;
                }
                state.expected_receive = Some(sequence.wrapping_add(1));
                state.last_received = Some(sequence);
                let (protocol, payload) = decode_frame(decoded.payload)?;
                if protocol == IPV4 {
                    if payload.first().is_some_and(|first| first >> 4 == 4) {
                        tun.write(payload).await?;
                    } else {
                        warn!("dropping malformed PPP IPv4 payload");
                    }
                    send_ack(&gre, peer_call_id, sequence).await?;
                } else {
                    for event in machine.handle(protocol, payload)? {
                        match event {
                            send @ Event::Send { .. } => send_event(&gre, peer_call_id, &mut state, send).await?,
                            Event::Terminated(reason) => return Err(Error::Ppp(format!("peer terminated LCP: {reason}"))),
                            _ => {}
                        }
                    }
                }
            }
            read = tun.read(&mut tun_buffer) => {
                let length = read?;
                if length == 0 { return Err(Error::Ppp("TUN device closed".into())); }
                if tun_buffer[0] >> 4 != 4 {
                    debug!(version = tun_buffer[0] >> 4, "dropping non-IPv4 TUN packet");
                    continue;
                }
                let frame = encode_frame(IPV4, &tun_buffer[..length], false);
                let packet = packet::encode_payload(peer_call_id, state.send_sequence, state.last_received, &frame)?;
                debug!(
                    sequence = state.send_sequence,
                    acknowledgement = ?state.last_received,
                    payload_length = frame.len(),
                    "TX IPv4 PPP/GRE"
                );
                gre.send(&packet).await?;
                state.send_sequence = state.send_sequence.wrapping_add(1);
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
        }
    }
}
