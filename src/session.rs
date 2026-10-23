use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use rand::{rngs::OsRng, RngCore};
use tokio::time::{timeout, MissedTickBehavior};
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

/// How long the tunnel may stay silent before we probe the peer with an LCP
/// Echo-Request.
pub const DEFAULT_ECHO_INTERVAL: Duration = Duration::from_secs(10);
/// How long the tunnel may stay silent before the peer counts as dead. Hai-IP
/// echoes every five seconds, so a full minute without a single GRE packet
/// means the path is gone, not merely idle.
pub const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(60);

pub struct SessionOptions {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tun_name: String,
    pub mtu: u16,
    pub echo_interval: Duration,
    pub peer_timeout: Duration,
}

struct GreState {
    send_sequence: u32,
    expected_receive: Option<u32>,
    last_received: Option<u32>,
    reorder: BTreeMap<u32, Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
enum ReceiveSequence {
    InOrder,
    Gap { expected: u32 },
    Stale { expected: u32 },
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

    fn receive_sequence(&mut self, sequence: u32) -> ReceiveSequence {
        let disposition = match self.expected_receive {
            None => ReceiveSequence::InOrder,
            Some(expected) if sequence == expected => ReceiveSequence::InOrder,
            Some(expected) if sequence.wrapping_sub(expected) < (1 << 31) => {
                ReceiveSequence::Gap { expected }
            }
            Some(expected) => ReceiveSequence::Stale { expected },
        };
        if !matches!(disposition, ReceiveSequence::Stale { .. }) {
            self.expected_receive = Some(sequence.wrapping_add(1));
            self.last_received = Some(sequence);
        }
        disposition
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
                match gre_state.receive_sequence(sequence) {
                    ReceiveSequence::InOrder => {}
                    ReceiveSequence::Gap { expected } => {
                        warn!(sequence, expected, "GRE gap detected during negotiation; advancing and retransmitting LCP Configure-Request");
                        gre_state.reorder.clear();
                        send_event(&gre, call.peer_call_id, &mut gre_state, machine.start())
                            .await?;
                    }
                    ReceiveSequence::Stale { expected } => {
                        warn!(
                            sequence,
                            expected, "dropping stale GRE packet during negotiation"
                        );
                        continue;
                    }
                }
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

    let (control_joined, negotiated) = tokio::select! {
        result = timeout(Duration::from_secs(30), negotiation) => (false, match result {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout(30)),
        }),
        result = &mut control_task => (true, match result {
            Ok(Ok(())) => Err(Error::Ppp("PPTP control task ended unexpectedly".into())),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(Error::Ppp(format!("control task failed: {error}"))),
        }),
    };
    let (local, remote) = match negotiated {
        Ok(connected) => connected,
        Err(error) => {
            finish_control(control_task, control_joined).await;
            return Err(error);
        }
    };
    info!(%local, peer = %remote, "IPCP opened");
    let tun = TunDevice::create(&options.tun_name, local, remote, options.mtu)?;
    info!(interface = %tun.name, "Hai-IP tunnel connected");
    let pump = Pump {
        gre,
        peer_call_id: call.peer_call_id,
        local_call_id: call.local_call_id,
        peer_ip,
        state: gre_state,
        machine,
        tun,
        echo_interval: options.echo_interval,
        peer_timeout: options.peer_timeout,
    };
    // The control connection must stay selected on for the whole session:
    // Stop-Control-Connection-Request and Call-Disconnect-Notify arrive there,
    // and before this the task was left unpolled once the tunnel was up.
    let (control_joined, result) = tokio::select! {
        result = pump.run() => (false, result),
        result = &mut control_task => (true, match result {
            Ok(Ok(())) => Err(Error::Ppp("PPTP control task ended unexpectedly".into())),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(Error::Ppp(format!("control task failed: {error}"))),
        }),
    };
    finish_control(control_task, control_joined).await;
    result
}

/// Shut the control task down. A `JoinHandle` that has already yielded its
/// output panics when polled again, so a task whose result was taken by a
/// `select!` branch must not be awaited a second time.
async fn finish_control(task: tokio::task::JoinHandle<Result<()>>, already_joined: bool) {
    if already_joined {
        return;
    }
    task.abort();
    let _ = task.await;
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

/// What the keepalive timer should do after `silence` without a single GRE
/// packet from the peer.
#[derive(Debug, Eq, PartialEq)]
enum Keepalive {
    Quiet,
    Probe,
    Dead,
}

fn keepalive_action(
    silence: Duration,
    echo_interval: Duration,
    peer_timeout: Duration,
) -> Keepalive {
    if !peer_timeout.is_zero() && silence >= peer_timeout {
        Keepalive::Dead
    } else if !echo_interval.is_zero() && silence >= echo_interval {
        Keepalive::Probe
    } else {
        Keepalive::Quiet
    }
}

struct Pump {
    gre: GreSocket,
    peer_call_id: u16,
    local_call_id: u16,
    peer_ip: Ipv4Addr,
    state: GreState,
    machine: Machine,
    tun: TunDevice,
    echo_interval: Duration,
    peer_timeout: Duration,
}

impl Pump {
    async fn run(self) -> Result<()> {
        let Pump {
            gre,
            peer_call_id,
            local_call_id,
            peer_ip,
            mut state,
            mut machine,
            tun,
            echo_interval,
            peer_timeout,
        } = self;
        let mut gre_buffer = vec![0_u8; 65_535];
        let mut tun_buffer = vec![0_u8; 65_535];
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        // A zero peer timeout disables dead-peer detection outright; the timer
        // then idles on a long period instead of complicating the select.
        let supervised = !peer_timeout.is_zero();
        let period = if supervised {
            echo_interval.clamp(Duration::from_secs(1), peer_timeout)
        } else {
            Duration::from_secs(3600)
        };
        let mut keepalive = tokio::time::interval(period);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;
        let mut last_rx = Instant::now();
        if supervised {
            info!(
                echo_interval_seconds = period.as_secs(),
                peer_timeout_seconds = peer_timeout.as_secs(),
                "dead-peer detection armed"
            );
        } else {
            warn!("dead-peer detection disabled; a silent peer will not be noticed");
        }

        loop {
            tokio::select! {
            received = gre.receive(&mut gre_buffer) => {
                let (length, source) = received?;
                if source != peer_ip { continue; }
                let decoded = packet::decode_ipv4(&gre_buffer[..length])?;
                if decoded.call_id != local_call_id { continue; }
                // Any well-formed packet for this call proves the peer is
                // alive, acknowledgement-only frames included.
                last_rx = Instant::now();
                debug!(
                    phase = "pump",
                    call_id = decoded.call_id,
                    sequence = ?decoded.sequence,
                    acknowledgement = ?decoded.acknowledgement,
                    payload_length = decoded.payload.len(),
                    "RX GRE"
                );
                let Some(sequence) = decoded.sequence else { continue; };
                match state.receive_sequence(sequence) {
                    ReceiveSequence::InOrder => {}
                    ReceiveSequence::Gap { expected } => {
                        warn!(sequence, expected, "GRE gap detected during pump; advancing receive sequence");
                    }
                    ReceiveSequence::Stale { expected } => {
                        warn!(sequence, expected, "dropping stale GRE packet during pump");
                        continue;
                    }
                }
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
            _ = keepalive.tick() => {
                if !supervised { continue; }
                let silence = last_rx.elapsed();
                match keepalive_action(silence, echo_interval, peer_timeout) {
                    Keepalive::Quiet => {}
                    Keepalive::Probe => {
                        debug!(silence_seconds = silence.as_secs(), "TX LCP Echo-Request to probe a quiet peer");
                        let probe = machine.echo_request();
                        send_event(&gre, peer_call_id, &mut state, probe).await?;
                    }
                    Keepalive::Dead => {
                        warn!(
                            silence_seconds = silence.as_secs(),
                            "no GRE traffic from the PPTP peer; closing the session so it can reconnect"
                        );
                        return Err(Error::PeerTimeout(silence.as_secs()));
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        finish_control, keepalive_action, GreState, Keepalive, ReceiveSequence,
        DEFAULT_ECHO_INTERVAL, DEFAULT_PEER_TIMEOUT,
    };
    use crate::error::{Error, Result};

    #[tokio::test]
    async fn a_control_task_whose_result_was_taken_is_not_joined_twice() {
        let mut task = tokio::spawn(async { Err::<(), Error>(Error::PeerTimeout(90)) });
        let joined = tokio::select! {
            result = &mut task => {
                assert!(matches!(result, Ok(Err(Error::PeerTimeout(90)))));
                true
            }
        };
        // Polling the handle again here is what paniced with
        // "JoinHandle polled after completion" and killed the process.
        finish_control(task, joined).await;
    }

    #[tokio::test]
    async fn a_control_task_still_running_is_aborted_and_joined() {
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok::<(), Error>(())
        });
        finish_control(task, false).await;
    }

    #[tokio::test]
    async fn finish_control_accepts_a_task_that_returned_ok() {
        let task = tokio::spawn(async { Ok::<(), Error>(()) });
        let _: Result<()> = Ok(());
        finish_control(task, false).await;
    }

    #[test]
    fn a_peer_that_keeps_talking_is_never_probed() {
        assert_eq!(
            keepalive_action(
                Duration::from_secs(5),
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Quiet
        );
    }

    #[test]
    fn a_quiet_peer_is_probed_before_it_is_declared_dead() {
        assert_eq!(
            keepalive_action(
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Probe
        );
        assert_eq!(
            keepalive_action(
                DEFAULT_PEER_TIMEOUT - Duration::from_secs(1),
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Probe
        );
    }

    #[test]
    fn silence_past_the_peer_timeout_is_fatal() {
        assert_eq!(
            keepalive_action(
                DEFAULT_PEER_TIMEOUT,
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Dead
        );
        assert_eq!(
            keepalive_action(
                Duration::from_secs(9 * 3600),
                DEFAULT_ECHO_INTERVAL,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Dead
        );
    }

    #[test]
    fn a_zero_peer_timeout_disables_dead_peer_detection() {
        assert_eq!(
            keepalive_action(
                Duration::from_secs(9 * 3600),
                DEFAULT_ECHO_INTERVAL,
                Duration::ZERO
            ),
            Keepalive::Probe
        );
    }

    #[test]
    fn a_zero_echo_interval_still_declares_a_dead_peer() {
        assert_eq!(
            keepalive_action(
                Duration::from_secs(30),
                Duration::ZERO,
                DEFAULT_PEER_TIMEOUT
            ),
            Keepalive::Quiet
        );
        assert_eq!(
            keepalive_action(DEFAULT_PEER_TIMEOUT, Duration::ZERO, DEFAULT_PEER_TIMEOUT),
            Keepalive::Dead
        );
    }

    #[test]
    fn receive_gap_advances_instead_of_stalling_the_tunnel() {
        let mut state = GreState::new();

        assert_eq!(state.receive_sequence(100), ReceiveSequence::InOrder);
        assert_eq!(
            state.receive_sequence(103),
            ReceiveSequence::Gap { expected: 101 }
        );
        assert_eq!(state.expected_receive, Some(104));
        assert_eq!(state.last_received, Some(103));
    }

    #[test]
    fn stale_receive_sequence_is_dropped_without_rewinding() {
        let mut state = GreState::new();

        assert_eq!(state.receive_sequence(100), ReceiveSequence::InOrder);
        assert_eq!(
            state.receive_sequence(99),
            ReceiveSequence::Stale { expected: 101 }
        );
        assert_eq!(state.expected_receive, Some(101));
        assert_eq!(state.last_received, Some(100));
    }

    #[test]
    fn receive_sequence_wrap_is_in_order() {
        let mut state = GreState::new();

        assert_eq!(state.receive_sequence(u32::MAX), ReceiveSequence::InOrder);
        assert_eq!(state.receive_sequence(0), ReceiveSequence::InOrder);
        assert_eq!(state.expected_receive, Some(1));
    }

    #[test]
    fn receive_gap_across_wrap_advances_and_late_pre_wrap_packet_is_stale() {
        let mut state = GreState::new();

        assert_eq!(
            state.receive_sequence(u32::MAX - 2),
            ReceiveSequence::InOrder
        );
        assert_eq!(
            state.receive_sequence(1),
            ReceiveSequence::Gap {
                expected: u32::MAX - 1,
            }
        );
        assert_eq!(
            state.receive_sequence(u32::MAX),
            ReceiveSequence::Stale { expected: 2 }
        );
    }

    #[test]
    fn ambiguous_half_range_sequence_is_stale() {
        let mut state = GreState::new();

        assert_eq!(state.receive_sequence(u32::MAX), ReceiveSequence::InOrder);
        assert_eq!(
            state.receive_sequence(1 << 31),
            ReceiveSequence::Stale { expected: 0 }
        );
    }
}
