use std::net::Ipv4Addr;

use rand::{rngs::OsRng, RngCore};
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::{
    crypto::mschapv2::{generate_response, verify_authenticator_response},
    error::{Error, Result},
};

use super::{control_packet, parse_control, CCP, CHAP, IPCP, IPV4, IPV6CP, LCP};

#[derive(Debug)]
pub enum Event {
    Send { protocol: u16, payload: Vec<u8> },
    Ipv4(Vec<u8>),
    Connected { local: Ipv4Addr, peer: Ipv4Addr },
    Terminated(String),
}

pub struct Machine {
    username: String,
    password: Zeroizing<String>,
    local_magic: u32,
    peer_magic: Option<u32>,
    echo_identifier: u8,
    lcp_options: Vec<u8>,
    lcp_local_acked: bool,
    lcp_peer_acked: bool,
    lcp_open: bool,
    authenticated: bool,
    expected_authenticator: Option<Zeroizing<[u8; 20]>>,
    ipcp_id: u8,
    ipcp_options: Vec<u8>,
    ipcp_local_acked: bool,
    ipcp_peer_acked: bool,
    local_address: Ipv4Addr,
    peer_address: Ipv4Addr,
}

impl Machine {
    pub fn new(username: String, password: String) -> Self {
        let local_magic = OsRng.next_u32();
        let mut lcp_options = Vec::new();
        lcp_options.extend_from_slice(&[2, 6, 0, 0, 0, 0]);
        lcp_options.extend_from_slice(&[5, 6]);
        lcp_options.extend_from_slice(&local_magic.to_be_bytes());
        lcp_options.extend_from_slice(&[7, 2, 8, 2]);
        Self {
            username,
            password: Zeroizing::new(password),
            local_magic,
            peer_magic: None,
            echo_identifier: 0,
            lcp_options,
            lcp_local_acked: false,
            lcp_peer_acked: false,
            lcp_open: false,
            authenticated: false,
            expected_authenticator: None,
            ipcp_id: 1,
            ipcp_options: ip_option(Ipv4Addr::UNSPECIFIED),
            ipcp_local_acked: false,
            ipcp_peer_acked: false,
            local_address: Ipv4Addr::UNSPECIFIED,
            peer_address: Ipv4Addr::UNSPECIFIED,
        }
    }

    pub fn start(&self) -> Event {
        Event::Send {
            protocol: LCP,
            payload: control_packet(1, 1, &self.lcp_options),
        }
    }

    /// Probe a peer that has stopped talking. RFC 1661 requires an Echo-Reply
    /// for every Echo-Request, so a run of unanswered probes is the only way to
    /// tell a quiet link apart from one whose GRE path has silently gone away.
    pub fn echo_request(&mut self) -> Event {
        self.echo_identifier = self.echo_identifier.wrapping_add(1);
        Event::Send {
            protocol: LCP,
            payload: control_packet(9, self.echo_identifier, &self.local_magic.to_be_bytes()),
        }
    }

    pub fn handle(&mut self, protocol: u16, payload: &[u8]) -> Result<Vec<Event>> {
        match protocol {
            LCP => self.handle_lcp(payload),
            CHAP if self.lcp_open => self.handle_chap(payload),
            IPCP if self.authenticated => self.handle_ipcp(payload),
            CCP if self.lcp_open => self.reject_configuration(CCP, payload),
            IPV6CP if self.lcp_open => self.reject_protocol(IPV6CP, payload),
            IPV4 if self.ipcp_local_acked && self.ipcp_peer_acked => {
                Ok(vec![Event::Ipv4(payload.to_vec())])
            }
            unsupported if self.lcp_open => {
                debug!(
                    protocol = format_args!("0x{unsupported:04x}"),
                    "rejecting unsupported PPP protocol"
                );
                self.reject_protocol(unsupported, payload)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn handle_lcp(&mut self, payload: &[u8]) -> Result<Vec<Event>> {
        let (code, identifier, data) = parse_control(payload)?;
        match code {
            1 => {
                self.inspect_lcp_options(data)?;
                self.lcp_peer_acked = true;
                self.update_lcp_open();
                Ok(vec![Event::Send {
                    protocol: LCP,
                    payload: control_packet(2, identifier, data),
                }])
            }
            2 => {
                if identifier != 1 || data != self.lcp_options {
                    return Err(Error::Ppp(
                        "LCP Configure-Ack does not exactly match request".into(),
                    ));
                }
                self.lcp_local_acked = true;
                self.update_lcp_open();
                Ok(Vec::new())
            }
            5 => Ok(vec![
                Event::Send {
                    protocol: LCP,
                    payload: control_packet(6, identifier, &[]),
                },
                Event::Terminated(String::from_utf8_lossy(data).into_owned()),
            ]),
            9 if self.lcp_open => {
                if data.len() < 4 {
                    return Err(Error::Ppp("LCP Echo-Request omitted Magic Number".into()));
                }
                let mut reply_data = self.local_magic.to_be_bytes().to_vec();
                reply_data.extend_from_slice(&data[4..]);
                info!(
                    identifier,
                    "RX LCP Echo-Request; sending RFC 1661 Echo-Reply"
                );
                Ok(vec![Event::Send {
                    protocol: LCP,
                    payload: control_packet(10, identifier, &reply_data),
                }])
            }
            10 => {
                debug!(identifier, "RX LCP Echo-Reply");
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn inspect_lcp_options(&mut self, options: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut mschapv2 = false;
        while offset < options.len() {
            let (kind, value, next) = option(options, offset)?;
            match kind {
                3 => {
                    if value != [0xc2, 0x23, 0x81] {
                        return Err(Error::Authentication(
                            "server did not request CHAP MS-v2".into(),
                        ));
                    }
                    mschapv2 = true;
                }
                5 if value.len() == 4 => {
                    self.peer_magic = Some(u32::from_be_bytes(
                        value.try_into().expect("four-byte magic"),
                    ));
                }
                _ => {}
            }
            offset = next;
        }
        if !mschapv2 {
            return Err(Error::Authentication(
                "server LCP request omitted CHAP MS-v2".into(),
            ));
        }
        Ok(())
    }

    fn update_lcp_open(&mut self) {
        if !self.lcp_open && self.lcp_local_acked && self.lcp_peer_acked {
            self.lcp_open = true;
            info!(
                local_magic = format_args!("0x{:08x}", self.local_magic),
                "LCP opened"
            );
        }
    }

    fn handle_chap(&mut self, payload: &[u8]) -> Result<Vec<Event>> {
        let (code, identifier, data) = parse_control(payload)?;
        match code {
            1 => {
                if data.first() != Some(&16) || data.len() < 17 {
                    return Err(Error::Authentication("invalid MS-CHAPv2 challenge".into()));
                }
                let authenticator: &[u8; 16] =
                    data[1..17].try_into().expect("validated challenge length");
                let mut peer_challenge = [0_u8; 16];
                OsRng.fill_bytes(&mut peer_challenge);
                let material = generate_response(
                    authenticator,
                    &peer_challenge,
                    &self.username,
                    &self.password,
                );
                let mut response = Vec::with_capacity(50 + self.username.len());
                response.push(49);
                response.extend_from_slice(&peer_challenge);
                response.extend_from_slice(&[0_u8; 8]);
                response.extend_from_slice(&*material.nt_response);
                response.push(0);
                response.extend_from_slice(self.username.as_bytes());
                self.expected_authenticator = Some(material.authenticator_response);
                Ok(vec![Event::Send {
                    protocol: CHAP,
                    payload: control_packet(2, identifier, &response),
                }])
            }
            3 => {
                let expected = self.expected_authenticator.as_ref().ok_or_else(|| {
                    Error::Authentication("CHAP Success arrived before Challenge".into())
                })?;
                if !verify_authenticator_response(expected, data) {
                    return Err(Error::Authentication(
                        "server authenticator response mismatch".into(),
                    ));
                }
                self.authenticated = true;
                info!("MS-CHAPv2 mutual authentication succeeded");
                Ok(vec![Event::Send {
                    protocol: IPCP,
                    payload: control_packet(1, self.ipcp_id, &self.ipcp_options),
                }])
            }
            4 => Err(Error::Authentication("server returned CHAP Failure".into())),
            _ => Ok(Vec::new()),
        }
    }

    fn handle_ipcp(&mut self, payload: &[u8]) -> Result<Vec<Event>> {
        let (code, identifier, data) = parse_control(payload)?;
        match code {
            1 => {
                if let Some(address) = find_ip_address(data)? {
                    self.peer_address = address;
                }
                self.ipcp_peer_acked = true;
                let mut events = vec![Event::Send {
                    protocol: IPCP,
                    payload: control_packet(2, identifier, data),
                }];
                self.maybe_connected(&mut events);
                Ok(events)
            }
            2 if identifier == self.ipcp_id && data == self.ipcp_options => {
                self.ipcp_local_acked = true;
                let mut events = Vec::new();
                self.maybe_connected(&mut events);
                Ok(events)
            }
            3 if identifier == self.ipcp_id => {
                let address = find_ip_address(data)?
                    .ok_or_else(|| Error::Ppp("IPCP Nak omitted IP-Address".into()))?;
                self.local_address = address;
                self.ipcp_options = ip_option(address);
                self.ipcp_id = self.ipcp_id.wrapping_add(1);
                Ok(vec![Event::Send {
                    protocol: IPCP,
                    payload: control_packet(1, self.ipcp_id, &self.ipcp_options),
                }])
            }
            4 => Err(Error::Ppp(
                "server rejected required IPCP IP-Address option".into(),
            )),
            5 => Ok(vec![Event::Send {
                protocol: IPCP,
                payload: control_packet(6, identifier, &[]),
            }]),
            _ => Ok(Vec::new()),
        }
    }

    fn maybe_connected(&self, events: &mut Vec<Event>) {
        if self.ipcp_local_acked && self.ipcp_peer_acked {
            events.push(Event::Connected {
                local: self.local_address,
                peer: self.peer_address,
            });
        }
    }

    fn reject_configuration(&self, protocol: u16, payload: &[u8]) -> Result<Vec<Event>> {
        let (code, identifier, data) = parse_control(payload)?;
        if code == 1 {
            let response_code = if data.is_empty() { 2 } else { 4 };
            Ok(vec![Event::Send {
                protocol,
                payload: control_packet(response_code, identifier, data),
            }])
        } else {
            Ok(Vec::new())
        }
    }

    fn reject_protocol(&self, protocol: u16, payload: &[u8]) -> Result<Vec<Event>> {
        let mut rejected = Vec::with_capacity(payload.len() + 2);
        rejected.extend_from_slice(&protocol.to_be_bytes());
        rejected.extend_from_slice(payload);
        Ok(vec![Event::Send {
            protocol: LCP,
            payload: control_packet(8, 2, &rejected),
        }])
    }
}

fn option(input: &[u8], offset: usize) -> Result<(u8, &[u8], usize)> {
    if input.len() < offset + 2 {
        return Err(Error::Ppp("truncated PPP option".into()));
    }
    let length = usize::from(input[offset + 1]);
    if length < 2 || input.len() < offset + length {
        return Err(Error::Ppp("invalid PPP option length".into()));
    }
    Ok((
        input[offset],
        &input[offset + 2..offset + length],
        offset + length,
    ))
}

fn find_ip_address(options: &[u8]) -> Result<Option<Ipv4Addr>> {
    let mut offset = 0;
    while offset < options.len() {
        let (kind, value, next) = option(options, offset)?;
        if kind == 3 && value.len() == 4 {
            return Ok(Some(Ipv4Addr::from(
                <[u8; 4]>::try_from(value).expect("four-byte address"),
            )));
        }
        offset = next;
    }
    Ok(None)
}

fn ip_option(address: Ipv4Addr) -> Vec<u8> {
    let mut option = vec![3, 6];
    option.extend_from_slice(&address.octets());
    option
}
