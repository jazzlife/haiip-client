pub mod machine;

use crate::error::{Error, Result};

pub const IPV4: u16 = 0x0021;
pub const IPCP: u16 = 0x8021;
pub const IPV6CP: u16 = 0x8057;
pub const CCP: u16 = 0x80fd;
pub const LCP: u16 = 0xc021;
pub const CHAP: u16 = 0xc223;

pub fn decode_frame(mut input: &[u8]) -> Result<(u16, &[u8])> {
    if input.starts_with(&[0xff, 0x03]) {
        input = &input[2..];
    }
    let first = *input
        .first()
        .ok_or_else(|| Error::Ppp("empty PPP frame".into()))?;
    if first & 1 != 0 {
        Ok((u16::from(first), &input[1..]))
    } else {
        if input.len() < 2 {
            return Err(Error::Ppp("truncated PPP protocol field".into()));
        }
        Ok((u16::from_be_bytes([input[0], input[1]]), &input[2..]))
    }
}

pub fn encode_frame(protocol: u16, payload: &[u8], include_address_control: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(payload.len() + 4);
    if include_address_control {
        output.extend_from_slice(&[0xff, 0x03]);
    }
    output.extend_from_slice(&protocol.to_be_bytes());
    output.extend_from_slice(payload);
    output
}

pub fn control_packet(code: u8, identifier: u8, data: &[u8]) -> Vec<u8> {
    let length = 4 + data.len();
    let mut output = Vec::with_capacity(length);
    output.push(code);
    output.push(identifier);
    output.extend_from_slice(&(length as u16).to_be_bytes());
    output.extend_from_slice(data);
    output
}

fn parse_control(input: &[u8]) -> Result<(u8, u8, &[u8])> {
    if input.len() < 4 {
        return Err(Error::Ppp("truncated PPP control packet".into()));
    }
    let length = usize::from(u16::from_be_bytes([input[2], input[3]]));
    if length < 4 || length > input.len() {
        return Err(Error::Ppp(format!("invalid PPP control length {length}")));
    }
    Ok((input[0], input[1], &input[4..length]))
}
