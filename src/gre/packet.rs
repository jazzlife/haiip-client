use crate::error::{Error, Result};

const GRE_PROTOCOL_PPP: u16 = 0x880b;
const KEY_PRESENT: u16 = 0x2000;
const SEQUENCE_PRESENT: u16 = 0x1000;
const ACK_PRESENT: u16 = 0x0080;
const VERSION_ONE: u16 = 0x0001;

#[derive(Debug)]
pub struct Packet<'a> {
    pub call_id: u16,
    pub sequence: Option<u32>,
    pub acknowledgement: Option<u32>,
    pub payload: &'a [u8],
}

pub fn encode_payload(
    call_id: u16,
    sequence: u32,
    acknowledgement: Option<u32>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let payload_length = u16::try_from(payload.len())
        .map_err(|_| Error::Gre("PPP payload exceeds 65535 bytes".into()))?;
    let mut flags = KEY_PRESENT | SEQUENCE_PRESENT | VERSION_ONE;
    if acknowledgement.is_some() {
        flags |= ACK_PRESENT;
    }
    let mut output =
        Vec::with_capacity(12 + usize::from(acknowledgement.is_some()) * 4 + payload.len());
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&GRE_PROTOCOL_PPP.to_be_bytes());
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(&call_id.to_be_bytes());
    output.extend_from_slice(&sequence.to_be_bytes());
    if let Some(ack) = acknowledgement {
        output.extend_from_slice(&ack.to_be_bytes());
    }
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn encode_ack(call_id: u16, acknowledgement: u32) -> Vec<u8> {
    // The reference pppd capture uses an ACK-only PPTP GRE packet with K|A,
    // no S bit, and therefore no sequence-number field.
    let flags = KEY_PRESENT | ACK_PRESENT | VERSION_ONE;
    let mut output = Vec::with_capacity(12);
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&GRE_PROTOCOL_PPP.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&call_id.to_be_bytes());
    output.extend_from_slice(&acknowledgement.to_be_bytes());
    output
}

pub fn decode_ipv4(input: &[u8]) -> Result<Packet<'_>> {
    if input.len() < 20 {
        return Err(Error::Gre("truncated IPv4 header".into()));
    }
    if input[0] >> 4 != 4 {
        return Err(Error::Gre("raw GRE packet is not IPv4".into()));
    }
    let ip_header_length = usize::from(input[0] & 0x0f) * 4;
    if ip_header_length < 20 || input.len() < ip_header_length + 8 {
        return Err(Error::Gre("invalid IPv4 header length".into()));
    }
    if input[9] != libc::IPPROTO_GRE as u8 {
        return Err(Error::Gre("IPv4 protocol is not GRE".into()));
    }
    decode_gre(&input[ip_header_length..])
}

pub fn decode_gre(input: &[u8]) -> Result<Packet<'_>> {
    if input.len() < 8 {
        return Err(Error::Gre("truncated PPTP GRE header".into()));
    }
    let flags = u16::from_be_bytes([input[0], input[1]]);
    if flags & KEY_PRESENT == 0 || flags & 0x0007 != VERSION_ONE {
        return Err(Error::Gre(format!("invalid PPTP GRE flags 0x{flags:04x}")));
    }
    let protocol = u16::from_be_bytes([input[2], input[3]]);
    if protocol != GRE_PROTOCOL_PPP {
        return Err(Error::Gre(format!("invalid GRE protocol 0x{protocol:04x}")));
    }
    let payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
    let call_id = u16::from_be_bytes([input[6], input[7]]);
    let mut offset = 8;
    let sequence = if flags & SEQUENCE_PRESENT != 0 && payload_length != 0 {
        Some(read_u32(input, &mut offset)?)
    } else {
        None
    };
    let acknowledgement = if flags & ACK_PRESENT != 0 {
        Some(read_u32(input, &mut offset)?)
    } else {
        None
    };
    if input.len() < offset + payload_length {
        return Err(Error::Gre(
            "GRE payload length exceeds received packet".into(),
        ));
    }
    if payload_length != 0 && sequence.is_none() {
        return Err(Error::Gre("GRE data packet has no sequence number".into()));
    }
    Ok(Packet {
        call_id,
        sequence,
        acknowledgement,
        payload: &input[offset..offset + payload_length],
    })
}

fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes = input
        .get(*offset..*offset + 4)
        .ok_or_else(|| Error::Gre("truncated GRE sequence/ack field".into()))?;
    *offset += 4;
    Ok(u32::from_be_bytes(
        bytes.try_into().expect("four-byte field"),
    ))
}
