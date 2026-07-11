use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::messages::{
    CallDisconnectNotify, ControlMessage, OutgoingCallReply, OutgoingCallRequest,
    StartControlConnectionReply, StartControlConnectionRequest, MAGIC_COOKIE, MESSAGE_TYPE_CONTROL,
};

const COMMON_HEADER_LENGTH: usize = 12;
const MAX_CONTROL_MESSAGE_LENGTH: usize = 512;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CodecError {
    #[error("message is shorter than the {0}-byte PPTP control header")]
    TruncatedHeader(usize),
    #[error("invalid message length {declared}; expected {expected}")]
    InvalidLength { declared: usize, expected: usize },
    #[error("PPTP message length {0} exceeds the safe control-message limit")]
    MessageTooLarge(usize),
    #[error("unsupported PPTP message type {0}")]
    InvalidMessageType(u16),
    #[error("invalid PPTP magic cookie 0x{0:08x}")]
    InvalidMagicCookie(u32),
    #[error("unsupported PPTP control message type {0}")]
    UnsupportedControlType(u16),
    #[error("reserved field {field} must be zero, got 0x{value:x}")]
    NonZeroReserved { field: &'static str, value: u64 },
    #[error("phone number length {0} exceeds its 64-byte field")]
    InvalidPhoneNumberLength(u16),
    #[error("I/O error while reading PPTP message: {0}")]
    Io(String),
}

pub fn encode(message: &ControlMessage) -> Bytes {
    let length = encoded_length(message);
    let mut output = BytesMut::with_capacity(length);
    output.put_u16(length as u16);
    output.put_u16(MESSAGE_TYPE_CONTROL);
    output.put_u32(MAGIC_COOKIE);
    output.put_u16(message.control_type());
    output.put_u16(0);

    match message {
        ControlMessage::StartRequest(value) => encode_start_request(&mut output, value),
        ControlMessage::StartReply(value) => encode_start_reply(&mut output, value),
        ControlMessage::StopRequest { reason } => {
            output.put_u8(*reason);
            output.put_u8(0);
            output.put_u16(0);
        }
        ControlMessage::StopReply {
            result_code,
            error_code,
        } => {
            output.put_u8(*result_code);
            output.put_u8(*error_code);
            output.put_u16(0);
        }
        ControlMessage::EchoRequest { identifier } => output.put_u32(*identifier),
        ControlMessage::EchoReply {
            identifier,
            result_code,
            error_code,
        } => {
            output.put_u32(*identifier);
            output.put_u8(*result_code);
            output.put_u8(*error_code);
            output.put_u16(0);
        }
        ControlMessage::OutgoingCallRequest(value) => encode_outgoing_request(&mut output, value),
        ControlMessage::OutgoingCallReply(value) => encode_outgoing_reply(&mut output, value),
        ControlMessage::CallClearRequest { call_id } => {
            output.put_u16(*call_id);
            output.put_u16(0);
        }
        ControlMessage::CallDisconnectNotify(value) => {
            output.put_u16(value.call_id);
            output.put_u8(value.result_code);
            output.put_u8(value.error_code);
            output.put_u16(value.cause_code);
            output.put_u16(0);
            output.extend_from_slice(&value.statistics);
        }
        ControlMessage::SetLinkInfo {
            peer_call_id,
            send_accm,
            receive_accm,
        } => {
            output.put_u16(*peer_call_id);
            output.put_u16(0);
            output.put_u32(*send_accm);
            output.put_u32(*receive_accm);
        }
    }
    debug_assert_eq!(output.len(), length);
    output.freeze()
}

pub fn decode(input: &[u8]) -> Result<ControlMessage, CodecError> {
    if input.len() < COMMON_HEADER_LENGTH {
        return Err(CodecError::TruncatedHeader(input.len()));
    }
    let declared = usize::from(u16::from_be_bytes([input[0], input[1]]));
    if declared != input.len() {
        return Err(CodecError::InvalidLength {
            declared,
            expected: input.len(),
        });
    }
    if declared > MAX_CONTROL_MESSAGE_LENGTH {
        return Err(CodecError::MessageTooLarge(declared));
    }
    let message_type = u16::from_be_bytes([input[2], input[3]]);
    if message_type != MESSAGE_TYPE_CONTROL {
        return Err(CodecError::InvalidMessageType(message_type));
    }
    let cookie = u32::from_be_bytes(input[4..8].try_into().expect("four-byte slice"));
    if cookie != MAGIC_COOKIE {
        return Err(CodecError::InvalidMagicCookie(cookie));
    }
    let control_type = u16::from_be_bytes([input[8], input[9]]);
    check_zero("Reserved0", u16::from_be_bytes([input[10], input[11]]))?;
    let mut reader = Reader::new(&input[COMMON_HEADER_LENGTH..]);

    let message = match control_type {
        1 => ControlMessage::StartRequest(decode_start_request(&mut reader, declared)?),
        2 => ControlMessage::StartReply(decode_start_reply(&mut reader, declared)?),
        3 => {
            expect_length(declared, 16)?;
            let reason = reader.u8();
            check_zero("Reserved1", reader.u8())?;
            check_zero("Reserved2", reader.u16())?;
            ControlMessage::StopRequest { reason }
        }
        4 => {
            expect_length(declared, 16)?;
            let result_code = reader.u8();
            let error_code = reader.u8();
            check_zero("Reserved1", reader.u16())?;
            ControlMessage::StopReply {
                result_code,
                error_code,
            }
        }
        5 => {
            expect_length(declared, 16)?;
            ControlMessage::EchoRequest {
                identifier: reader.u32(),
            }
        }
        6 => {
            expect_length(declared, 20)?;
            let identifier = reader.u32();
            let result_code = reader.u8();
            let error_code = reader.u8();
            check_zero("Reserved1", reader.u16())?;
            ControlMessage::EchoReply {
                identifier,
                result_code,
                error_code,
            }
        }
        7 => ControlMessage::OutgoingCallRequest(decode_outgoing_request(&mut reader, declared)?),
        8 => ControlMessage::OutgoingCallReply(decode_outgoing_reply(&mut reader, declared)?),
        12 => {
            expect_length(declared, 16)?;
            let call_id = reader.u16();
            check_zero("Reserved1", reader.u16())?;
            ControlMessage::CallClearRequest { call_id }
        }
        13 => {
            expect_length(declared, 148)?;
            let value = CallDisconnectNotify {
                call_id: reader.u16(),
                result_code: reader.u8(),
                error_code: reader.u8(),
                cause_code: reader.u16(),
                statistics: {
                    check_zero("Reserved1", reader.u16())?;
                    reader.array()
                },
            };
            ControlMessage::CallDisconnectNotify(value)
        }
        15 => {
            expect_length(declared, 24)?;
            let peer_call_id = reader.u16();
            check_zero("Reserved1", reader.u16())?;
            ControlMessage::SetLinkInfo {
                peer_call_id,
                send_accm: reader.u32(),
                receive_accm: reader.u32(),
            }
        }
        value => return Err(CodecError::UnsupportedControlType(value)),
    };
    Ok(message)
}

pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlMessage, CodecError> {
    let mut length_bytes = [0_u8; 2];
    reader
        .read_exact(&mut length_bytes)
        .await
        .map_err(io_error)?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length < COMMON_HEADER_LENGTH {
        return Err(CodecError::TruncatedHeader(length));
    }
    if length > MAX_CONTROL_MESSAGE_LENGTH {
        return Err(CodecError::MessageTooLarge(length));
    }
    let mut message = vec![0_u8; length];
    message[..2].copy_from_slice(&length_bytes);
    reader
        .read_exact(&mut message[2..])
        .await
        .map_err(io_error)?;
    decode(&message)
}

fn encoded_length(message: &ControlMessage) -> usize {
    match message {
        ControlMessage::StartRequest(_) | ControlMessage::StartReply(_) => 156,
        ControlMessage::StopRequest { .. }
        | ControlMessage::StopReply { .. }
        | ControlMessage::EchoRequest { .. }
        | ControlMessage::CallClearRequest { .. } => 16,
        ControlMessage::EchoReply { .. } => 20,
        ControlMessage::OutgoingCallRequest(_) => 168,
        ControlMessage::OutgoingCallReply(_) => 32,
        ControlMessage::CallDisconnectNotify(_) => 148,
        ControlMessage::SetLinkInfo { .. } => 24,
    }
}

fn encode_start_request(output: &mut BytesMut, value: &StartControlConnectionRequest) {
    output.put_u16(value.protocol_version);
    output.put_u16(0);
    output.put_u32(value.framing_capabilities);
    output.put_u32(value.bearer_capabilities);
    output.put_u16(value.maximum_channels);
    output.put_u16(value.firmware_revision);
    output.extend_from_slice(&value.host_name);
    output.extend_from_slice(&value.vendor_name);
}

fn encode_start_reply(output: &mut BytesMut, value: &StartControlConnectionReply) {
    output.put_u16(value.protocol_version);
    output.put_u8(value.result_code);
    output.put_u8(value.error_code);
    output.put_u32(value.framing_capabilities);
    output.put_u32(value.bearer_capabilities);
    output.put_u16(value.maximum_channels);
    output.put_u16(value.firmware_revision);
    output.extend_from_slice(&value.host_name);
    output.extend_from_slice(&value.vendor_name);
}

fn encode_outgoing_request(output: &mut BytesMut, value: &OutgoingCallRequest) {
    output.put_u16(value.call_id);
    output.put_u16(value.call_serial_number);
    output.put_u32(value.minimum_bps);
    output.put_u32(value.maximum_bps);
    output.put_u32(value.bearer_type);
    output.put_u32(value.framing_type);
    output.put_u16(value.receive_window);
    output.put_u16(value.processing_delay);
    let phone_length = value
        .phone_number
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(64);
    output.put_u16(phone_length as u16);
    output.put_u16(0);
    output.extend_from_slice(&value.phone_number);
    output.extend_from_slice(&value.subaddress);
}

fn encode_outgoing_reply(output: &mut BytesMut, value: &OutgoingCallReply) {
    output.put_u16(value.call_id);
    output.put_u16(value.peer_call_id);
    output.put_u8(value.result_code);
    output.put_u8(value.error_code);
    output.put_u16(value.cause_code);
    output.put_u32(value.connect_speed);
    output.put_u16(value.receive_window);
    output.put_u16(value.processing_delay);
    output.put_u32(value.physical_channel_id);
}

fn decode_start_request(
    reader: &mut Reader<'_>,
    length: usize,
) -> Result<StartControlConnectionRequest, CodecError> {
    expect_length(length, 156)?;
    let protocol_version = reader.u16();
    check_zero("Reserved1", reader.u16())?;
    Ok(StartControlConnectionRequest {
        protocol_version,
        framing_capabilities: reader.u32(),
        bearer_capabilities: reader.u32(),
        maximum_channels: reader.u16(),
        firmware_revision: reader.u16(),
        host_name: reader.array(),
        vendor_name: reader.array(),
    })
}

fn decode_start_reply(
    reader: &mut Reader<'_>,
    length: usize,
) -> Result<StartControlConnectionReply, CodecError> {
    expect_length(length, 156)?;
    Ok(StartControlConnectionReply {
        protocol_version: reader.u16(),
        result_code: reader.u8(),
        error_code: reader.u8(),
        framing_capabilities: reader.u32(),
        bearer_capabilities: reader.u32(),
        maximum_channels: reader.u16(),
        firmware_revision: reader.u16(),
        host_name: reader.array(),
        vendor_name: reader.array(),
    })
}

fn decode_outgoing_request(
    reader: &mut Reader<'_>,
    length: usize,
) -> Result<OutgoingCallRequest, CodecError> {
    expect_length(length, 168)?;
    let call_id = reader.u16();
    let call_serial_number = reader.u16();
    let minimum_bps = reader.u32();
    let maximum_bps = reader.u32();
    let bearer_type = reader.u32();
    let framing_type = reader.u32();
    let receive_window = reader.u16();
    let processing_delay = reader.u16();
    let phone_length = reader.u16();
    if phone_length > 64 {
        return Err(CodecError::InvalidPhoneNumberLength(phone_length));
    }
    check_zero("Reserved1", reader.u16())?;
    Ok(OutgoingCallRequest {
        call_id,
        call_serial_number,
        minimum_bps,
        maximum_bps,
        bearer_type,
        framing_type,
        receive_window,
        processing_delay,
        phone_number: reader.array(),
        subaddress: reader.array(),
    })
}

fn decode_outgoing_reply(
    reader: &mut Reader<'_>,
    length: usize,
) -> Result<OutgoingCallReply, CodecError> {
    expect_length(length, 32)?;
    Ok(OutgoingCallReply {
        call_id: reader.u16(),
        peer_call_id: reader.u16(),
        result_code: reader.u8(),
        error_code: reader.u8(),
        cause_code: reader.u16(),
        connect_speed: reader.u32(),
        receive_window: reader.u16(),
        processing_delay: reader.u16(),
        physical_channel_id: reader.u32(),
    })
}

fn expect_length(actual: usize, expected: usize) -> Result<(), CodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CodecError::InvalidLength {
            declared: actual,
            expected,
        })
    }
}

fn check_zero<T>(field: &'static str, value: T) -> Result<(), CodecError>
where
    T: Into<u64> + Copy + Eq + From<u8>,
{
    if value == T::from(0) {
        Ok(())
    } else {
        Err(CodecError::NonZeroReserved {
            field,
            value: value.into(),
        })
    }
}

fn io_error(error: std::io::Error) -> CodecError {
    CodecError::Io(error.to_string())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn u8(&mut self) -> u8 {
        let value = self.input[self.offset];
        self.offset += 1;
        value
    }

    fn u16(&mut self) -> u16 {
        let value = u16::from_be_bytes(
            self.input[self.offset..self.offset + 2]
                .try_into()
                .expect("two-byte slice"),
        );
        self.offset += 2;
        value
    }

    fn u32(&mut self) -> u32 {
        let value = u32::from_be_bytes(
            self.input[self.offset..self.offset + 4]
                .try_into()
                .expect("four-byte slice"),
        );
        self.offset += 4;
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let value = self.input[self.offset..self.offset + N]
            .try_into()
            .expect("validated message length");
        self.offset += N;
        value
    }
}
