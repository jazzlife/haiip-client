pub const MAGIC_COOKIE: u32 = 0x1a2b_3c4d;
pub const MESSAGE_TYPE_CONTROL: u16 = 1;
pub const PROTOCOL_VERSION_1_0: u16 = 0x0100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartControlConnectionRequest {
    pub protocol_version: u16,
    pub framing_capabilities: u32,
    pub bearer_capabilities: u32,
    pub maximum_channels: u16,
    pub firmware_revision: u16,
    pub host_name: [u8; 64],
    pub vendor_name: [u8; 64],
}

impl Default for StartControlConnectionRequest {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_1_0,
            framing_capabilities: 3,
            bearer_capabilities: 3,
            maximum_channels: 0,
            firmware_revision: 1,
            host_name: fixed_text("haiip-client"),
            vendor_name: fixed_text("Hai-IP Rust client"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartControlConnectionReply {
    pub protocol_version: u16,
    pub result_code: u8,
    pub error_code: u8,
    pub framing_capabilities: u32,
    pub bearer_capabilities: u32,
    pub maximum_channels: u16,
    pub firmware_revision: u16,
    pub host_name: [u8; 64],
    pub vendor_name: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutgoingCallRequest {
    pub call_id: u16,
    pub call_serial_number: u16,
    pub minimum_bps: u32,
    pub maximum_bps: u32,
    pub bearer_type: u32,
    pub framing_type: u32,
    pub receive_window: u16,
    pub processing_delay: u16,
    pub phone_number: [u8; 64],
    pub subaddress: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutgoingCallReply {
    pub call_id: u16,
    pub peer_call_id: u16,
    pub result_code: u8,
    pub error_code: u8,
    pub cause_code: u16,
    pub connect_speed: u32,
    pub receive_window: u16,
    pub processing_delay: u16,
    pub physical_channel_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallDisconnectNotify {
    pub call_id: u16,
    pub result_code: u8,
    pub error_code: u8,
    pub cause_code: u16,
    pub statistics: [u8; 128],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    StartRequest(StartControlConnectionRequest),
    StartReply(StartControlConnectionReply),
    StopRequest {
        reason: u8,
    },
    StopReply {
        result_code: u8,
        error_code: u8,
    },
    EchoRequest {
        identifier: u32,
    },
    EchoReply {
        identifier: u32,
        result_code: u8,
        error_code: u8,
    },
    OutgoingCallRequest(OutgoingCallRequest),
    OutgoingCallReply(OutgoingCallReply),
    CallClearRequest {
        call_id: u16,
    },
    CallDisconnectNotify(CallDisconnectNotify),
    SetLinkInfo {
        peer_call_id: u16,
        send_accm: u32,
        receive_accm: u32,
    },
}

impl ControlMessage {
    pub const fn control_type(&self) -> u16 {
        match self {
            Self::StartRequest(_) => 1,
            Self::StartReply(_) => 2,
            Self::StopRequest { .. } => 3,
            Self::StopReply { .. } => 4,
            Self::EchoRequest { .. } => 5,
            Self::EchoReply { .. } => 6,
            Self::OutgoingCallRequest(_) => 7,
            Self::OutgoingCallReply(_) => 8,
            Self::CallClearRequest { .. } => 12,
            Self::CallDisconnectNotify(_) => 13,
            Self::SetLinkInfo { .. } => 15,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::StartRequest(_) => "Start-Control-Connection-Request",
            Self::StartReply(_) => "Start-Control-Connection-Reply",
            Self::StopRequest { .. } => "Stop-Control-Connection-Request",
            Self::StopReply { .. } => "Stop-Control-Connection-Reply",
            Self::EchoRequest { .. } => "Echo-Request",
            Self::EchoReply { .. } => "Echo-Reply",
            Self::OutgoingCallRequest(_) => "Outgoing-Call-Request",
            Self::OutgoingCallReply(_) => "Outgoing-Call-Reply",
            Self::CallClearRequest { .. } => "Call-Clear-Request",
            Self::CallDisconnectNotify(_) => "Call-Disconnect-Notify",
            Self::SetLinkInfo { .. } => "Set-Link-Info",
        }
    }
}

pub fn fixed_text<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let bytes = value.as_bytes();
    let length = bytes.len().min(N);
    output[..length].copy_from_slice(&bytes[..length]);
    output
}
