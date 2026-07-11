use haiip_client::pptp::{
    codec::{decode, encode, CodecError},
    messages::{
        fixed_text, CallDisconnectNotify, ControlMessage, OutgoingCallReply, OutgoingCallRequest,
        StartControlConnectionReply, StartControlConnectionRequest,
    },
};

fn round_trip(message: ControlMessage) {
    let bytes = encode(&message);
    assert_eq!(decode(&bytes), Ok(message));
}

#[test]
fn start_request_matches_rfc_2637_wire_layout() {
    let message = ControlMessage::StartRequest(StartControlConnectionRequest::default());
    let encoded = encode(&message);
    assert_eq!(encoded.len(), 156);
    assert_eq!(
        &encoded[..16],
        &hex::decode("009c00011a2b3c4d0001000001000000").unwrap()
    );
    assert_eq!(decode(&encoded), Ok(message));
}

#[test]
fn every_supported_control_message_round_trips() {
    round_trip(ControlMessage::StartReply(StartControlConnectionReply {
        protocol_version: 0x0100,
        result_code: 1,
        error_code: 0,
        framing_capabilities: 3,
        bearer_capabilities: 3,
        maximum_channels: 32,
        firmware_revision: 1,
        host_name: fixed_text("Hai-IP2"),
        vendor_name: fixed_text("HaiOnNet"),
    }));
    round_trip(ControlMessage::StopRequest { reason: 3 });
    round_trip(ControlMessage::StopReply {
        result_code: 1,
        error_code: 0,
    });
    round_trip(ControlMessage::EchoRequest {
        identifier: 0x1234_5678,
    });
    round_trip(ControlMessage::EchoReply {
        identifier: 7,
        result_code: 1,
        error_code: 0,
    });
    round_trip(ControlMessage::OutgoingCallRequest(OutgoingCallRequest {
        call_id: 0xcafe,
        call_serial_number: 17,
        minimum_bps: 300,
        maximum_bps: 100_000_000,
        bearer_type: 3,
        framing_type: 3,
        receive_window: 64,
        processing_delay: 0,
        phone_number: fixed_text(""),
        subaddress: fixed_text(""),
    }));
    round_trip(ControlMessage::OutgoingCallReply(OutgoingCallReply {
        call_id: 44,
        peer_call_id: 0xcafe,
        result_code: 1,
        error_code: 0,
        cause_code: 0,
        connect_speed: 100_000_000,
        receive_window: 64,
        processing_delay: 0,
        physical_channel_id: 0,
    }));
    round_trip(ControlMessage::CallClearRequest { call_id: 0xcafe });
    round_trip(ControlMessage::CallDisconnectNotify(CallDisconnectNotify {
        call_id: 44,
        result_code: 4,
        error_code: 0,
        cause_code: 0,
        statistics: fixed_text("normal disconnect"),
    }));
    round_trip(ControlMessage::SetLinkInfo {
        peer_call_id: 44,
        send_accm: 0xffff_ffff,
        receive_accm: 0xffff_ffff,
    });
}

#[test]
fn malformed_headers_and_reserved_fields_are_rejected() {
    let original = encode(&ControlMessage::EchoRequest { identifier: 1 });

    let mut bad_cookie = original.to_vec();
    bad_cookie[4] = 0;
    assert!(matches!(
        decode(&bad_cookie),
        Err(CodecError::InvalidMagicCookie(_))
    ));

    let mut bad_reserved = original.to_vec();
    bad_reserved[11] = 1;
    assert_eq!(
        decode(&bad_reserved),
        Err(CodecError::NonZeroReserved {
            field: "Reserved0",
            value: 1
        })
    );

    let mut bad_length = original.to_vec();
    bad_length[1] = 15;
    assert_eq!(
        decode(&bad_length),
        Err(CodecError::InvalidLength {
            declared: 15,
            expected: 16
        })
    );
}

#[tokio::test]
async fn stream_reader_handles_fragmented_tcp_data() {
    let encoded = encode(&ControlMessage::EchoRequest { identifier: 99 });
    let (mut tx, mut rx) = tokio::io::duplex(64);
    let writer = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        tx.write_all(&encoded[..3]).await.unwrap();
        tx.write_all(&encoded[3..]).await.unwrap();
    });
    let message = haiip_client::pptp::codec::read_message(&mut rx)
        .await
        .unwrap();
    writer.await.unwrap();
    assert_eq!(message, ControlMessage::EchoRequest { identifier: 99 });
}
