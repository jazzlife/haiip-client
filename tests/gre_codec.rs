use haiip_client::gre::packet::{decode_gre, encode_ack, encode_payload};

#[test]
fn enhanced_gre_payload_round_trip() {
    let encoded = encode_payload(0x1234, u32::MAX, Some(77), b"ppp").unwrap();
    let decoded = decode_gre(&encoded).unwrap();
    assert_eq!(decoded.call_id, 0x1234);
    assert_eq!(decoded.sequence, Some(u32::MAX));
    assert_eq!(decoded.acknowledgement, Some(77));
    assert_eq!(decoded.payload, b"ppp");
}

#[test]
fn pppd_ack_only_wire_format_has_no_payload_or_sequence() {
    let encoded = encode_ack(0x2600, 3);
    assert_eq!(encoded, hex::decode("2081880b0000260000000003").unwrap());
    let decoded = decode_gre(&encoded).unwrap();
    assert_eq!(decoded.sequence, None);
    assert_eq!(decoded.acknowledgement, Some(3));
    assert!(decoded.payload.is_empty());
}
