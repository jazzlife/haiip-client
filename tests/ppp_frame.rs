use haiip_client::ppp::{decode_frame, encode_frame, LCP};

#[test]
fn address_control_and_compressed_forms_decode_identically() {
    let payload = [9, 1, 0, 8, 1, 2, 3, 4];
    for include_address_control in [true, false] {
        let frame = encode_frame(LCP, &payload, include_address_control);
        assert_eq!(decode_frame(&frame).unwrap(), (LCP, payload.as_slice()));
    }
}
