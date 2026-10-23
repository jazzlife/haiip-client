use haiip_client::ppp::{decode_frame, encode_frame, LCP};

#[test]
fn address_control_and_compressed_forms_decode_identically() {
    let payload = [9, 1, 0, 8, 1, 2, 3, 4];
    for include_address_control in [true, false] {
        let frame = encode_frame(LCP, &payload, include_address_control);
        assert_eq!(decode_frame(&frame).unwrap(), (LCP, payload.as_slice()));
    }
}

#[test]
fn lcp_echo_requests_carry_the_local_magic_and_fresh_identifiers() {
    use haiip_client::ppp::machine::{Event, Machine};

    let mut machine = Machine::new("user@1".into(), "secret".into());
    let Event::Send {
        protocol,
        payload: first,
    } = machine.echo_request()
    else {
        panic!("echo_request must emit a Send event");
    };
    assert_eq!(protocol, LCP);
    // RFC 1661 Echo-Request: code 9, 4-byte header, then the Magic-Number.
    assert_eq!(first[0], 9);
    assert_eq!(first[1], 1);
    assert_eq!(u16::from_be_bytes([first[2], first[3]]), 8);
    assert_eq!(first.len(), 8);
    let magic = &first[4..8];
    assert_ne!(magic, [0, 0, 0, 0]);

    let Event::Send {
        payload: second, ..
    } = machine.echo_request()
    else {
        panic!("echo_request must emit a Send event");
    };
    assert_eq!(second[1], 2, "each probe needs its own identifier");
    assert_eq!(&second[4..8], magic, "the magic number must not change");
}

#[test]
fn an_echo_reply_is_accepted_without_a_response() {
    use haiip_client::ppp::machine::Machine;

    let mut machine = Machine::new("user@1".into(), "secret".into());
    let reply = [10_u8, 1, 0, 8, 1, 2, 3, 4];
    let events = machine
        .handle(LCP, &reply)
        .expect("Echo-Reply is valid LCP");
    assert!(events.is_empty());
}
