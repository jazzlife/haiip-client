use haiip_client::crypto::mschapv2::{generate_response, verify_authenticator_response};

#[test]
fn rfc_2759_section_8_vector() {
    let authenticator = hex::decode("5B5D7C7D7B3F2F3E3C2C602132262628").unwrap();
    let peer = hex::decode("21402324255E262A28295F2B3A337C7E").unwrap();
    let material = generate_response(
        authenticator.as_slice().try_into().unwrap(),
        peer.as_slice().try_into().unwrap(),
        "User",
        "clientPass",
    );
    assert_eq!(
        material.nt_response.as_slice(),
        hex::decode("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF").unwrap()
    );
    assert_eq!(
        material.authenticator_response.as_slice(),
        hex::decode("407A5589115FD0D6209F510FE9C04566932CDA56").unwrap()
    );
    assert!(verify_authenticator_response(
        &material.authenticator_response,
        b"S=407A5589115FD0D6209F510FE9C04566932CDA56 M=Authenticated"
    ));
}
