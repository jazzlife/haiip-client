use des::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Des,
};
use md4::{Digest as Md4Digest, Md4};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

pub struct ResponseMaterial {
    pub nt_response: Zeroizing<[u8; 24]>,
    pub authenticator_response: Zeroizing<[u8; 20]>,
}

pub fn generate_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &str,
    password: &str,
) -> ResponseMaterial {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let password_hash = nt_password_hash(password);
    let nt_response = Zeroizing::new(challenge_response(&challenge, &password_hash));

    let mut md4 = Md4::new();
    md4.update(*password_hash);
    let password_hash_hash: [u8; 16] = md4.finalize().into();
    let mut sha1 = Sha1::new();
    sha1.update(password_hash_hash);
    sha1.update(*nt_response);
    sha1.update(MAGIC1);
    let digest = sha1.finalize();
    let mut sha1 = Sha1::new();
    sha1.update(digest);
    sha1.update(challenge);
    sha1.update(MAGIC2);
    let authenticator_response = Zeroizing::new(sha1.finalize().into());

    ResponseMaterial {
        nt_response,
        authenticator_response,
    }
}

pub fn verify_authenticator_response(expected: &[u8; 20], success_message: &[u8]) -> bool {
    let Some(hex_value) = success_message
        .windows(2)
        .position(|window| window == b"S=")
        .and_then(|position| success_message.get(position + 2..position + 42))
    else {
        return false;
    };
    let Some(decoded) = decode_hex_20(hex_value) else {
        return false;
    };
    expected.ct_eq(&decoded).into()
}

fn challenge_hash(peer: &[u8; 16], authenticator: &[u8; 16], username: &str) -> [u8; 8] {
    let username = username
        .rsplit_once('\\')
        .map_or(username, |(_, name)| name);
    let mut sha1 = Sha1::new();
    sha1.update(peer);
    sha1.update(authenticator);
    sha1.update(username.as_bytes());
    let digest = sha1.finalize();
    digest[..8].try_into().expect("eight-byte challenge hash")
}

fn nt_password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let utf16le = Zeroizing::new(
        password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut md4 = Md4::new();
    md4.update(&*utf16le);
    Zeroizing::new(md4.finalize().into())
}

fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut padded = Zeroizing::new([0_u8; 21]);
    padded[..16].copy_from_slice(password_hash);
    let mut response = [0_u8; 24];
    for index in 0..3 {
        let key = expand_des_key(&padded[index * 7..index * 7 + 7]);
        let cipher = Des::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(challenge);
        cipher.encrypt_block(&mut block);
        response[index * 8..index * 8 + 8].copy_from_slice(&block);
    }
    response
}

fn expand_des_key(input: &[u8]) -> [u8; 8] {
    let mut key = [
        input[0] & 0xfe,
        (input[0] << 7 | input[1] >> 1) & 0xfe,
        (input[1] << 6 | input[2] >> 2) & 0xfe,
        (input[2] << 5 | input[3] >> 3) & 0xfe,
        (input[3] << 4 | input[4] >> 4) & 0xfe,
        (input[4] << 3 | input[5] >> 5) & 0xfe,
        (input[5] << 2 | input[6] >> 6) & 0xfe,
        (input[6] << 1) & 0xfe,
    ];
    for byte in &mut key {
        if byte.count_ones() % 2 == 0 {
            *byte |= 1;
        }
    }
    key
}

fn decode_hex_20(input: &[u8]) -> Option<[u8; 20]> {
    if input.len() != 40 {
        return None;
    }
    let mut output = [0_u8; 20];
    for (index, pair) in input.chunks_exact(2).enumerate() {
        output[index] = hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
