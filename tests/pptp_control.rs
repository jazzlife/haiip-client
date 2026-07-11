use std::time::Duration;

use haiip_client::pptp::{
    codec::{encode, read_message},
    control::{establish, ControlConnectOptions},
    messages::{fixed_text, ControlMessage, StartControlConnectionReply},
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[tokio::test]
async fn start_control_exchange_handles_echo_and_fragmented_reply() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            read_message(&mut stream).await.unwrap(),
            ControlMessage::StartRequest(_)
        ));

        let echo = encode(&ControlMessage::EchoRequest { identifier: 73 });
        stream.write_all(&echo).await.unwrap();
        assert_eq!(
            read_message(&mut stream).await.unwrap(),
            ControlMessage::EchoReply {
                identifier: 73,
                result_code: 1,
                error_code: 0,
            }
        );

        let reply = encode(&ControlMessage::StartReply(StartControlConnectionReply {
            protocol_version: 0x0100,
            result_code: 1,
            error_code: 0,
            framing_capabilities: 3,
            bearer_capabilities: 3,
            maximum_channels: 8,
            firmware_revision: 2,
            host_name: fixed_text("mock-pac"),
            vendor_name: fixed_text("test"),
        }));
        stream.write_all(&reply[..7]).await.unwrap();
        stream.write_all(&reply[7..]).await.unwrap();
    });

    let control = establish(&ControlConnectOptions {
        server: "127.0.0.1".to_owned(),
        port,
        timeout: Duration::from_secs(2),
    })
    .await
    .unwrap();
    assert_eq!(control.server.firmware_revision, 2);
    peer.await.unwrap();
}
