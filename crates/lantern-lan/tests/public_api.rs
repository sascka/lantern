// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::thread;

use lantern_lan::{BindAddress, LAN_PROTOCOL_VERSION, LanListener, PeerAddress, connect};

#[test]
fn public_api_negotiates_one_loopback_connection() {
    let bind = BindAddress::from_str("127.0.0.1:0");
    let Ok(bind) = bind else {
        panic!("public bind address should accept loopback");
    };
    let listener = LanListener::bind(bind);
    let Ok(listener) = listener else {
        panic!("public listener should bind to loopback");
    };
    let local = listener.local_address();
    let Ok(local) = local else {
        panic!("public listener should report its bound address");
    };
    let local_debug = format!("{local:?}");
    let socket_text = format!("127.0.0.1:{}", local.port());
    let peer = PeerAddress::from_str(&socket_text);
    let Ok(peer) = peer else {
        panic!("public peer address should accept the bound loopback port");
    };
    assert!(!local_debug.contains(&socket_text));

    let accepting = thread::spawn(move || listener.accept());
    let client = connect(peer);
    let Ok(client) = client else {
        panic!("public client handshake should succeed");
    };
    let server = match accepting.join() {
        Ok(result) => result,
        Err(_) => panic!("public server thread should not panic"),
    };
    let Ok(server) = server else {
        panic!("public server handshake should succeed");
    };

    assert_eq!(client.protocol_version(), LAN_PROTOCOL_VERSION);
    assert_eq!(server.protocol_version(), LAN_PROTOCOL_VERSION);
}

#[test]
fn public_address_errors_do_not_repeat_untrusted_text() {
    let marker = "public-peer-marker.example:38383";
    let error = PeerAddress::from_str(marker);
    let Err(error) = error else {
        panic!("DNS address should be rejected");
    };
    assert!(!format!("{error}").contains(marker));
    assert!(!format!("{error:?}").contains(marker));
}
