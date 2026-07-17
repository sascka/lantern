// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::thread;

use lantern_lan::{BindAddress, LAN_PROTOCOL_VERSION, LanError, LanListener, PeerAddress, connect};
use lantern_transport::{BoundedSession, MAX_FRAME_BYTES, SessionLimits};

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

#[test]
fn bounded_public_sessions_exchange_an_exact_maximum_frame_and_reply() {
    let bind = BindAddress::from_str("127.0.0.1:0");
    let Ok(bind) = bind else {
        panic!("public bind address should accept loopback");
    };
    let listener = match LanListener::bind(bind) {
        Ok(listener) => listener,
        Err(_) => panic!("public listener should bind to loopback"),
    };
    let local = match listener.local_address() {
        Ok(address) => address,
        Err(_) => panic!("public listener should report its bound address"),
    };
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()));
    let Ok(peer) = peer else {
        panic!("public peer address should accept the listener port");
    };

    let accepting = thread::spawn(move || {
        let connection = listener.accept().map_err(|_| ())?;
        let mut session = BoundedSession::new(connection, SessionLimits::default());
        let mut destination = [0_u8; MAX_FRAME_BYTES];
        let frame = session.receive_frame(&mut destination).map_err(|_| ())?;
        let Some(frame) = frame else {
            return Err(());
        };
        if frame.len() != MAX_FRAME_BYTES || frame.iter().any(|byte| *byte != 0x5a) {
            return Err(());
        }
        session.send_frame(&[0xa5]).map_err(|_| ())?;
        Ok::<_, ()>((session.received_usage(), session.sent_usage()))
    });

    let connection = match connect(peer) {
        Ok(connection) => connection,
        Err(_) => panic!("public client connection should complete"),
    };
    let mut client = BoundedSession::new(connection, SessionLimits::default());
    assert!(client.send_frame(&[0x5a; MAX_FRAME_BYTES]).is_ok());
    let mut reply = [0_u8; MAX_FRAME_BYTES];
    let received = client.receive_frame(&mut reply);
    let Ok(Some(received)) = received else {
        panic!("public client should receive the reply frame");
    };
    assert_eq!(received, [0xa5]);

    let server_usage = match accepting.join() {
        Ok(Ok(usage)) => usage,
        Ok(Err(())) => panic!("public server frame exchange should succeed"),
        Err(_) => panic!("public server thread should not panic"),
    };
    assert_eq!(server_usage.0.frames(), 1);
    assert_eq!(server_usage.1.frames(), 1);
    assert_eq!(client.sent_usage().frames(), 1);
    assert_eq!(client.received_usage().frames(), 1);
}

#[test]
fn listener_limits_one_peer_and_allows_a_bounded_reconnect() {
    let bind = BindAddress::from_str("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("public reconnect bind address should be valid"));
    let listener =
        LanListener::bind(bind).unwrap_or_else(|_| panic!("public reconnect listener should bind"));
    let local = listener
        .local_address()
        .unwrap_or_else(|_| panic!("public reconnect listener should report its port"));
    let peer = PeerAddress::from_str(&format!("127.0.0.1:{}", local.port()))
        .unwrap_or_else(|_| panic!("public reconnect peer should be valid"));

    let first_client = thread::spawn(move || connect(peer));
    let first_server = listener
        .accept()
        .unwrap_or_else(|_| panic!("first peer connection should be admitted"));
    let first_client = match first_client.join() {
        Ok(Ok(connection)) => connection,
        Ok(Err(_)) => panic!("first client connection should complete"),
        Err(_) => panic!("first client thread should not panic"),
    };

    let second_client = thread::spawn(move || connect(peer));
    assert!(matches!(listener.accept(), Err(LanError::PeerLimitReached)));
    assert!(matches!(second_client.join(), Ok(Err(_))));

    drop(first_server);
    drop(first_client);
    let reconnecting_client = thread::spawn(move || connect(peer));
    let reconnecting_server = listener
        .accept()
        .unwrap_or_else(|_| panic!("peer reconnect should be admitted after close"));
    let reconnecting_client = match reconnecting_client.join() {
        Ok(Ok(connection)) => connection,
        Ok(Err(_)) => panic!("reconnecting client should complete"),
        Err(_) => panic!("reconnecting client thread should not panic"),
    };

    drop(reconnecting_server);
    drop(reconnecting_client);
}
