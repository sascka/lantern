// SPDX-License-Identifier: MPL-2.0

use lantern_core::{
    ContainerState, Envelope, INITIAL_COPY_BUDGET, LocalRouteRecord, NORMAL_PRIORITY,
    PROTOCOL_VERSION,
};

fn test_envelope() -> Envelope {
    let result = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0x11; 16],
        [0x22; 16],
        300,
        16,
        NORMAL_PRIORITY,
        b"OBVIOUS TEST PAYLOAD".to_vec(),
    );
    let Ok(envelope) = result else {
        panic!("valid integration fixture was rejected");
    };
    envelope
}

#[test]
fn relay_route_uses_bounded_advertised_values_without_changing_envelope() {
    let envelope = test_envelope();
    let original_payload = envelope.protected_payload().as_bytes().to_vec();
    let result = LocalRouteRecord::from_received(&envelope, 1_000, 900, 99, 99);
    let Ok(route) = result else {
        panic!("bounded Relay route was rejected");
    };

    assert_eq!(route.remaining_ttl(), 300);
    assert_eq!(route.hops_taken(), 16);
    assert_eq!(route.copies_left(), INITIAL_COPY_BUDGET);
    assert_eq!(route.state(), ContainerState::Stored);
    assert_eq!(envelope.protected_payload().as_bytes(), original_payload);
}

#[test]
fn public_debug_output_does_not_include_test_payload_or_identifiers() {
    let envelope = test_envelope();
    let output = format!("{envelope:?}");

    assert!(!output.contains("OBVIOUS TEST PAYLOAD"));
    assert!(!output.contains("17, 17"));
    assert!(!output.contains("34, 34"));
}
