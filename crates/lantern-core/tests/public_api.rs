// SPDX-License-Identifier: MPL-2.0

use lantern_core::{
    ContainerState, DeduplicationStatus, EnqueueOutcome, Envelope, EnvelopeQueue,
    INITIAL_COPY_BUDGET, LocalRouteRecord, NORMAL_PRIORITY, PROTOCOL_VERSION, decode_envelope,
    encode_envelope, encoded_envelope_size,
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

#[test]
fn public_cbor_api_round_trips_one_immutable_envelope() {
    let envelope = test_envelope();
    let encoded = encode_envelope(&envelope);
    let Ok(encoded) = encoded else {
        panic!("valid integration Envelope was not encoded");
    };

    assert_eq!(encoded_envelope_size(&envelope), Ok(encoded.len()));
    assert_eq!(decode_envelope(&encoded), Ok(envelope));
}

#[test]
fn public_queue_api_deduplicates_active_and_removed_envelopes() {
    let mut queue = EnvelopeQueue::default();
    let envelope = test_envelope();
    let identifier = envelope.message_id();
    let route = LocalRouteRecord::for_origin(&envelope, 1_000);
    let Ok(route) = route else {
        panic!("valid public route fixture was rejected");
    };
    let inserted = queue.enqueue(envelope, route, 1_000);
    let Ok(inserted) = inserted else {
        panic!("valid public Envelope was not queued");
    };
    assert_eq!(inserted.outcome(), EnqueueOutcome::Stored);

    let duplicate = test_envelope();
    let duplicate_route = LocalRouteRecord::for_origin(&duplicate, 1_001);
    let Ok(duplicate_route) = duplicate_route else {
        panic!("valid duplicate route fixture was rejected");
    };
    let duplicate = queue.enqueue(duplicate, duplicate_route, 1_001);
    let Ok(duplicate) = duplicate else {
        panic!("public duplicate lookup failed");
    };
    assert_eq!(duplicate.outcome(), EnqueueOutcome::DuplicateActive);
    assert_eq!(queue.len(), 1);

    let removed = queue.remove_opened(identifier, 1_002);
    let Ok(removed) = removed else {
        panic!("public queued Envelope could not be removed");
    };
    assert_eq!(removed.removed_entries().len(), 1);
    assert_eq!(
        queue.deduplication_status(identifier, 1_002),
        DeduplicationStatus::Tombstone
    );
}
