// SPDX-License-Identifier: MPL-2.0

use std::collections::BTreeSet;

use lantern_core::{
    ContainerState, Envelope, EnvelopeQueue, LocalRouteRecord, MAX_ENVELOPE_SIZE, NORMAL_PRIORITY,
    PROTOCOL_VERSION, QueueLimits, decode_envelope, encode_envelope,
};
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, RngAlgorithm, RngSeed},
};

fn config(seed: u64, cases: u32) -> Config {
    Config {
        cases,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(seed),
        ..Config::default()
    }
}

fn queue_limits() -> QueueLimits {
    let result = QueueLimits::try_new(8, 16 * 1024, 16, 600);
    let Ok(limits) = result else {
        panic!("valid property-test queue limits were rejected");
    };
    limits
}

fn message_id(value: u16) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id[..2].copy_from_slice(&value.to_be_bytes());
    id
}

fn envelope(id: u16, payload_size: usize) -> Envelope {
    let result = Envelope::try_from_fields(
        PROTOCOL_VERSION,
        message_id(id),
        [0x22; 16],
        60,
        4,
        NORMAL_PRIORITY,
        vec![0x33; payload_size],
    );
    let Ok(envelope) = result else {
        panic!("valid property-test Envelope was rejected");
    };
    envelope
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e01, 128))]

    #[test]
    fn arbitrary_bytes_never_escape_strict_decoding(
        input in vec(any::<u8>(), 0..=8 * 1024),
    ) {
        if let Ok(envelope) = decode_envelope(&input) {
            let encoded = encode_envelope(&envelope);
            prop_assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                prop_assert_eq!(encoded, input);
            }
        }
    }

    #[test]
    fn generated_envelopes_round_trip_canonically(
        id in any::<[u8; 16]>(),
        hint in any::<[u8; 16]>(),
        ttl in 60_u64..=604_800,
        max_hops in 1_u64..=16,
        payload in vec(any::<u8>(), 1..=4 * 1024),
    ) {
        let envelope = Envelope::try_from_fields(
            PROTOCOL_VERSION,
            id,
            hint,
            ttl,
            max_hops,
            NORMAL_PRIORITY,
            payload,
        );
        prop_assert!(envelope.is_ok());
        if let Ok(envelope) = envelope {
            let encoded = encode_envelope(&envelope);
            prop_assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                prop_assert!(encoded.len() <= MAX_ENVELOPE_SIZE);
                prop_assert_eq!(decode_envelope(&encoded), Ok(envelope));
            }
        }
    }
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e02, 64))]

    #[test]
    fn queue_limits_hold_for_generated_operation_sequences(
        operations in vec((any::<u16>(), 1_usize..=4 * 1024, 0_u16..=90), 1..=160),
    ) {
        let limits = queue_limits();
        let mut queue = EnvelopeQueue::new(limits);
        let mut now = 1_000_u64;

        for (id, payload_size, elapsed) in operations {
            now += u64::from(elapsed);
            let envelope = envelope(id, payload_size);
            let route = LocalRouteRecord::for_origin(&envelope, now);
            prop_assert!(route.is_ok());
            if let Ok(route) = route {
                prop_assert!(queue.enqueue(envelope, route, now).is_ok());
            }

            prop_assert!(queue.len() <= limits.max_entries());
            prop_assert!(queue.stored_bytes() <= limits.max_bytes());
            prop_assert!(queue.tombstone_count() <= limits.max_tombstones());

            let mut active_ids = BTreeSet::new();
            let mut stored_bytes = 0_usize;
            for entry in queue.entries() {
                prop_assert_eq!(entry.route().state(), ContainerState::Stored);
                prop_assert!(entry.route().local_deadline() > now);
                prop_assert!(active_ids.insert(entry.envelope().message_id()));
                stored_bytes += entry.encoded_size();
            }
            prop_assert_eq!(stored_bytes, queue.stored_bytes());
            for tombstone in queue.tombstones() {
                prop_assert!(!active_ids.contains(&tombstone.message_id()));
            }
        }
    }
}
