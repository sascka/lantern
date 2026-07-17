// SPDX-License-Identifier: MPL-2.0

use lantern_sync::{decode_sync_frame, encode_sync_frame};
use lantern_transport::MAX_FRAME_BYTES;
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, RngAlgorithm, RngSeed},
};

fn property_config() -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x4c41_4e53_594e_4301),
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn accepted_arbitrary_input_is_already_canonical(
        input in vec(any::<u8>(), 0..=MAX_FRAME_BYTES),
    ) {
        if let Ok(frame) = decode_sync_frame(&input) {
            let encoded = encode_sync_frame(&frame);
            prop_assert_eq!(encoded, Ok(input));
        }
    }
}
