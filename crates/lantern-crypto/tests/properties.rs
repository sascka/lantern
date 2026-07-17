// SPDX-License-Identifier: MPL-2.0

use lantern_crypto::{
    decode_contact_qr, decode_inner_message, decode_protected_payload, encode_inner_message,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 2_048,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_bounded_inner_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..=4155)) {
        if let Ok(decoded) = decode_inner_message(&input) {
            let encoded = encode_inner_message(&decoded);
            prop_assert_eq!(encoded.as_deref(), Ok(input.as_slice()));
        }
    }

    #[test]
    fn arbitrary_bounded_wrapper_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = decode_protected_payload(&input);
    }

    #[test]
    fn arbitrary_bounded_contact_text_never_panics(input in prop::collection::vec(any::<char>(), 0..=704)) {
        let input: String = input.into_iter().collect();
        let _ = decode_contact_qr(&input);
    }
}
