// SPDX-License-Identifier: MPL-2.0

use crate::LanError;

pub const LAN_PROTOCOL_VERSION: u8 = 1;
pub(crate) const HELLO_BYTES: usize = 8;

const MAGIC: [u8; 4] = *b"LANT";
const HELLO_KIND: u8 = 1;
const REQUIRED_FLAGS: u8 = 0;
const REQUIRED_RESERVED: u8 = 0;

pub(crate) const fn encode_hello() -> [u8; HELLO_BYTES] {
    [
        MAGIC[0],
        MAGIC[1],
        MAGIC[2],
        MAGIC[3],
        HELLO_KIND,
        LAN_PROTOCOL_VERSION,
        REQUIRED_FLAGS,
        REQUIRED_RESERVED,
    ]
}

pub(crate) fn decode_hello(bytes: [u8; HELLO_BYTES]) -> Result<(), LanError> {
    if bytes[..4] != MAGIC || bytes[4] != HELLO_KIND {
        return Err(LanError::InvalidHello);
    }
    if bytes[5] != LAN_PROTOCOL_VERSION {
        return Err(LanError::UnsupportedVersion);
    }
    if bytes[6] != REQUIRED_FLAGS || bytes[7] != REQUIRED_RESERVED {
        return Err(LanError::InvalidHello);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LAN_PROTOCOL_VERSION, decode_hello, encode_hello};
    use crate::LanError;

    #[test]
    fn hello_has_one_fixed_vector() {
        assert_eq!(
            encode_hello(),
            [0x4c, 0x41, 0x4e, 0x54, 0x01, 0x01, 0x00, 0x00]
        );
        assert!(decode_hello(encode_hello()).is_ok());
    }

    #[test]
    fn unsupported_version_has_a_separate_closed_error() {
        let mut hello = encode_hello();
        hello[5] = LAN_PROTOCOL_VERSION + 1;
        assert_eq!(decode_hello(hello), Err(LanError::UnsupportedVersion));
    }

    #[test]
    fn every_non_version_field_is_strict() {
        for index in [0_usize, 1, 2, 3, 4, 6, 7] {
            let mut hello = encode_hello();
            hello[index] ^= 0x80;
            assert_eq!(decode_hello(hello), Err(LanError::InvalidHello));
        }
    }
}
