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

