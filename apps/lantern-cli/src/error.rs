// SPDX-License-Identifier: AGPL-3.0-or-later

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    Usage,
    Io,
    UnsafeFile,
    InvalidText,
    InvalidNumber,
    Profile,
    Contact,
    Crypto,
    Node,
    Lan,
    Bridge,
    Timeout,
    SasRejected,
    UnknownContact,
    AmbiguousContact,
    QueueDeferred,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str("invalid command; run lantern-cli help"),
            Self::Io => formatter.write_str("file operation failed"),
            Self::UnsafeFile => formatter.write_str("file or directory permissions are unsafe"),
            Self::InvalidText => formatter.write_str("text input is invalid or too large"),
            Self::InvalidNumber => formatter.write_str("numeric argument is invalid"),
            Self::Profile => formatter.write_str("secret profile operation failed"),
            Self::Contact => formatter.write_str("contact exchange data is invalid"),
            Self::Crypto => formatter.write_str("cryptographic operation failed"),
            Self::Node => formatter.write_str("node operation failed"),
            Self::Lan => formatter.write_str("LAN operation failed"),
            Self::Bridge => {
                formatter.write_str("queue and cryptographic state could not be joined")
            }
            Self::Timeout => formatter.write_str("timed out waiting for the other contact file"),
            Self::SasRejected => formatter.write_str("contact verification was cancelled"),
            Self::UnknownContact => formatter.write_str("contact name was not found"),
            Self::AmbiguousContact => formatter.write_str("contact name is not unique"),
            Self::QueueDeferred => {
                formatter.write_str("message remains pending because the queue is full")
            }
        }
    }
}

impl std::error::Error for CliError {}
