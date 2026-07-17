// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{CoreError, QueueError};
use lantern_diagnostics::DiagnosticError;
use lantern_storage::StorageError;
use lantern_time::ClockError;

/// Safe node error that contains no path, message bytes or exact time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    NotRunning,
    Clock(ClockError),
    Core(CoreError),
    Queue(QueueError),
    Storage(StorageError),
    Diagnostics(DiagnosticError),
}

impl fmt::Display for NodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => formatter.write_str("node is not running"),
            Self::Clock(error) => write!(formatter, "node clock failed: {error}"),
            Self::Core(error) => write!(formatter, "node rejected core data: {error}"),
            Self::Queue(error) => write!(formatter, "node queue failed: {error}"),
            Self::Storage(error) => write!(formatter, "node storage failed: {error}"),
            Self::Diagnostics(error) => {
                write!(formatter, "node diagnostics failed: {error}")
            }
        }
    }
}

impl std::error::Error for NodeError {}

impl From<ClockError> for NodeError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<CoreError> for NodeError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

impl From<QueueError> for NodeError {
    fn from(error: QueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<StorageError> for NodeError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<DiagnosticError> for NodeError {
    fn from(error: DiagnosticError) -> Self {
        Self::Diagnostics(error)
    }
}
