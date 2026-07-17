// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use lantern_core::{CoreError, QueueError};
use lantern_diagnostics::{DiagnosticError, PersistentDiagnosticError};
use lantern_storage::StorageError;
use lantern_time::ClockError;

use crate::ProfileLockError;

/// Safe node error that contains no path, message bytes or exact time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    NotRunning,
    InvalidProfilePaths,
    Clock(ClockError),
    Core(CoreError),
    Queue(QueueError),
    Storage(StorageError),
    Diagnostics(DiagnosticError),
    PersistentDiagnostics(PersistentDiagnosticError),
    ProfileLock(ProfileLockError),
}

impl fmt::Display for NodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => formatter.write_str("node is not running"),
            Self::InvalidProfilePaths => {
                formatter.write_str("node profile paths overlap or cannot be resolved")
            }
            Self::Clock(error) => write!(formatter, "node clock failed: {error}"),
            Self::Core(error) => write!(formatter, "node rejected core data: {error}"),
            Self::Queue(error) => write!(formatter, "node queue failed: {error}"),
            Self::Storage(error) => write!(formatter, "node storage failed: {error}"),
            Self::Diagnostics(error) => {
                write!(formatter, "node diagnostics failed: {error}")
            }
            Self::PersistentDiagnostics(error) => {
                write!(formatter, "node persistent diagnostics failed: {error}")
            }
            Self::ProfileLock(error) => write!(formatter, "node profile lock failed: {error}"),
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

impl From<PersistentDiagnosticError> for NodeError {
    fn from(error: PersistentDiagnosticError) -> Self {
        Self::PersistentDiagnostics(error)
    }
}

impl From<ProfileLockError> for NodeError {
    fn from(error: ProfileLockError) -> Self {
        Self::ProfileLock(error)
    }
}
