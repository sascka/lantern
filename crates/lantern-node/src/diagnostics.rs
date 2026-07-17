// SPDX-License-Identifier: MPL-2.0

use core::fmt;
use std::path::Path;

use lantern_diagnostics::{
    DiagnosticEvent, DiagnosticJournal, JournalLimits, JournalMaintenance, JournalView,
    PersistentDiagnosticJournal, PersistentDiagnosticRecovery, RecordResult,
};

use crate::NodeError;

pub(crate) enum NodeDiagnostics {
    Memory(DiagnosticJournal),
    Persistent(PersistentDiagnosticJournal),
}

impl NodeDiagnostics {
    pub(crate) fn memory(limits: JournalLimits) -> Self {
        Self::Memory(DiagnosticJournal::new(limits))
    }

    pub(crate) fn persistent(
        path: &Path,
        limits: JournalLimits,
        observed_wall_seconds: u64,
    ) -> Result<(Self, PersistentDiagnosticRecovery), NodeError> {
        let (journal, recovery) =
            PersistentDiagnosticJournal::open(path, limits, observed_wall_seconds)?;
        Ok((Self::Persistent(journal), recovery))
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Memory(journal) => journal.len(),
            Self::Persistent(journal) => journal.len(),
        }
    }

    pub(crate) const fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent(_))
    }

    pub(crate) fn record(
        &mut self,
        event: DiagnosticEvent,
        observed_wall_seconds: u64,
    ) -> Result<RecordResult, NodeError> {
        match self {
            Self::Memory(journal) => Ok(journal.record(event, observed_wall_seconds)?),
            Self::Persistent(journal) => Ok(journal.record(event, observed_wall_seconds)?),
        }
    }

    pub(crate) fn maintain(
        &mut self,
        observed_wall_seconds: u64,
    ) -> Result<JournalMaintenance, NodeError> {
        match self {
            Self::Memory(journal) => Ok(journal.maintain(observed_wall_seconds)),
            Self::Persistent(journal) => Ok(journal.maintain(observed_wall_seconds)?),
        }
    }

    pub(crate) fn view(
        &mut self,
        observed_wall_seconds: u64,
    ) -> Result<JournalView<'_>, NodeError> {
        match self {
            Self::Memory(journal) => Ok(journal.view(observed_wall_seconds)),
            Self::Persistent(journal) => Ok(journal.view(observed_wall_seconds)?),
        }
    }

    pub(crate) fn clear(&mut self, observed_wall_seconds: u64) -> Result<usize, NodeError> {
        match self {
            Self::Memory(journal) => Ok(journal.clear()),
            Self::Persistent(journal) => Ok(journal.clear(observed_wall_seconds)?),
        }
    }
}

impl fmt::Debug for NodeDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeDiagnostics")
            .field("persistent", &self.is_persistent())
            .field("record_count", &self.len())
            .finish_non_exhaustive()
    }
}
