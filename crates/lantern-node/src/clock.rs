// SPDX-License-Identifier: MPL-2.0

use lantern_time::{ClockError, ClockReading, SystemRuntimeClock};

/// Time source used by the node lifecycle.
pub trait NodeClock {
    fn read(&mut self) -> Result<ClockReading, ClockError>;
}

impl NodeClock for SystemRuntimeClock {
    fn read(&mut self) -> Result<ClockReading, ClockError> {
        self.now()
    }
}
