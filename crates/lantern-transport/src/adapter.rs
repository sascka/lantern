// SPDX-License-Identifier: MPL-2.0

/// Result of one complete-frame receive operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameReceive {
    /// One complete frame was written into the provided destination prefix.
    Complete(usize),
    /// The remote side closed the session without another frame.
    ConnectionClosed,
}

/// Closed failure vocabulary. It cannot carry addresses, payload, or OS text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransportFailureKind {
    Interrupted,
    Unavailable,
    ConnectionFailed,
    ProtocolViolation,
    ResourceExhausted,
}

/// Adapter between a concrete delivery mechanism and the common bounded API.
///
/// Each successful operation handles exactly one complete opaque frame. A
/// receive implementation must inspect its own wire length before reading the
/// body, must not write beyond `destination`, and must not allocate based on an
/// untrusted length larger than `destination.len()`.
///
/// `send_frame` must return success only when it has accepted the complete
/// frame. Concrete asynchronous buffering and cancellation remain outside this
/// Stage 2 interface.
pub trait FrameTransport {
    fn receive_frame(
        &mut self,
        destination: &mut [u8],
    ) -> Result<FrameReceive, TransportFailureKind>;

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportFailureKind>;
}
