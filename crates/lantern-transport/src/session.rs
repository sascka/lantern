// SPDX-License-Identifier: MPL-2.0

use core::fmt;

use crate::{FrameReceive, FrameTransport, MAX_FRAME_BYTES, SessionLimits, TransportFailureKind};

/// Exact bounded counters for policy and coarse diagnostic conversion.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionUsage {
    frames: u32,
    bytes: usize,
}

impl SessionUsage {
    pub const fn frames(self) -> u32 {
        self.frames
    }

    pub const fn bytes(self) -> usize {
        self.bytes
    }
}

impl fmt::Debug for SessionUsage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionUsage")
            .field("frames", &self.frames)
            .field("bytes", &"redacted")
            .finish()
    }
}

#[derive(Clone, Copy)]
struct Budget {
    usage: SessionUsage,
}

impl Budget {
    const fn new() -> Self {
        Self {
            usage: SessionUsage {
                frames: 0,
                bytes: 0,
            },
        }
    }

    fn check_charge(self, frame_bytes: usize, limits: SessionLimits) -> Result<(), SessionError> {
        let Some(next_frames) = self.usage.frames.checked_add(1) else {
            return Err(SessionError::ArithmeticOverflow);
        };
        if next_frames > limits.max_frames() {
            return Err(SessionError::FrameQuotaReached);
        }
        let Some(next_bytes) = self.usage.bytes.checked_add(frame_bytes) else {
            return Err(SessionError::ArithmeticOverflow);
        };
        if next_bytes > limits.max_bytes() {
            return Err(SessionError::ByteQuotaReached);
        }
        Ok(())
    }

    fn charge(&mut self, frame_bytes: usize) -> Result<(), SessionError> {
        let next_frames = self
            .usage
            .frames
            .checked_add(1)
            .ok_or(SessionError::ArithmeticOverflow)?;
        let next_bytes = self
            .usage
            .bytes
            .checked_add(frame_bytes)
            .ok_or(SessionError::ArithmeticOverflow)?;
        self.usage.frames = next_frames;
        self.usage.bytes = next_bytes;
        Ok(())
    }

    const fn remaining_bytes(self, limits: SessionLimits) -> usize {
        limits.max_bytes() - self.usage.bytes
    }
}

/// One bounded bidirectional session around a concrete frame adapter.
pub struct BoundedSession<T> {
    transport: T,
    limits: SessionLimits,
    received: Budget,
    sent: Budget,
    terminated: bool,
}

impl<T> BoundedSession<T> {
    pub const fn new(transport: T, limits: SessionLimits) -> Self {
        Self {
            transport,
            limits,
            received: Budget::new(),
            sent: Budget::new(),
            terminated: false,
        }
    }

    pub const fn limits(&self) -> SessionLimits {
        self.limits
    }

    pub const fn received_usage(&self) -> SessionUsage {
        self.received.usage
    }

    pub const fn sent_usage(&self) -> SessionUsage {
        self.sent.usage
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: FrameTransport> BoundedSession<T> {
    /// Receives one complete frame into a caller-owned fixed-size buffer.
    ///
    /// The buffer must be at least `MAX_FRAME_BYTES`. Only a bounded prefix is
    /// exposed to the adapter. `Ok(None)` means a normal connection close.
    pub fn receive_frame<'buffer>(
        &mut self,
        destination: &'buffer mut [u8],
    ) -> Result<Option<&'buffer [u8]>, SessionError> {
        self.ensure_active()?;
        if destination.len() < MAX_FRAME_BYTES {
            return Err(SessionError::ReceiveBufferTooSmall);
        }
        self.received
            .check_charge(0, self.limits)
            .inspect_err(|_| {
                self.terminated = true;
            })?;

        let available = MAX_FRAME_BYTES.min(self.received.remaining_bytes(self.limits));
        if available == 0 {
            self.terminated = true;
            return Err(SessionError::ByteQuotaReached);
        }
        let outcome = match self.transport.receive_frame(&mut destination[..available]) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.terminated = true;
                return Err(SessionError::TransportFailure(error));
            }
        };

        let FrameReceive::Complete(frame_bytes) = outcome else {
            self.terminated = true;
            return Ok(None);
        };
        if frame_bytes == 0 {
            self.terminated = true;
            return Err(SessionError::EmptyFrame);
        }
        if frame_bytes > available {
            self.terminated = true;
            return Err(SessionError::AdapterLengthViolation);
        }
        if let Err(error) = self.received.check_charge(frame_bytes, self.limits) {
            self.terminated = true;
            return Err(error);
        }
        if let Err(error) = self.received.charge(frame_bytes) {
            self.terminated = true;
            return Err(error);
        }
        Ok(Some(&destination[..frame_bytes]))
    }

    /// Sends one complete opaque frame after validating size and session quota.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), SessionError> {
        self.ensure_active()?;
        validate_frame_size(frame.len())?;
        if let Err(error) = self.sent.check_charge(frame.len(), self.limits) {
            self.terminated = true;
            return Err(error);
        }
        if let Err(error) = self.transport.send_frame(frame) {
            self.terminated = true;
            return Err(SessionError::TransportFailure(error));
        }
        if let Err(error) = self.sent.charge(frame.len()) {
            self.terminated = true;
            return Err(error);
        }
        Ok(())
    }

    const fn ensure_active(&self) -> Result<(), SessionError> {
        if self.terminated {
            return Err(SessionError::SessionTerminated);
        }
        Ok(())
    }
}

impl<T> fmt::Debug for BoundedSession<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedSession")
            .field("limits", &self.limits)
            .field("received", &self.received.usage)
            .field("sent", &self.sent.usage)
            .field("terminated", &self.terminated)
            .finish_non_exhaustive()
    }
}

fn validate_frame_size(frame_bytes: usize) -> Result<(), SessionError> {
    if frame_bytes == 0 {
        return Err(SessionError::EmptyFrame);
    }
    if frame_bytes > MAX_FRAME_BYTES {
        return Err(SessionError::FrameTooLarge);
    }
    Ok(())
}

/// Safe session error without frame contents, addresses, or exact input sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    ReceiveBufferTooSmall,
    EmptyFrame,
    FrameTooLarge,
    FrameQuotaReached,
    ByteQuotaReached,
    AdapterLengthViolation,
    ArithmeticOverflow,
    TransportFailure(TransportFailureKind),
    SessionTerminated,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceiveBufferTooSmall => formatter.write_str("receive buffer is too small"),
            Self::EmptyFrame => formatter.write_str("empty transport frame"),
            Self::FrameTooLarge => formatter.write_str("transport frame exceeds limit"),
            Self::FrameQuotaReached => formatter.write_str("session frame quota reached"),
            Self::ByteQuotaReached => formatter.write_str("session byte quota reached"),
            Self::AdapterLengthViolation => {
                formatter.write_str("transport adapter returned an invalid frame length")
            }
            Self::ArithmeticOverflow => formatter.write_str("session counter overflow"),
            Self::TransportFailure(_) => formatter.write_str("transport operation failed"),
            Self::SessionTerminated => formatter.write_str("transport session is terminated"),
        }
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{MAX_SESSION_BYTES, MAX_SESSION_FRAMES};

    #[derive(Debug)]
    enum Incoming {
        Frame(Vec<u8>),
        LengthViolation(usize),
        Failure(TransportFailureKind),
        Closed,
    }

    #[derive(Default)]
    struct FakeTransport {
        incoming: VecDeque<Incoming>,
        sent: Vec<Vec<u8>>,
        receive_capacities: Vec<usize>,
        send_calls: usize,
        send_failure: Option<TransportFailureKind>,
    }

    impl FrameTransport for FakeTransport {
        fn receive_frame(
            &mut self,
            destination: &mut [u8],
        ) -> Result<FrameReceive, TransportFailureKind> {
            self.receive_capacities.push(destination.len());
            let Some(incoming) = self.incoming.pop_front() else {
                return Ok(FrameReceive::ConnectionClosed);
            };
            match incoming {
                Incoming::Frame(frame) => {
                    if frame.len() > destination.len() {
                        return Err(TransportFailureKind::ProtocolViolation);
                    }
                    destination[..frame.len()].copy_from_slice(&frame);
                    Ok(FrameReceive::Complete(frame.len()))
                }
                Incoming::LengthViolation(length) => Ok(FrameReceive::Complete(length)),
                Incoming::Failure(error) => Err(error),
                Incoming::Closed => Ok(FrameReceive::ConnectionClosed),
            }
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransportFailureKind> {
            self.send_calls += 1;
            if let Some(error) = self.send_failure.take() {
                return Err(error);
            }
            self.sent.push(frame.to_vec());
            Ok(())
        }
    }

    fn limits(max_frames: u32, max_bytes: usize) -> SessionLimits {
        let result = SessionLimits::try_new(max_frames, max_bytes);
        let Ok(limits) = result else {
            panic!("valid test session limits were rejected");
        };
        limits
    }

    #[test]
    fn send_validates_size_before_calling_adapter() {
        let mut session = BoundedSession::new(FakeTransport::default(), limits(2, 16));
        assert_eq!(session.send_frame(&[]), Err(SessionError::EmptyFrame));
        assert_eq!(
            session.send_frame(&vec![0x11; MAX_FRAME_BYTES + 1]),
            Err(SessionError::FrameTooLarge)
        );
        assert_eq!(session.sent_usage().frames(), 0);
        assert_eq!(session.into_inner().send_calls, 0);
    }

    #[test]
    fn successful_send_updates_bounded_usage() {
        let mut session = BoundedSession::new(FakeTransport::default(), limits(2, 8));
        assert!(session.send_frame(&[1, 2, 3]).is_ok());
        assert!(session.send_frame(&[4, 5, 6, 7, 8]).is_ok());
        assert_eq!(session.sent_usage().frames(), 2);
        assert_eq!(session.sent_usage().bytes(), 8);
        let transport = session.into_inner();
        assert_eq!(transport.sent, vec![vec![1, 2, 3], vec![4, 5, 6, 7, 8]]);
    }

    #[test]
    fn exact_maximum_frame_is_accepted() {
        let mut session = BoundedSession::new(FakeTransport::default(), limits(1, MAX_FRAME_BYTES));
        assert!(session.send_frame(&vec![0x11; MAX_FRAME_BYTES]).is_ok());
        assert_eq!(session.sent_usage().frames(), 1);
        assert_eq!(session.sent_usage().bytes(), MAX_FRAME_BYTES);
    }

    #[test]
    fn send_failure_terminates_without_charging_frame() {
        let transport = FakeTransport {
            send_failure: Some(TransportFailureKind::Unavailable),
            ..FakeTransport::default()
        };
        let mut session = BoundedSession::new(transport, limits(1, 8));
        assert_eq!(
            session.send_frame(&[1, 2, 3]),
            Err(SessionError::TransportFailure(
                TransportFailureKind::Unavailable
            ))
        );
        assert_eq!(session.sent_usage().frames(), 0);
        assert_eq!(session.sent_usage().bytes(), 0);
        assert!(session.is_terminated());
    }

    #[test]
    fn frame_and_byte_quota_terminate_session_before_send() {
        let mut by_frames = BoundedSession::new(FakeTransport::default(), limits(1, 8));
        assert!(by_frames.send_frame(&[1]).is_ok());
        assert_eq!(
            by_frames.send_frame(&[2]),
            Err(SessionError::FrameQuotaReached)
        );
        assert!(by_frames.is_terminated());
        assert_eq!(by_frames.into_inner().send_calls, 1);

        let mut by_bytes = BoundedSession::new(FakeTransport::default(), limits(2, 1));
        assert!(by_bytes.send_frame(&[1]).is_ok());
        assert_eq!(
            by_bytes.send_frame(&[2]),
            Err(SessionError::ByteQuotaReached)
        );
        assert_eq!(by_bytes.into_inner().send_calls, 1);
    }

    #[test]
    fn receive_requires_one_fixed_bounded_buffer() {
        let mut transport = FakeTransport::default();
        transport.incoming.push_back(Incoming::Frame(vec![1, 2, 3]));
        let mut session = BoundedSession::new(transport, limits(1, MAX_FRAME_BYTES));
        let mut short = vec![0_u8; MAX_FRAME_BYTES - 1];
        assert_eq!(
            session.receive_frame(&mut short),
            Err(SessionError::ReceiveBufferTooSmall)
        );
        assert!(!session.is_terminated());

        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        let received = session.receive_frame(&mut buffer);
        let Ok(Some(frame)) = received else {
            panic!("valid bounded frame was not received");
        };
        assert_eq!(frame, [1, 2, 3]);
        assert_eq!(session.received_usage().bytes(), 3);
        assert_eq!(
            session.into_inner().receive_capacities,
            vec![MAX_FRAME_BYTES]
        );
    }

    #[test]
    fn remaining_byte_quota_limits_adapter_before_read() {
        let mut transport = FakeTransport::default();
        transport.incoming.push_back(Incoming::Frame(vec![1, 2, 3]));
        transport.incoming.push_back(Incoming::Frame(vec![4, 5]));
        let mut session = BoundedSession::new(transport, limits(2, 5));
        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        assert!(matches!(session.receive_frame(&mut buffer), Ok(Some(_))));
        assert!(matches!(session.receive_frame(&mut buffer), Ok(Some(_))));
        assert_eq!(session.received_usage().bytes(), 5);
        assert_eq!(session.into_inner().receive_capacities, vec![5, 2]);
    }

    #[test]
    fn exhausted_receive_quotas_stop_before_another_adapter_call() {
        let mut by_frames = FakeTransport::default();
        by_frames.incoming.push_back(Incoming::Frame(vec![1]));
        by_frames.incoming.push_back(Incoming::Frame(vec![2]));
        let mut session = BoundedSession::new(by_frames, limits(1, 2));
        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        assert!(matches!(session.receive_frame(&mut buffer), Ok(Some(_))));
        assert_eq!(
            session.receive_frame(&mut buffer),
            Err(SessionError::FrameQuotaReached)
        );
        assert_eq!(session.into_inner().receive_capacities.len(), 1);

        let mut by_bytes = FakeTransport::default();
        by_bytes.incoming.push_back(Incoming::Frame(vec![1, 2]));
        by_bytes.incoming.push_back(Incoming::Frame(vec![3]));
        let mut session = BoundedSession::new(by_bytes, limits(2, 2));
        assert!(matches!(session.receive_frame(&mut buffer), Ok(Some(_))));
        assert_eq!(
            session.receive_frame(&mut buffer),
            Err(SessionError::ByteQuotaReached)
        );
        assert_eq!(session.into_inner().receive_capacities.len(), 1);
    }

    #[test]
    fn invalid_adapter_length_and_empty_frame_terminate_session() {
        let mut invalid = FakeTransport::default();
        invalid
            .incoming
            .push_back(Incoming::LengthViolation(MAX_FRAME_BYTES + 1));
        let mut session = BoundedSession::new(invalid, SessionLimits::standard());
        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        assert_eq!(
            session.receive_frame(&mut buffer),
            Err(SessionError::AdapterLengthViolation)
        );
        assert!(session.is_terminated());
        assert_eq!(
            session.receive_frame(&mut buffer),
            Err(SessionError::SessionTerminated)
        );

        let mut empty = FakeTransport::default();
        empty.incoming.push_back(Incoming::Frame(Vec::new()));
        let mut session = BoundedSession::new(empty, SessionLimits::standard());
        assert_eq!(
            session.receive_frame(&mut buffer),
            Err(SessionError::EmptyFrame)
        );
        assert!(session.is_terminated());
    }

    #[test]
    fn transport_failure_and_close_do_not_expose_external_details() {
        let mut failing = FakeTransport::default();
        failing
            .incoming
            .push_back(Incoming::Failure(TransportFailureKind::ConnectionFailed));
        let mut session = BoundedSession::new(failing, SessionLimits::standard());
        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        let error = session.receive_frame(&mut buffer);
        assert_eq!(
            error,
            Err(SessionError::TransportFailure(
                TransportFailureKind::ConnectionFailed
            ))
        );
        assert_eq!(
            format!("{:?}", error),
            "Err(TransportFailure(ConnectionFailed))"
        );
        assert!(session.is_terminated());

        let mut closed = FakeTransport::default();
        closed.incoming.push_back(Incoming::Closed);
        let mut session = BoundedSession::new(closed, SessionLimits::standard());
        assert!(matches!(session.receive_frame(&mut buffer), Ok(None)));
        assert!(session.is_terminated());
    }

    #[test]
    fn debug_redacts_exact_traffic_bytes_and_transport_state() {
        let mut session = BoundedSession::new(FakeTransport::default(), limits(2, 16));
        assert!(session.send_frame(&[0x5a; 7]).is_ok());
        let output = format!("{session:?}");
        assert!(!output.contains("FakeTransport"));
        assert!(!output.contains("bytes: 7"));
        assert!(!output.contains("90"));
        assert!(output.contains("redacted"));
    }

    #[test]
    fn deterministic_sequence_never_exceeds_hard_limits() {
        let mut session = BoundedSession::new(
            FakeTransport::default(),
            limits(MAX_SESSION_FRAMES, MAX_SESSION_BYTES),
        );
        for step in 0..MAX_SESSION_FRAMES {
            let length = usize::try_from((step % 64) + 1)
                .unwrap_or_else(|_| panic!("bounded frame length conversion failed"));
            assert!(session.send_frame(&vec![0x33; length]).is_ok());
            assert!(session.sent_usage().frames() <= MAX_SESSION_FRAMES);
            assert!(session.sent_usage().bytes() <= MAX_SESSION_BYTES);
        }
        assert_eq!(
            session.send_frame(&[0x44]),
            Err(SessionError::FrameQuotaReached)
        );
        assert!(session.is_terminated());
    }
}
