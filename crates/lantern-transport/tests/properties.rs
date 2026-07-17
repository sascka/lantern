// SPDX-License-Identifier: MPL-2.0

use std::collections::VecDeque;

use lantern_transport::{
    BoundedSession, FrameReceive, FrameTransport, MAX_FRAME_BYTES, SessionError, SessionLimits,
    TransportFailureKind,
};
use proptest::{
    collection::vec,
    prelude::*,
    test_runner::{Config, RngAlgorithm, RngSeed},
};

fn config(seed: u64) -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(seed),
        ..Config::default()
    }
}

fn limits(max_frames: u32, max_bytes: usize) -> SessionLimits {
    let result = SessionLimits::try_new(max_frames, max_bytes);
    let Ok(limits) = result else {
        panic!("valid property-test session limits were rejected");
    };
    limits
}

#[derive(Default)]
struct TestTransport {
    incoming: VecDeque<usize>,
}

impl FrameTransport for TestTransport {
    fn receive_frame(
        &mut self,
        destination: &mut [u8],
    ) -> Result<FrameReceive, TransportFailureKind> {
        let Some(length) = self.incoming.pop_front() else {
            return Ok(FrameReceive::ConnectionClosed);
        };
        if length > destination.len() {
            return Err(TransportFailureKind::ProtocolViolation);
        }
        destination[..length].fill(0x33);
        Ok(FrameReceive::Complete(length))
    }

    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), TransportFailureKind> {
        Ok(())
    }
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e21))]

    #[test]
    fn outgoing_usage_matches_the_session_model(
        lengths in vec(1_usize..=2 * 1024, 1..=96),
    ) {
        let limits = limits(32, 16 * 1024);
        let mut session = BoundedSession::new(TestTransport::default(), limits);
        let mut expected_frames = 0_u32;
        let mut expected_bytes = 0_usize;
        let mut terminated = false;

        for length in lengths {
            let frame = vec![0x44; length];
            let result = session.send_frame(&frame);
            let expected = if terminated {
                Err(SessionError::SessionTerminated)
            } else if expected_frames == limits.max_frames() {
                terminated = true;
                Err(SessionError::FrameQuotaReached)
            } else if expected_bytes + length > limits.max_bytes() {
                terminated = true;
                Err(SessionError::ByteQuotaReached)
            } else {
                expected_frames += 1;
                expected_bytes += length;
                Ok(())
            };

            prop_assert_eq!(result, expected);
            prop_assert_eq!(session.sent_usage().frames(), expected_frames);
            prop_assert_eq!(session.sent_usage().bytes(), expected_bytes);
            prop_assert_eq!(session.is_terminated(), terminated);
        }
    }
}

proptest! {
    #![proptest_config(config(0x4c41_4e54_4552_4e22))]

    #[test]
    fn incoming_frames_never_cross_the_available_quota(
        lengths in vec(1_usize..=2 * 1024, 1..=64),
    ) {
        let limits = limits(16, 8 * 1024);
        let transport = TestTransport {
            incoming: lengths.iter().copied().collect(),
        };
        let mut session = BoundedSession::new(transport, limits);
        let mut buffer = vec![0_u8; MAX_FRAME_BYTES];
        let mut expected_frames = 0_u32;
        let mut expected_bytes = 0_usize;
        let mut terminated = false;

        for length in lengths {
            let result = session.receive_frame(&mut buffer);
            if terminated {
                prop_assert_eq!(result, Err(SessionError::SessionTerminated));
                continue;
            }
            if expected_frames == limits.max_frames() {
                prop_assert_eq!(result, Err(SessionError::FrameQuotaReached));
                terminated = true;
            } else if expected_bytes == limits.max_bytes() {
                prop_assert_eq!(result, Err(SessionError::ByteQuotaReached));
                terminated = true;
            } else if length > limits.max_bytes() - expected_bytes {
                prop_assert_eq!(
                    result,
                    Err(SessionError::TransportFailure(
                        TransportFailureKind::ProtocolViolation,
                    )),
                );
                terminated = true;
            } else {
                prop_assert!(result.is_ok());
                if let Ok(Some(frame)) = result {
                    prop_assert_eq!(frame.len(), length);
                } else {
                    prop_assert!(false, "adapter did not return a complete frame");
                }
                expected_frames += 1;
                expected_bytes += length;
            }

            prop_assert_eq!(session.received_usage().frames(), expected_frames);
            prop_assert_eq!(session.received_usage().bytes(), expected_bytes);
            prop_assert_eq!(session.is_terminated(), terminated);
        }
    }
}
