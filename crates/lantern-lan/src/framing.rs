// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::Instant,
};

use lantern_transport::{FrameReceive, MAX_FRAME_BYTES, TransportFailureKind};

pub const FRAME_LENGTH_PREFIX_BYTES: usize = 4;

pub(crate) fn receive_wire_frame(
    stream: &mut TcpStream,
    destination: &mut [u8],
    timeout: Duration,
) -> Result<FrameReceive, TransportFailureKind> {
    let deadline = deadline_after(timeout)?;
    let Some(prefix) = read_prefix(stream, deadline)? else {
        return Ok(FrameReceive::ConnectionClosed);
    };
    let frame_bytes = decode_frame_length(prefix, destination.len())?;
    read_exact_before(stream, &mut destination[..frame_bytes], deadline)?;
    Ok(FrameReceive::Complete(frame_bytes))
}

pub(crate) fn send_wire_frame(
    stream: &mut TcpStream,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), TransportFailureKind> {
    let prefix = encode_frame_length(frame.len())?;
    let deadline = deadline_after(timeout)?;
    write_all_before(stream, &prefix, deadline)?;
    write_all_before(stream, frame, deadline)
}

fn read_prefix(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Option<[u8; FRAME_LENGTH_PREFIX_BYTES]>, TransportFailureKind> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_BYTES];
    loop {
        apply_read_deadline(stream, deadline)?;
        match stream.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => return Err(TransportFailureKind::ProtocolViolation),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_frame_io(error)),
        }
    }
    read_exact_before(stream, &mut prefix[1..], deadline)?;
    Ok(Some(prefix))
}

fn read_exact_before(
    stream: &mut TcpStream,
    mut destination: &mut [u8],
    deadline: Instant,
) -> Result<(), TransportFailureKind> {
    while !destination.is_empty() {
        apply_read_deadline(stream, deadline)?;
        match stream.read(destination) {
            Ok(0) => return Err(TransportFailureKind::Unavailable),
            Ok(read_bytes) => destination = &mut destination[read_bytes..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_frame_io(error)),
        }
    }
    Ok(())
}

fn write_all_before(
    stream: &mut TcpStream,
    mut source: &[u8],
    deadline: Instant,
) -> Result<(), TransportFailureKind> {
    while !source.is_empty() {
        apply_write_deadline(stream, deadline)?;
        match stream.write(source) {
            Ok(0) => return Err(TransportFailureKind::Unavailable),
            Ok(written_bytes) => source = &source[written_bytes..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_frame_io(error)),
        }
    }
    Ok(())
}

fn decode_frame_length(
    prefix: [u8; FRAME_LENGTH_PREFIX_BYTES],
    destination_bytes: usize,
) -> Result<usize, TransportFailureKind> {
    let encoded = u32::from_be_bytes(prefix);
    let frame_bytes =
        usize::try_from(encoded).map_err(|_| TransportFailureKind::ProtocolViolation)?;
    if frame_bytes == 0 || frame_bytes > MAX_FRAME_BYTES {
        return Err(TransportFailureKind::ProtocolViolation);
    }
    if frame_bytes > destination_bytes {
        return Err(TransportFailureKind::ResourceExhausted);
    }
    Ok(frame_bytes)
}

fn encode_frame_length(
    frame_bytes: usize,
) -> Result<[u8; FRAME_LENGTH_PREFIX_BYTES], TransportFailureKind> {
    if frame_bytes == 0 || frame_bytes > MAX_FRAME_BYTES {
        return Err(TransportFailureKind::ProtocolViolation);
    }
    let encoded =
        u32::try_from(frame_bytes).map_err(|_| TransportFailureKind::ProtocolViolation)?;
    Ok(encoded.to_be_bytes())
}

fn deadline_after(timeout: Duration) -> Result<Instant, TransportFailureKind> {
    if timeout.is_zero() {
        return Err(TransportFailureKind::Interrupted);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(TransportFailureKind::Interrupted)
}

fn apply_read_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), TransportFailureKind> {
    stream
        .set_read_timeout(Some(remaining_time(deadline)?))
        .map_err(map_frame_io)
}

fn apply_write_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), TransportFailureKind> {
    stream
        .set_write_timeout(Some(remaining_time(deadline)?))
        .map_err(map_frame_io)
}

fn remaining_time(deadline: Instant) -> Result<Duration, TransportFailureKind> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(TransportFailureKind::Interrupted);
    }
    Ok(remaining)
}

fn map_frame_io(error: io::Error) -> TransportFailureKind {
    match error.kind() {
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            TransportFailureKind::Interrupted
        }
        io::ErrorKind::OutOfMemory => TransportFailureKind::ResourceExhausted,
        io::ErrorKind::InvalidData => TransportFailureKind::ProtocolViolation,
        _ => TransportFailureKind::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{FRAME_LENGTH_PREFIX_BYTES, decode_frame_length, encode_frame_length};
    use lantern_transport::{MAX_FRAME_BYTES, TransportFailureKind};
    use proptest::{
        prelude::*,
        test_runner::{Config, RngAlgorithm, RngSeed},
    };

    fn property_config() -> Config {
        Config {
            cases: 256,
            rng_algorithm: RngAlgorithm::ChaCha,
            rng_seed: RngSeed::Fixed(0x4c41_4e46_5241_4d45),
            ..Config::default()
        }
    }

    #[test]
    fn minimum_and_maximum_frames_have_big_endian_prefixes() {
        assert_eq!(encode_frame_length(1), Ok([0, 0, 0, 1]));
        assert_eq!(encode_frame_length(MAX_FRAME_BYTES), Ok([0, 1, 0, 0]));
    }

    #[test]
    fn empty_oversized_and_capacity_excess_are_rejected_before_body_read() {
        assert_eq!(
            decode_frame_length([0, 0, 0, 0], MAX_FRAME_BYTES),
            Err(TransportFailureKind::ProtocolViolation)
        );
        assert_eq!(
            decode_frame_length([0, 1, 0, 1], MAX_FRAME_BYTES),
            Err(TransportFailureKind::ProtocolViolation)
        );
        assert_eq!(
            decode_frame_length([0, 0, 0, 2], 1),
            Err(TransportFailureKind::ResourceExhausted)
        );
        assert_eq!(
            encode_frame_length(0),
            Err(TransportFailureKind::ProtocolViolation)
        );
        assert_eq!(
            encode_frame_length(MAX_FRAME_BYTES + 1),
            Err(TransportFailureKind::ProtocolViolation)
        );
    }

    proptest! {
        #![proptest_config(property_config())]

        #[test]
        fn arbitrary_prefixes_follow_only_the_documented_length_rule(
            prefix in any::<[u8; FRAME_LENGTH_PREFIX_BYTES]>(),
            capacity in 0_usize..=(MAX_FRAME_BYTES + 1),
        ) {
            let encoded = u32::from_be_bytes(prefix);
            let logical = usize::try_from(encoded).unwrap_or(usize::MAX);
            let result = decode_frame_length(prefix, capacity);
            if logical == 0 || logical > MAX_FRAME_BYTES {
                prop_assert_eq!(result, Err(TransportFailureKind::ProtocolViolation));
            } else if logical > capacity {
                prop_assert_eq!(result, Err(TransportFailureKind::ResourceExhausted));
            } else {
                prop_assert_eq!(result, Ok(logical));
            }
        }
    }
}
