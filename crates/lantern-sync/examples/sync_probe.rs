// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::{env, ffi::OsString, io::Write, process::ExitCode};

use lantern_core::{Envelope, MESSAGE_ID_LENGTH, MessageId, NORMAL_PRIORITY, PROTOCOL_VERSION};
use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};
use lantern_sync::{EnvelopeSink, SyncSinkError, receive_batch, send_batch};
use lantern_transport::{BoundedSession, SessionLimits};

const USAGE: &[u8] =
    b"usage:\n  sync-probe listen <private-ip:port>\n  sync-probe connect <private-ip:port>\n";
const SUCCESS: &[u8] = b"One synthetic Lantern Envelope synchronized\n";
const FAILED: &[u8] = b"Lantern sync probe failed\n";
const PAYLOAD: &[u8] = b"LANTERN-SYNTHETIC-SYNC-PAYLOAD-V1";

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(()) => write_message(std::io::stdout(), SUCCESS),
        Err(()) => {
            let _ = write_message(std::io::stderr(), FAILED);
            let _ = write_message(std::io::stderr(), USAGE);
            ExitCode::FAILURE
        }
    }
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), ()> {
    let _program = arguments.next();
    let mode = arguments.next().ok_or(())?.into_string().map_err(|_| ())?;
    let address = arguments.next().ok_or(())?.into_string().map_err(|_| ())?;
    if arguments.next().is_some() {
        return Err(());
    }

    match mode.as_str() {
        "listen" => {
            let address = BindAddress::from_str(&address).map_err(|_| ())?;
            let listener = LanListener::bind(address).map_err(|_| ())?;
            let connection = listener.accept().map_err(|_| ())?;
            let session = BoundedSession::new(connection, SessionLimits::default());
            let mut sink = ProbeSink::default();
            let (_session, summary) = receive_batch(session, &mut sink).map_err(|_| ())?;
            if summary.transferred() != 1 || sink.accepted != 1 {
                return Err(());
            }
            Ok(())
        }
        "connect" => {
            let address = PeerAddress::from_str(&address).map_err(|_| ())?;
            let connection = connect(address).map_err(|_| ())?;
            let session = BoundedSession::new(connection, SessionLimits::default());
            let envelope = synthetic_envelope()?;
            let (_session, summary) = send_batch(session, &[envelope]).map_err(|_| ())?;
            if summary.transferred() != 1 {
                return Err(());
            }
            Ok(())
        }
        _ => Err(()),
    }
}

fn synthetic_envelope() -> Result<Envelope, ()> {
    Envelope::try_from_fields(
        PROTOCOL_VERSION,
        [0x31; MESSAGE_ID_LENGTH],
        [0x42; 16],
        300,
        4,
        NORMAL_PRIORITY,
        PAYLOAD.to_vec(),
    )
    .map_err(|_| ())
}

#[derive(Default)]
struct ProbeSink {
    accepted: u8,
}

impl EnvelopeSink for ProbeSink {
    fn wants(&mut self, _message_id: MessageId) -> Result<bool, SyncSinkError> {
        Ok(self.accepted == 0)
    }

    fn accept(&mut self, envelope: Envelope) -> Result<(), SyncSinkError> {
        if envelope.protected_payload().as_bytes() != PAYLOAD || self.accepted != 0 {
            return Err(SyncSinkError::Rejected);
        }
        self.accepted = 1;
        Ok(())
    }
}

fn write_message(mut output: impl Write, message: &[u8]) -> ExitCode {
    if output.write_all(message).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
