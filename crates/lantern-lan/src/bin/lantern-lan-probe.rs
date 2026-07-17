// SPDX-License-Identifier: MPL-2.0

use core::str::FromStr;
use std::{env, ffi::OsString, io::Write, process::ExitCode};

use lantern_lan::{BindAddress, LanListener, PeerAddress, connect};

const USAGE: &[u8] = b"usage:\n  lantern-lan-probe listen <private-ip:port>\n  lantern-lan-probe connect <private-ip:port>\n";
const SUCCESS: &[u8] = b"Lantern LAN version 1 negotiated\n";
const INVALID_ARGUMENTS: &[u8] = b"invalid LAN probe arguments\n";
const NEGOTIATION_FAILED: &[u8] = b"LAN version negotiation failed\n";

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(()) => write_message(std::io::stdout(), SUCCESS),
        Err(ProbeError::Arguments) => {
            let _ = write_message(std::io::stderr(), INVALID_ARGUMENTS);
            let _ = write_message(std::io::stderr(), USAGE);
            ExitCode::FAILURE
        }
        Err(ProbeError::Lan) => write_message(std::io::stderr(), NEGOTIATION_FAILED),
    }
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), ProbeError> {
    let _program = arguments.next();
    let mode = arguments.next().ok_or(ProbeError::Arguments)?;
    let address = arguments.next().ok_or(ProbeError::Arguments)?;
    if arguments.next().is_some() {
        return Err(ProbeError::Arguments);
    }
    let mode = mode.into_string().map_err(|_| ProbeError::Arguments)?;
    let address = address.into_string().map_err(|_| ProbeError::Arguments)?;

    match mode.as_str() {
        "listen" => {
            let address = BindAddress::from_str(&address).map_err(|_| ProbeError::Arguments)?;
            let listener = LanListener::bind(address).map_err(|_| ProbeError::Lan)?;
            let connection = listener.accept().map_err(|_| ProbeError::Lan)?;
            connection.shutdown().map_err(|_| ProbeError::Lan)
        }
        "connect" => {
            let address = PeerAddress::from_str(&address).map_err(|_| ProbeError::Arguments)?;
            let connection = connect(address).map_err(|_| ProbeError::Lan)?;
            connection.shutdown().map_err(|_| ProbeError::Lan)
        }
        _ => Err(ProbeError::Arguments),
    }
}

fn write_message(mut output: impl Write, message: &[u8]) -> ExitCode {
    if output.write_all(message).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeError {
    Arguments,
    Lan,
}

#[cfg(test)]
mod tests {
    use super::{ProbeError, run};
    use std::ffi::OsString;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(|value| OsString::from((*value).to_owned()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn rejects_missing_extra_and_public_arguments_before_network_use() {
        assert_eq!(run(arguments(&["probe"])), Err(ProbeError::Arguments));
        assert_eq!(
            run(arguments(&["probe", "connect", "8.8.8.8:53"])),
            Err(ProbeError::Arguments)
        );
        assert_eq!(
            run(arguments(
                &["probe", "connect", "127.0.0.1:38383", "extra",]
            )),
            Err(ProbeError::Arguments)
        );
    }
}
