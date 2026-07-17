// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

mod contact;
mod error;
mod files;
mod node;

use std::{
    ffi::OsString,
    io::{BufRead, Write},
    path::PathBuf,
};

use lantern_secret_storage::SecretProfile;

use contact::{InvitePaths, RespondPaths};
pub use error::CliError;
use node::SendRequest;

enum Command {
    Help,
    ProfileInit {
        profile: PathBuf,
        passphrase: PathBuf,
    },
    NodeInit {
        node: PathBuf,
    },
    ContactInvite {
        profile: PathBuf,
        passphrase: PathBuf,
        name: String,
        invitation_out: PathBuf,
        response_in: PathBuf,
        initiator_confirmation_in: PathBuf,
        receiver_confirmation_out: PathBuf,
    },
    ContactRespond {
        profile: PathBuf,
        passphrase: PathBuf,
        name: String,
        invitation_in: PathBuf,
        response_out: PathBuf,
        initiator_confirmation_out: PathBuf,
        receiver_confirmation_in: PathBuf,
    },
    Contacts {
        profile: PathBuf,
        passphrase: PathBuf,
    },
    Send {
        profile: PathBuf,
        passphrase: PathBuf,
        node: PathBuf,
        contact: String,
        message: PathBuf,
        ttl_seconds: u64,
        max_hops: u64,
    },
    Listen {
        node: PathBuf,
        address: String,
    },
    Connect {
        node: PathBuf,
        address: String,
    },
    Receive {
        profile: PathBuf,
        passphrase: PathBuf,
        node: PathBuf,
    },
    Inbox {
        profile: PathBuf,
        passphrase: PathBuf,
    },
    Diagnostics {
        node: PathBuf,
    },
}

pub fn run(
    arguments: impl IntoIterator<Item = OsString>,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match parse(arguments)? {
        Command::Help => help(output),
        Command::ProfileInit {
            profile,
            passphrase,
        } => {
            let passphrase = files::read_passphrase(&passphrase)?;
            SecretProfile::create(&profile, &passphrase).map_err(|_| CliError::Profile)?;
            writeln!(output, "Profile created.").map_err(|_| CliError::Io)
        }
        Command::NodeInit { node } => node::create_node(&node, output),
        Command::ContactInvite {
            profile,
            passphrase,
            name,
            invitation_out,
            response_in,
            initiator_confirmation_in,
            receiver_confirmation_out,
        } => contact::invite(
            &profile,
            &passphrase,
            name,
            InvitePaths {
                invitation_out: &invitation_out,
                response_in: &response_in,
                initiator_confirmation_in: &initiator_confirmation_in,
                receiver_confirmation_out: &receiver_confirmation_out,
            },
            input,
            output,
        ),
        Command::ContactRespond {
            profile,
            passphrase,
            name,
            invitation_in,
            response_out,
            initiator_confirmation_out,
            receiver_confirmation_in,
        } => contact::respond(
            &profile,
            &passphrase,
            name,
            RespondPaths {
                invitation_in: &invitation_in,
                response_out: &response_out,
                initiator_confirmation_out: &initiator_confirmation_out,
                receiver_confirmation_in: &receiver_confirmation_in,
            },
            input,
            output,
        ),
        Command::Contacts {
            profile,
            passphrase,
        } => contact::list(&profile, &passphrase, output),
        Command::Send {
            profile,
            passphrase,
            node,
            contact,
            message,
            ttl_seconds,
            max_hops,
        } => node::send(
            SendRequest {
                profile_path: &profile,
                passphrase_path: &passphrase,
                node_path: &node,
                contact_name: &contact,
                message_path: &message,
                ttl_seconds,
                max_hops,
            },
            output,
        ),
        Command::Listen { node, address } => node::listen_once(&node, &address, output),
        Command::Connect { node, address } => node::connect_once(&node, &address, output),
        Command::Receive {
            profile,
            passphrase,
            node,
        } => node::receive(&profile, &passphrase, &node, output),
        Command::Inbox {
            profile,
            passphrase,
        } => node::inbox(&profile, &passphrase, output),
        Command::Diagnostics { node } => node::diagnostics(&node, output),
    }
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, CliError> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or(CliError::Usage)?;
    let command = command.to_str().ok_or(CliError::Usage)?;
    let values = arguments.collect::<Vec<_>>();
    match command {
        "help" if values.is_empty() => Ok(Command::Help),
        "profile-init" if values.len() == 2 => Ok(Command::ProfileInit {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
        }),
        "node-init" if values.len() == 1 => Ok(Command::NodeInit {
            node: path(&values, 0)?,
        }),
        "contact-invite" if values.len() == 7 => Ok(Command::ContactInvite {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
            name: text(&values, 2)?,
            invitation_out: path(&values, 3)?,
            response_in: path(&values, 4)?,
            initiator_confirmation_in: path(&values, 5)?,
            receiver_confirmation_out: path(&values, 6)?,
        }),
        "contact-respond" if values.len() == 7 => Ok(Command::ContactRespond {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
            name: text(&values, 2)?,
            invitation_in: path(&values, 3)?,
            response_out: path(&values, 4)?,
            initiator_confirmation_out: path(&values, 5)?,
            receiver_confirmation_in: path(&values, 6)?,
        }),
        "contacts" if values.len() == 2 => Ok(Command::Contacts {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
        }),
        "send" if values.len() == 7 => Ok(Command::Send {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
            node: path(&values, 2)?,
            contact: text(&values, 3)?,
            message: path(&values, 4)?,
            ttl_seconds: number(&values, 5)?,
            max_hops: number(&values, 6)?,
        }),
        "listen" if values.len() == 2 => Ok(Command::Listen {
            node: path(&values, 0)?,
            address: text(&values, 1)?,
        }),
        "connect" if values.len() == 2 => Ok(Command::Connect {
            node: path(&values, 0)?,
            address: text(&values, 1)?,
        }),
        "receive" if values.len() == 3 => Ok(Command::Receive {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
            node: path(&values, 2)?,
        }),
        "inbox" if values.len() == 2 => Ok(Command::Inbox {
            profile: path(&values, 0)?,
            passphrase: path(&values, 1)?,
        }),
        "diagnostics" if values.len() == 1 => Ok(Command::Diagnostics {
            node: path(&values, 0)?,
        }),
        _ => Err(CliError::Usage),
    }
}

fn path(values: &[OsString], index: usize) -> Result<PathBuf, CliError> {
    values.get(index).map(PathBuf::from).ok_or(CliError::Usage)
}

fn text(values: &[OsString], index: usize) -> Result<String, CliError> {
    values
        .get(index)
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .ok_or(CliError::Usage)
}

fn number(values: &[OsString], index: usize) -> Result<u64, CliError> {
    text(values, index)?
        .parse()
        .map_err(|_| CliError::InvalidNumber)
}

fn help(output: &mut dyn Write) -> Result<(), CliError> {
    writeln!(
        output,
        "lantern-cli 0.1 experimental preview\n\
         \n\
         profile-init PROFILE PASSFILE\n\
         node-init NODE\n\
         contact-invite PROFILE PASSFILE NAME INVITE RESPONSE CONFIRM_IN CONFIRM_OUT\n\
         contact-respond PROFILE PASSFILE NAME INVITE RESPONSE CONFIRM_OUT CONFIRM_IN\n\
         contacts PROFILE PASSFILE\n\
         send PROFILE PASSFILE NODE CONTACT MESSAGEFILE TTL MAX_HOPS\n\
         listen NODE BIND_ADDRESS\n\
         connect NODE PEER_ADDRESS\n\
         receive PROFILE PASSFILE NODE\n\
         inbox PROFILE PASSFILE\n\
         diagnostics NODE"
    )
    .map_err(|_| CliError::Io)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{CliError, Command, parse};

    #[test]
    fn parser_rejects_missing_extra_and_invalid_numeric_arguments() {
        assert!(matches!(parse([OsString::from("help")]), Ok(Command::Help)));
        assert!(matches!(
            parse([OsString::from("send")]),
            Err(CliError::Usage)
        ));
        assert!(matches!(
            parse([
                OsString::from("send"),
                OsString::from("p"),
                OsString::from("k"),
                OsString::from("n"),
                OsString::from("c"),
                OsString::from("m"),
                OsString::from("bad"),
                OsString::from("2"),
            ]),
            Err(CliError::InvalidNumber)
        ));
    }
}
