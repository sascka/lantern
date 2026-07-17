// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    net::TcpListener,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lantern-cli-demo-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&path)
            .unwrap_or_else(|_| panic!("CLI test directory should be created"));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_lantern-cli")
}

fn path(value: &Path) -> OsString {
    value.as_os_str().to_owned()
}

fn text(value: &str) -> OsString {
    OsString::from(value)
}

fn run_ok(arguments: &[OsString]) -> Output {
    let output = Command::new(binary())
        .args(arguments)
        .output()
        .unwrap_or_else(|_| panic!("CLI command should start"));
    assert!(
        output.status.success(),
        "CLI command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn spawn_with_input(arguments: &[OsString], input: &[u8]) -> Child {
    let mut child = Command::new(binary())
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("CLI process should start"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("CLI process should have stdin"));
    stdin
        .write_all(input)
        .unwrap_or_else(|_| panic!("CLI process should receive its input"));
    drop(stdin);
    child
}

fn wait_ok(child: Child) -> Output {
    let output = child
        .wait_with_output()
        .unwrap_or_else(|_| panic!("CLI process should finish"));
    assert!(
        output.status.success(),
        "CLI process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn write_private(path: &Path, value: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("private CLI fixture should be created"));
    file.write_all(value)
        .unwrap_or_else(|_| panic!("private CLI fixture should be written"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("private CLI fixture should be synced"));
}

fn free_loopback_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("CLI test port should be allocated"));
    let port = listener
        .local_addr()
        .map(|address| address.port())
        .unwrap_or_else(|_| panic!("CLI test port should be available"));
    drop(listener);
    format!("127.0.0.1:{port}")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone())
        .unwrap_or_else(|_| panic!("CLI output should be UTF-8"))
}

fn sas(output: &Output) -> String {
    stdout(output)
        .lines()
        .find_map(|line| line.strip_prefix("SAS: ").map(str::to_owned))
        .unwrap_or_else(|| panic!("contact command should print SAS"))
}

fn directory_contains(directory: &Path, marker: &[u8]) -> bool {
    let entries =
        fs::read_dir(directory).unwrap_or_else(|_| panic!("CLI node directory should be readable"));
    for entry in entries {
        let entry = entry.unwrap_or_else(|_| panic!("CLI node entry should be readable"));
        let metadata = entry
            .metadata()
            .unwrap_or_else(|_| panic!("CLI node metadata should be readable"));
        if metadata.is_file() {
            let bytes = fs::read(entry.path())
                .unwrap_or_else(|_| panic!("CLI node file should be readable"));
            if bytes.windows(marker.len()).any(|window| window == marker) {
                return true;
            }
        }
    }
    false
}

#[test]
fn separate_cli_processes_deliver_one_encrypted_message_through_relay() {
    let temporary = TestDirectory::new();
    let alice_profile = temporary.path().join("alice-profile");
    let bob_profile = temporary.path().join("bob-profile");
    let alice_node = temporary.path().join("alice-node");
    let relay_node = temporary.path().join("relay-node");
    let bob_node = temporary.path().join("bob-node");
    let alice_pass = temporary.path().join("alice.pass");
    let bob_pass = temporary.path().join("bob.pass");
    let message_file = temporary.path().join("message.txt");
    let exchange = temporary.path().join("exchange");
    let mut exchange_builder = fs::DirBuilder::new();
    exchange_builder.mode(0o700);
    exchange_builder
        .create(&exchange)
        .unwrap_or_else(|_| panic!("contact exchange directory should be created"));

    let alice_secret = b"Alice CLI test passphrase 2026";
    let bob_secret = b"Bob CLI test passphrase 2026";
    let message = b"private CLI relay message 7c91";
    write_private(&alice_pass, alice_secret);
    write_private(&bob_pass, bob_secret);
    write_private(&message_file, message);

    let profile_outputs = [
        run_ok(&[
            text("profile-init"),
            path(&alice_profile),
            path(&alice_pass),
        ]),
        run_ok(&[text("profile-init"), path(&bob_profile), path(&bob_pass)]),
    ];
    let node_outputs = [
        run_ok(&[text("node-init"), path(&alice_node)]),
        run_ok(&[text("node-init"), path(&relay_node)]),
        run_ok(&[text("node-init"), path(&bob_node)]),
    ];

    let invitation = exchange.join("invitation.qr");
    let response = exchange.join("response.qr");
    let bob_confirmation = exchange.join("bob-confirmation.cbor");
    let alice_confirmation = exchange.join("alice-confirmation.cbor");
    let alice_contact = spawn_with_input(
        &[
            text("contact-invite"),
            path(&alice_profile),
            path(&alice_pass),
            text("Bob"),
            path(&invitation),
            path(&response),
            path(&bob_confirmation),
            path(&alice_confirmation),
        ],
        b"MATCH\n",
    );
    let bob_contact = spawn_with_input(
        &[
            text("contact-respond"),
            path(&bob_profile),
            path(&bob_pass),
            text("Alice"),
            path(&invitation),
            path(&response),
            path(&bob_confirmation),
            path(&alice_confirmation),
        ],
        b"MATCH\n",
    );
    let alice_contact = wait_ok(alice_contact);
    let bob_contact = wait_ok(bob_contact);
    assert_eq!(sas(&alice_contact), sas(&bob_contact));

    let alice_contacts = run_ok(&[text("contacts"), path(&alice_profile), path(&alice_pass)]);
    let bob_contacts = run_ok(&[text("contacts"), path(&bob_profile), path(&bob_pass)]);
    assert!(stdout(&alice_contacts).contains("Bob L1-"));
    assert!(stdout(&bob_contacts).contains("Alice L1-"));

    let send = run_ok(&[
        text("send"),
        path(&alice_profile),
        path(&alice_pass),
        path(&alice_node),
        text("Bob"),
        path(&message_file),
        text("3600"),
        text("2"),
    ]);
    assert!(
        !send
            .stdout
            .windows(message.len())
            .any(|window| window == message)
    );

    let first_address = free_loopback_address();
    let relay_listener = spawn_with_input(
        &[text("listen"), path(&relay_node), text(&first_address)],
        b"",
    );
    thread::sleep(Duration::from_millis(300));
    let alice_connection = run_ok(&[text("connect"), path(&alice_node), text(&first_address)]);
    let relay_received = wait_ok(relay_listener);

    let second_address = free_loopback_address();
    let bob_listener = spawn_with_input(
        &[text("listen"), path(&bob_node), text(&second_address)],
        b"",
    );
    thread::sleep(Duration::from_millis(300));
    let relay_connection = run_ok(&[text("connect"), path(&relay_node), text(&second_address)]);
    let bob_received = wait_ok(bob_listener);

    let received = run_ok(&[
        text("receive"),
        path(&bob_profile),
        path(&bob_pass),
        path(&bob_node),
    ]);
    assert!(
        received
            .stdout
            .windows(message.len())
            .any(|window| window == message)
    );
    let repeated_receive = run_ok(&[
        text("receive"),
        path(&bob_profile),
        path(&bob_pass),
        path(&bob_node),
    ]);
    assert!(stdout(&repeated_receive).contains("opened 0"));
    assert!(
        !repeated_receive
            .stdout
            .windows(message.len())
            .any(|window| window == message)
    );
    let inbox = run_ok(&[text("inbox"), path(&bob_profile), path(&bob_pass)]);
    assert!(
        inbox
            .stdout
            .windows(message.len())
            .any(|window| window == message)
    );

    let diagnostics = run_ok(&[text("diagnostics"), path(&relay_node)]);
    for output in profile_outputs.iter().chain(node_outputs.iter()).chain([
        &alice_contact,
        &bob_contact,
        &alice_contacts,
        &bob_contacts,
        &send,
        &alice_connection,
        &relay_received,
        &relay_connection,
        &bob_received,
        &diagnostics,
    ]) {
        for marker in [
            alice_secret.as_slice(),
            bob_secret.as_slice(),
            message.as_slice(),
        ] {
            assert!(
                !output
                    .stdout
                    .windows(marker.len())
                    .any(|window| window == marker)
            );
            assert!(
                !output
                    .stderr
                    .windows(marker.len())
                    .any(|window| window == marker)
            );
        }
    }
    for output in [&received, &repeated_receive, &inbox] {
        for marker in [alice_secret.as_slice(), bob_secret.as_slice()] {
            assert!(
                !output
                    .stdout
                    .windows(marker.len())
                    .any(|window| window == marker)
            );
            assert!(
                !output
                    .stderr
                    .windows(marker.len())
                    .any(|window| window == marker)
            );
        }
    }
    assert!(
        !diagnostics
            .stdout
            .windows(message.len())
            .any(|window| window == message)
    );
    assert!(!directory_contains(&relay_node, message));
    assert!(!relay_node.join("secrets.kdf").exists());
    assert!(!relay_node.join("secrets.sqlite3").exists());
}
