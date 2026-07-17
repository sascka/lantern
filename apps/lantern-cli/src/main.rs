// SPDX-License-Identifier: AGPL-3.0-or-later

use std::io::{self, Write as _};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    if let Err(error) = lantern_cli::run(std::env::args_os().skip(1), &mut input, &mut output) {
        let _ = writeln!(io::stderr().lock(), "error: {error}");
        std::process::exit(1);
    }
}
