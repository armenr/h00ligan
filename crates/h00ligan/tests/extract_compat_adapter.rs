//! The shipped code-intelligence surfaces must not expose an authority-bypassing
//! live-source extraction command.

use std::process::Command;

#[test]
fn h00ligan_has_no_live_scan_extract_surface() {
    let help = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .arg("--help")
        .output()
        .expect("run h00ligan help");
    assert!(help.status.success(), "h00ligan --help must succeed");
    let help = String::from_utf8(help.stdout).expect("UTF-8 help");
    assert!(
        help.contains("index"),
        "known-positive control: the generation-producing index command must remain listed:\n{help}"
    );
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("extract")),
        "a live-scan command bypasses immutable-generation authority and must not be shipped:\n{help}"
    );

    let rejected = Command::new(env!("CARGO_BIN_EXE_h00ligan"))
        .args(["extract", "."])
        .output()
        .expect("invoke retired extract command");
    assert!(
        !rejected.status.success(),
        "the retired live-scan command must be rejected"
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("unrecognized subcommand") && stderr.contains("extract"),
        "rejection must identify the absent command:\n{stderr}"
    );
}
