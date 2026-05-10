use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("scrypt-rs").unwrap()
}

#[test]
fn cli_short_mode() {
    cmd()
        .args([
            "-S", "-s", "salty", "-L", "9", "-r", "8", "-p", "1", "-l", "16",
        ])
        .write_stdin("hello world\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("6f17c79ddea39226d18cab929e3b483e"));
}

#[test]
fn cli_full_mode() {
    cmd()
        .args(["-s", "salty", "-L", "9", "-r", "8", "-p", "1", "-l", "16"])
        .write_stdin("hello world\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Input | Salt: \"salty\""))
        .stdout(predicate::str::contains(
            "Input | Normalized passphrase: \"hello world\"",
        ))
        .stdout(predicate::str::contains(
            "hexadecimal: 6f17c79ddea39226d18cab929e3b483e",
        ))
        .stdout(predicate::str::contains("base64: bxfHnd6jkibRjKuSnjtIPg=="))
        .stdout(predicate::str::contains("BIP39 words list representation:"));
}

#[test]
fn cli_default_params() {
    // Just verify it runs with defaults (log_n=19 is slow, so use explicit fast params)
    cmd()
        .args(["-S", "-s", "", "-L", "9", "-r", "8", "-p", "1", "-l", "16"])
        .write_stdin("test\n")
        .assert()
        .success();
}

#[test]
fn cli_whitespace_normalization() {
    // "  hello   world  \n" should normalize to "hello world"
    cmd()
        .args([
            "-S", "-s", "test", "-L", "9", "-r", "8", "-p", "1", "-l", "16",
        ])
        .write_stdin("  hello   world  \n")
        .assert()
        .success()
        .stdout(predicate::str::contains("86d95aaab3bbc77265e1dcfc822c7e48"));
}

#[test]
fn cli_empty_passphrase() {
    cmd()
        .args(["-S", "-s", "", "-L", "9", "-r", "8", "-p", "1", "-l", "16"])
        .write_stdin("\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("9d6e54a7a7f4b1dfc2e4da1bf0f1930c"));
}

#[test]
fn cli_32_byte_output_with_bip39() {
    cmd()
        .args(["-s", "salt123", "-L", "9", "-r", "8", "-p", "1", "-l", "32"])
        .write_stdin("mnemonic test\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "921a47527109bd15f339a5f480e61e6ce79593bc0b99954ddfea84a590b35a81",
        ))
        .stdout(predicate::str::contains("BIP39 words list representation:"));
}

#[test]
fn cli_invalid_bip39_length() {
    cmd()
        .args(["-s", "salt", "-L", "9", "-r", "8", "-p", "1", "-l", "17"])
        .write_stdin("invalid bip39\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Unable to generate words list"));
}
