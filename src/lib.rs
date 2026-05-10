use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bip39::Mnemonic;
use scrypt::{scrypt, Params as ScryptParams};

/// Normalizes a passphrase by collapsing all contiguous whitespace into a
/// single space and trimming leading/trailing whitespace.
pub fn normalize_passphrase(input: &str) -> String {
    input.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Derives a key from `pass` and `salt` using scrypt with the given parameters.
///
/// `log_n` is log2 of the CPU/memory cost parameter N.
pub fn derive_key(
    pass: &str,
    salt: &str,
    log_n: u8,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<Vec<u8>> {
    let params = ScryptParams::new(log_n, r, p, dk_len)
        .map_err(|e| anyhow!("invalid scrypt parameters: {}", e))?;
    let mut dk = vec![0u8; dk_len];
    scrypt(pass.as_bytes(), salt.as_bytes(), &params, &mut dk)
        .map_err(|e| anyhow!("scrypt derivation failed: {}", e))?;
    Ok(dk)
}

/// Returns the hex-encoded representation of the derived key.
pub fn format_hex(dk: &[u8]) -> String {
    hex::encode(dk)
}

/// Returns the base64-encoded representation of the derived key.
pub fn format_base64(dk: &[u8]) -> String {
    BASE64.encode(dk)
}

/// Returns the BIP39 mnemonic for the derived key, or an error message if the
/// key length is not valid for BIP39 (must be 16, 20, 24, 28, or 32 bytes).
pub fn format_bip39(dk: &[u8]) -> String {
    match Mnemonic::from_entropy(dk) {
        Ok(m) => m.to_string(),
        Err(_) => "Unable to generate words list".to_string(),
    }
}

/// Produces the short (hex-only) output.
pub fn format_short_output(dk: &[u8]) -> String {
    format_hex(dk)
}

/// Produces the full verbose output showing inputs and all output formats.
pub fn format_full_output(
    dk: &[u8],
    pass: &str,
    salt: &str,
    log_n: u8,
    r: u32,
    p: u32,
    dk_len: usize,
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Input | Salt: \"{}\"", salt));
    lines.push(format!("Input | Normalized passphrase: \"{}\"", pass));
    lines.push(format!(
        "Input | Scrypt parameters: cost factor {} - blocksize {} - parallelization {} - key length in bytes {}",
        log_n, r, p, dk_len
    ));
    lines.push(format!(
        "Output| Scrypt derived key in hexadecimal: {}",
        format_hex(dk)
    ));
    lines.push(format!(
        "Output| Scrypt derived key in base64: {}",
        format_base64(dk)
    ));
    let bip39 = format_bip39(dk);
    if bip39 == "Unable to generate words list" {
        lines.push(format!("Output| Scrypt BIP39: {}", bip39));
    } else {
        lines.push(format!(
            "Output| Scrypt BIP39 words list representation: {}",
            bip39
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── normalize_passphrase ──────────────────────────────────────────

    #[test]
    fn normalize_trims_leading_trailing() {
        assert_eq!(normalize_passphrase("  hello  "), "hello");
    }

    #[test]
    fn normalize_collapses_inner_whitespace() {
        assert_eq!(normalize_passphrase("hello   world"), "hello world");
    }

    #[test]
    fn normalize_handles_tabs_and_newlines() {
        assert_eq!(normalize_passphrase("hello\t\n  world"), "hello world");
    }

    #[test]
    fn normalize_empty_string() {
        assert_eq!(normalize_passphrase(""), "");
    }

    #[test]
    fn normalize_only_whitespace() {
        assert_eq!(normalize_passphrase("   \t\n  "), "");
    }

    #[test]
    fn normalize_single_word() {
        assert_eq!(normalize_passphrase("  password  "), "password");
    }

    #[test]
    fn normalize_already_clean() {
        assert_eq!(normalize_passphrase("already clean"), "already clean");
    }

    #[test]
    fn normalize_preserves_stdin_newline() {
        assert_eq!(normalize_passphrase("hello world\n"), "hello world");
    }

    // ── derive_key ────────────────────────────────────────────────────

    #[test]
    fn derive_key_vector_hello_world() {
        let dk = derive_key("hello world", "salty", 9, 8, 1, 16).unwrap();
        assert_eq!(hex::encode(&dk), "6f17c79ddea39226d18cab929e3b483e");
    }

    #[test]
    fn derive_key_vector_empty() {
        let dk = derive_key("", "", 9, 8, 1, 16).unwrap();
        assert_eq!(hex::encode(&dk), "9d6e54a7a7f4b1dfc2e4da1bf0f1930c");
    }

    #[test]
    fn derive_key_vector_password_nacl() {
        let dk = derive_key("password", "NaCl", 10, 8, 2, 16).unwrap();
        assert_eq!(hex::encode(&dk), "6d1a16d34e5543ffa9f6322de7fc17a0");
    }

    #[test]
    fn derive_key_vector_32_bytes() {
        let dk = derive_key("mnemonic test", "salt123", 9, 8, 1, 32).unwrap();
        assert_eq!(
            hex::encode(&dk),
            "921a47527109bd15f339a5f480e61e6ce79593bc0b99954ddfea84a590b35a81"
        );
    }

    #[test]
    fn derive_key_vector_20_bytes() {
        let dk = derive_key("twenty bytes", "salt", 9, 8, 1, 20).unwrap();
        assert_eq!(hex::encode(&dk), "315d5f8dfbacf55f9397ed8cebc70c5d3279862d");
    }

    #[test]
    fn derive_key_invalid_params() {
        assert!(derive_key("pass", "salt", 0, 0, 0, 16).is_err());
    }

    // ── format_hex ────────────────────────────────────────────────────

    #[test]
    fn format_hex_known() {
        let dk = vec![0x6f, 0x17, 0xc7, 0x9d];
        assert_eq!(format_hex(&dk), "6f17c79d");
    }

    #[test]
    fn format_hex_empty() {
        assert_eq!(format_hex(&[]), "");
    }

    // ── format_base64 ─────────────────────────────────────────────────

    #[test]
    fn format_base64_known() {
        let dk = derive_key("hello world", "salty", 9, 8, 1, 16).unwrap();
        assert_eq!(format_base64(&dk), "bxfHnd6jkibRjKuSnjtIPg==");
    }

    #[test]
    fn format_base64_empty() {
        assert_eq!(format_base64(&[]), "");
    }

    // ── format_bip39 ──────────────────────────────────────────────────

    #[test]
    fn format_bip39_valid_16_bytes() {
        let dk = derive_key("hello world", "salty", 9, 8, 1, 16).unwrap();
        let words = format_bip39(&dk);
        assert_eq!(words.split_whitespace().count(), 12);
    }

    #[test]
    fn format_bip39_valid_32_bytes() {
        let dk = derive_key("mnemonic test", "salt123", 9, 8, 1, 32).unwrap();
        let words = format_bip39(&dk);
        assert_eq!(words.split_whitespace().count(), 24);
    }

    #[test]
    fn format_bip39_valid_20_bytes() {
        let dk = derive_key("twenty bytes", "salt", 9, 8, 1, 20).unwrap();
        let words = format_bip39(&dk);
        assert_eq!(words.split_whitespace().count(), 15);
    }

    #[test]
    fn format_bip39_invalid_length() {
        let dk = vec![0u8; 17];
        assert_eq!(format_bip39(&dk), "Unable to generate words list");
    }

    // ── format_short_output ───────────────────────────────────────────

    #[test]
    fn short_output_is_hex() {
        let dk = derive_key("hello world", "salty", 9, 8, 1, 16).unwrap();
        assert_eq!(format_short_output(&dk), "6f17c79ddea39226d18cab929e3b483e");
    }

    // ── format_full_output ────────────────────────────────────────────

    #[test]
    fn full_output_contains_all_sections() {
        let dk = derive_key("hello world", "salty", 9, 8, 1, 16).unwrap();
        let out = format_full_output(&dk, "hello world", "salty", 9, 8, 1, 16);
        assert!(out.contains("Input | Salt: \"salty\""));
        assert!(out.contains("Input | Normalized passphrase: \"hello world\""));
        assert!(out.contains("cost factor 9"));
        assert!(out.contains("blocksize 8"));
        assert!(out.contains("parallelization 1"));
        assert!(out.contains("key length in bytes 16"));
        assert!(out.contains("hexadecimal: 6f17c79ddea39226d18cab929e3b483e"));
        assert!(out.contains("base64: bxfHnd6jkibRjKuSnjtIPg=="));
        assert!(out.contains("BIP39 words list representation:"));
    }

    #[test]
    fn full_output_invalid_bip39_length() {
        let dk = vec![0u8; 17];
        let out = format_full_output(&dk, "test", "salt", 9, 8, 1, 17);
        assert!(out.contains("Scrypt BIP39: Unable to generate words list"));
    }

    #[test]
    fn full_output_empty_pass_and_salt() {
        let dk = derive_key("", "", 9, 8, 1, 16).unwrap();
        let out = format_full_output(&dk, "", "", 9, 8, 1, 16);
        assert!(out.contains("Salt: \"\""));
        assert!(out.contains("Normalized passphrase: \"\""));
        assert!(out.contains("hexadecimal: 9d6e54a7a7f4b1dfc2e4da1bf0f1930c"));
    }
}
