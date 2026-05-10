use anyhow::Result;
use clap::Parser;
use std::io;

use scrypt_rs::{derive_key, format_full_output, format_short_output, normalize_passphrase};

/// Minimal CLI tool for scrypt key derivation with hex, base64, and BIP39 output.
///
/// Reads a passphrase from stdin (first line), normalizes whitespace, and
/// derives a key using scrypt.
#[derive(Parser)]
#[command(name = "scrypt-rs", version, about)]
struct Cli {
    /// Return only the hex-encoded derived key
    #[arg(short = 'S', long = "short")]
    short: bool,

    /// Salt string
    #[arg(short = 's', long = "salt", default_value = "")]
    salt: String,

    /// log2(N) CPU/memory cost parameter for scrypt
    #[arg(short = 'L', long = "logn", default_value_t = 19)]
    log_n: u8,

    /// r (block size) parameter for scrypt
    #[arg(short = 'r', default_value_t = 8)]
    r: u32,

    /// p (parallelization) parameter for scrypt
    #[arg(short = 'p', default_value_t = 2)]
    p: u32,

    /// Derived key length in bytes
    #[arg(short = 'l', long = "len", default_value_t = 16)]
    len: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let pass = normalize_passphrase(&input);

    let dk = derive_key(&pass, &cli.salt, cli.log_n, cli.r, cli.p, cli.len)?;

    if cli.short {
        println!("{}", format_short_output(&dk));
    } else {
        println!(
            "{}",
            format_full_output(&dk, &pass, &cli.salt, cli.log_n, cli.r, cli.p, cli.len)
        );
    }

    Ok(())
}
