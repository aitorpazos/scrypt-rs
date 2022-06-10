extern crate base64;
extern crate bip39;
extern crate crypto;
extern crate hex;
extern crate regex;

#[macro_use]
extern crate clap;

use bip39::Mnemonic;
use clap::{App, Arg, ArgMatches};
use crypto::scrypt;
use regex::Regex;
use std::io;

/// Defines command line arguments
fn arg_matches<'a>() -> ArgMatches<'a> {
    App::new("scrypt-rs")
        .about("Read passphrase (first line from stdin), normalize it (drop extra whitespace) and pass it to scrypt")
        .arg(Arg::with_name("short").short("S").long("short").takes_value(false)
            .help("Return hex encoded scrypt derivated key"))
        .arg(Arg::with_name("salt").short("s").long("salt").takes_value(true).default_value("")
            .help("Set salt"))
        .arg(Arg::with_name("logN").short("L").long("logn").takes_value(true).default_value("19")
            .help("log₂N (CPU/memory cost) param for scrypt"))
        .arg(Arg::with_name("r").short("r").takes_value(true).default_value("8")
            .help("r (blocksize) param for scrypt"))
        .arg(Arg::with_name("p").short("p").takes_value(true).default_value("2")
            .help("p (parallelization) param for scrypt"))
        .arg(Arg::with_name("len").short("l").long("len").takes_value(true).default_value("16")
            .help("Derived key length in bytes"))
        .get_matches()
}

/// Reads stdin and normalizes passphrase
fn subcommand_dispatch(app_m: ArgMatches) {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read passphrase");
    let pass = normalize_passphrase(&input);
    let salt = app_m.value_of("salt").unwrap().to_string();
    let params = Params::from_matches(&app_m);
    run_scrypt(params, &pass, &salt);
}

/// Program entrypoint
fn main() {
    subcommand_dispatch(arg_matches());
}

/// Parameters struct definition
struct Params {
    log_n: u8,
    r: u32,
    p: u32,
    dk_len: usize,
    short: bool,
}

/// Paramaters struct assignments from command line arguments values
impl Params {
    fn from_matches(matches: &ArgMatches) -> Params {
        let log_n = value_t!(matches, "logN", u8).unwrap_or_else(|e| e.exit());
        let r = value_t!(matches, "r", u32).unwrap_or_else(|e| e.exit());
        let p = value_t!(matches, "p", u32).unwrap_or_else(|e| e.exit());
        let dk_len = value_t!(matches, "len", usize).unwrap_or_else(|e| e.exit());
        let short = matches.is_present("short");
        Params {
            log_n,
            r,
            p,
            dk_len,
            short,
        }
    }
}

/// Performs key derivation
fn derive_key(params: &Params, pass: &str, salt: &str) -> Vec<u8> {
    let mut dk = vec![0; params.dk_len];
    let scrypt_params = scrypt::ScryptParams::new(params.log_n, params.r, params.p);
    scrypt::scrypt(pass.as_bytes(), salt.as_bytes(), &scrypt_params, &mut dk);
    dk
}

/// Performs key derivation and outputs result
fn run_scrypt(params: Params, pass: &str, salt: &str) {
    let dk = derive_key(&params, pass, salt);
    if params.short {
        short_output(dk)
    } else {
        full_output(dk, pass, salt, params)
    }
}

/// Minimal output returning the derived key in hexadecimal
fn short_output(dk: Vec<u8>) {
    println!("{}", hex::encode(dk));
}

/// Verbose output for derived key showing input parameters and generated key
fn full_output(dk: Vec<u8>, pass: &str, salt: &str, params: Params) {
    println!("Input | Salt: \"{}\"", &salt);
    println!("Input | Normalized passphrase: \"{}\"", pass);
    println!("Input | Scrypt parameters: cost factor {} - blocksize {} - parallelization {} - key length in bytes {}", params.log_n, params.r, params.p, params.dk_len);
    println!(
        "Output| Scrypt derived key in hexadecimal: {}",
        hex::encode(&dk)
    );
    println!(
        "Output| Scrypt derived key in base64: {}",
        base64::encode(&dk)
    );
    match Mnemonic::from_entropy(&dk) {
        Ok(mnemonic) => println!(
            "Output| Scrypt BIP39 words list representation: {}",
            mnemonic
        ),
        Err(_) => println!("Output| Scrypt BIP39: Unable to generate words list"),
    };
}

// Utils

/// Normalizes passphrase removing leading and trailing spaces
fn normalize_passphrase(input: &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    re.replace_all(input, " ").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_test() {
        let secret = "test secret";
        let passphrase = "test passphrase";
        let params = Params {
            short: true,
            dk_len: 16,
            log_n: 9,
            p: 2,
            r: 8,
        };
        let response = hex::encode(derive_key(&params, secret, passphrase));
        assert_eq!("f9b9450a44c185a5f7ef0ba3f19e2943", response);
    }
}
