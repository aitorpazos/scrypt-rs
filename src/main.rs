extern crate base64;
extern crate crypto;
extern crate regex;
extern crate bip39;

#[macro_use]
extern crate clap;

use bip39::{Mnemonic, Language};
use clap::{Arg, App, ArgMatches};
use crypto::scrypt;
use regex::Regex;
use std::io;

fn arg_matches<'a>() -> ArgMatches<'a> {
    App::new("scrypt-rs")
        .about("Read passphrase (first line from stdin), normalize it (drop extra whitespace) and pass it to scrypt")
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

fn subcommand_dispatch(app_m: ArgMatches) {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read passphrase");
    let pass = normalize_passphrase(&input);
    let salt = app_m.value_of("salt").unwrap().to_string();
    println!("Salt: \"{}\"", &salt);
    println!("Normalized passphrase: \"{}\"", pass);
    run_scrypt(&app_m, &pass, &salt);
}

fn main() {
    subcommand_dispatch(arg_matches());
}

struct Params {
    log_n : u8,
    r : u32,
    p : u32,
    dk_len : usize,
}

impl Params {
    fn from_matches(matches : &ArgMatches) -> Params {
        let log_n = value_t!(matches, "logN", u8).unwrap_or_else(|e| e.exit());
        let r = value_t!(matches, "r", u32).unwrap_or_else(|e| e.exit());
        let p = value_t!(matches, "p", u32).unwrap_or_else(|e| e.exit());
        let dk_len = value_t!(matches, "len", usize).unwrap_or_else(|e| e.exit());
        Params { log_n : log_n, r : r, p : p, dk_len: dk_len }
    }
}

fn derive_key(params : Params, pass : &str, salt: &str) -> Vec<u8> {
    let mut dk = vec![0; params.dk_len];
    let scrypt_params = scrypt::ScryptParams::new(params.log_n, params.r, params.p);
    scrypt::scrypt(pass.as_bytes(), salt.as_bytes(), &scrypt_params, &mut dk);
    dk
}

fn run_scrypt(app_m: &ArgMatches, pass: &str, salt: &str) {
    let params = Params::from_matches(app_m);
    let dk = derive_key(params, pass, salt);
    print_hex("Scrypt: ", &dk);
    let mnemonic = Mnemonic::from_entropy(&dk, Language::English).unwrap();
    println!("BIP39: {}", mnemonic.phrase());
    println!("base64: {}", base64::encode(&dk));
}

// Utils

fn normalize_passphrase(input : &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    re.replace_all(input, " ").trim().to_owned()
}

fn print_hex(prefix: &str, bytes: &[u8]) {
    print!("{}", prefix);
    for b in bytes.iter() {
        print!("{:x}", b);
    }
    println!("");
}
