# scrypt-rs

Minimal command-line tool for [scrypt](https://en.wikipedia.org/wiki/Scrypt) key derivation (RFC 7914).

Reads a passphrase from stdin, normalizes whitespace, derives a key using scrypt, and outputs the result in hex, base64, and/or [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic format.

Credit to [w3rs/kdftool](https://github.com/w3rs/kdftool) which this tool is originally based on.

## Installation

### From source

```shell
cargo install --path .
```

### From releases

Download a pre-built binary from the [Releases](https://github.com/aitorpazos/scrypt-rs/releases) page.

## Usage

```shell
echo "my passphrase" | scrypt-rs [OPTIONS]
```

### Options

| Flag | Long | Default | Description |
|------|------|---------|-------------|
| `-S` | `--short` | | Output only the hex-encoded derived key |
| `-s` | `--salt` | `""` | Salt string |
| `-L` | `--logn` | `19` | log₂(N) — CPU/memory cost parameter |
| `-r` | | `8` | Block size parameter |
| `-p` | | `2` | Parallelization parameter |
| `-l` | `--len` | `16` | Derived key length in bytes |

### Examples

Short output (hex only):

```shell
echo "my secret passphrase" | scrypt-rs -S -s "my salt" -L 14 -r 8 -p 1 -l 32
```

Full output (shows all input parameters + hex, base64, and BIP39):

```shell
echo "my secret passphrase" | scrypt-rs -s "my salt" -L 14 -r 8 -p 1 -l 32
```

Example full output:

```
Input | Salt: "my salt"
Input | Normalized passphrase: "my secret passphrase"
Input | Scrypt parameters: cost factor 14 - blocksize 8 - parallelization 1 - key length in bytes 32
Output| Scrypt derived key in hexadecimal: <hex>
Output| Scrypt derived key in base64: <base64>
Output| Scrypt BIP39 words list representation: <24 words>
```

### BIP39 output

BIP39 mnemonic generation requires the derived key length to be one of: **16, 20, 24, 28, or 32 bytes**. Other lengths will show "Unable to generate words list".

## Building

```shell
cargo build --release
```

### Development

```shell
cargo fmt       # format code
cargo clippy    # lint
cargo test      # run all tests
```

## License

[GPL-3.0](LICENSE)
