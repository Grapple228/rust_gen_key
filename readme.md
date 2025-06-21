# Key Generation Tool

This is a simple command-line tool for generating RSA and HMAC keys. The generated keys can be output to the console or saved to files in a specified directory.

## Important

> ⚠️ **Security Notice:**  
> This tool uses the `rsa` crate, which is affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071).  
> **Do not use this tool for generating production or long-term RSA keys until the issue is resolved.**  
> For production, use OpenSSL or another well-audited cryptography library.

## Features

- Generate RSA key pairs (private and public keys).
- Generate HMAC keys.
- Output keys in PEM or DER format (for RSA only).
- Save keys to a specified directory or print them to stdout.

## Installation

To build and run the tool, ensure you have Rust and Cargo installed. Clone the repository and run:

### From source

```bash
cargo install --git https://github.com/grapple228/rust_gen_key.git
```

### From crates.io

```bash
cargo install gen-key
```

## Key formats

RSA private keys are saved in [**PKCS#8**](https://datatracker.ietf.org/doc/html/rfc5208) format (both PEM and DER), public keys are saved in [**X.509 (SPKI)**](https://tools.ietf.org/html/rfc5280#section-4.1.2.7) format.
HMAC keys are saved as raw bytes (or base64url when printed to stdout).

## Usage

The tool can be run with various command-line options. Below are some examples of how to use it:

### Display help message

```bash
gen-key --help
```

### Generate RSA Key Pair

To generate a 2048-bit RSA key pair and print to stdout:

```bash
gen-key --stdout
```

To generate a 4096-bit RSA key pair, print to stdout, and save to `./mykeys/`:

```bash
gen-key --alg rsa -k 4096 -o ./mykeys --stdout
```

### Generate HMAC Key

To generate a 512-bit HMAC key and print as base64 to stdout:

```bash
gen-key --alg hmac -k 512
```

### Save key to directory as files

To save PEM-formatted RSA keys to `./certs/` only:

```bash
gen-key --alg rsa -o ./certs
```

To print DER-formatted RSA keys as base64 to stdout and save to `./certs/`:

```bash
gen-key --alg rsa --stdout -o ./certs -f der
```

To print with custom name:

```bash
gen-key --alg rsa --stdout -o ./certs -f der -p custom
```

## Command-Line Options

| Short | Long            | Description                           | Values / Notes                                                                                              |
| ----- | --------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
|       | `--alg`         | Specify the algorithm                 | `rsa [default]`, `hmac`                                                                                     |
| `-k`  | `--key-size`    | Specify the key size in bits          | RSA: `2048 [default]`, `3072`, `4096`<br>HMAC: `256 [default]`, `384`, `512`                                |
| `-o`  | `--out-dir`     | Output directory for saving keys      | Path to directory. If set and `--stdout` is not, then it will only save files                               |
| `-p`  | `--prefix`      | Keys will be created with prefix      | Could be as `default [default]` or non-empty string.<br>RSA:`rsa.pub` and `rsa.pub.der`<br>HMAC: `hmac.key` |
|       | `--stdout`      | Print generated key(s) to stdout      | No value needed. Enables printing keys to stdout                                                            |
| `-f`  | `--format`      | Output format for RSA keys            | `pem [default]`, `der`                                                                                      |
|       | `--line-ending` | Set line ending for `.pem` files      | `crlf [default]`, `cr`, `lf`                                                                                |
| `-r`  | `--replace`     | Replace file if exists in `--out-dir` | `false` by default and will throw an error if file exists                                                   |
| `-h`  | `--help`        | Show help message                     |                                                                                                             |

## Notes

If both `--stdout` and `--out-dir` are set, keys will be output to both locations  
If `--stdout` is not set and `--out-dir` is not set, keys will be printed into **stdout** by default

## Example output

When generating keys, the tool will provide feedback in the console, indicating the status of key generation and where the keys are saved.

RSA (to console):

```bash
$ gen-key
Generating RSA key pair with size 2048...
-----BEGIN PRIVATE KEY-----
... KEY HERE ...
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
... KEY HERE ...
-----END PUBLIC KEY-----
```

HMAC (to console):

```bash
$ gen-key --alg hmac
Generating HMAC key with 32 bytes...
HMAC key (base64url):
XFMH-E2lXaBHC0_7ZyiqHiAM1kfQ7aGqTnCSnrU-pPc
```

RSA (to file):

```bash
$ gen-key -o ./certs/
Generating RSA key pair with size 2048...
Saving keys to ./certs/
RSA private key saved to ./certs/rsa
RSA public key saved to ./certs/rsa.pub
```

HMAC (to file):

```bash
$ gen-key -o ./certs/ --alg hmac
Generating HMAC key with 32 bytes...
Saving key to ./certs/
HMAC key saved to ./certs/hmac.key
```

## Contributing

`Contributions` are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request. I wrote this tool for my own use, so it may not fit everyone's needs, but your input is appreciated!

## Future plans

- Add support for generating ECC keys

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
