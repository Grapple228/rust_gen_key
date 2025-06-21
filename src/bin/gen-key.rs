use clap::{Parser, ValueEnum};
use derive_more::derive::From;
use grapple_utils::b64::b64u_encode;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::PathBuf;
use std::{
    fs,
    io::{self, Write},
};

const DEFAULT_DIR: &str = "./certs";
const HMAC_DEFAULT_KEY_SIZE: usize = 256;
const RSA_DEFAULT_KEY_SIZE: usize = 2048;

/// Simple tool to generate RSA or HMAC keys
#[derive(Parser)]
#[clap(
    author,
    version,
    about = "Generate an RSA or HMAC key and output to files (if --out-dir is set) and/or stdout.",
    after_help = "EXAMPLES:\n\
    \n  Generate a 2048-bit RSA key pair and print to stdout:\n    gen-key --stdout\n\
    \n  Generate a 4096-bit RSA key pair, print to stdout, and save to ./mykeys/:\n    gen-key --alg rsa --key-size 4096 --out-dir ./mykeys --stdout\n\
    \n  Generate a 256-bit HMAC key and print as base64 to stdout:\n    gen-key --alg hmac --stdout\n\
    \n  Save PEM-formatted RSA keys to ./certs/ only:\n    gen-key --alg rsa --out-dir ./certs\n\
    \n  Print DER-formatted RSA keys as base64 to stdout and save to files:\n    gen-key --alg rsa --stdout --out-dir ./certs --format der\n\
    \n  Generate PEM with LF line endings:\n    gen-key --alg rsa --stdout --line-ending lf\n\
    \nNOTES:\n\
    - **RSA private keys are saved in PKCS#8 format (both PEM and DER).**\n\
    - **RSA public keys are saved in X.509 format (both PEM and DER).**\n\
    See https://datatracker.ietf.org/doc/html/rfc5208 for PKCS#8 specification.\n\n\
    See https://tools.ietf.org/html/rfc5280#section-4.1.2.7 for X.509 (SPKI) specification.\n\n\
    - **HMAC keys are saved as raw bytes (or base64url when printed to stdout).**\n\
    - If --stdout is set, keys are printed to the console.\n\
    - If --out-dir is set, keys are written to files in the specified directory.\n\
    - You can use both --stdout and --out-dir to output to both.\n\
    - If neither --stdout nor --out-dir is set, keys are printed to stdout by default.\n\
    - Supported key sizes: RSA (2048 [default], 3072, 4096), HMAC (256 [default], 384, 512).\n\
    - The --line-ending flag controls PEM line endings: 'crlf' [default], cr or 'lf'.\n\
    - Use --replace to allow overwriting existing files in the output directory.\n\
    - Use --prefix to set a custom prefix for output file names (default: 'default').\n"
)]
struct Cli {
    /// Algorithm to generate key for: rsa or hmac
    #[clap(
        long,
        default_value = "rsa",
        help = "Algorithm to generate key for: rsa or hmac"
    )]
    alg: Algorithm,

    /// Output directory for key files (if not set, files are not written)
    #[clap(
        short,
        long,
        value_parser,
        help = "Output directory for key files (if not set, files are not written)"
    )]
    out_dir: Option<PathBuf>,

    /// Print keys to stdout (default if --out-dir is not set)
    #[clap(
        long,
        action,
        help = "Print keys to stdout (default if --out-dir is not set)"
    )]
    stdout: bool,

    /// Output format: pem or der (RSA only, ignored for HMAC; always PKCS#8)
    #[clap(
        short,
        long,
        default_value = "pem",
        help = "Output format: pem or der (RSA only, ignored for HMAC; always PKCS#8)"
    )]
    format: OutputFormat,

    /// Key size in bits (RSA: 2048 [default], 3072, 4096; HMAC: 256 [default], 384, 512)
    #[clap(
        short,
        long,
        value_parser,
        default_value_if("alg", "rsa", "2048"),
        default_value_if("alg", "hmac", "256"),
        help = "Key size in bits (RSA: 2048 [default], 3072, 4096; HMAC: 256 [default], 384, 512)"
    )]
    key_size: Option<usize>,

    /// Line ending for PEM output: crlf [default], cr or lf
    #[clap(
        long,
        value_enum,
        default_value = "cr-lf",
        help = "Line ending for PEM output: cr-lf [default], cr or lf"
    )]
    line_ending: PemLineEnding,

    /// Overwrite existing files in output directory
    #[clap(long, short, help = "Overwrite existing files in output directory")]
    replace: bool,

    /// Prefix for output file names: 'default' or any custom string
    #[clap(
        long,
        short,
        default_value = "default",
        help = "Prefix for output file names: 'default' or any custom string"
    )]
    prefix: String,
}
impl Cli {
    pub fn init_dir(&self) -> io::Result<PathBuf> {
        let out_dir = self
            .out_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR));

        fs::create_dir_all(&out_dir)?;

        Ok(out_dir)
    }
}

// region:    --- Prefix

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Prefix {
    Default,
    Custom(String),
}

impl Prefix {
    pub fn from_str(value: &str) -> Result<Prefix> {
        if value.is_empty() {
            return Err(Error::PrefixEmpty);
        }

        // Sanitize: disallow path separators and other invalid filename chars
        if value.contains('/')
            || value.contains('\\')
            || value.contains("..")
            || value.chars().any(|c| {
                c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|'
            })
        {
            return Err(Error::InvalidFilePrefix);
        }

        if value.eq_ignore_ascii_case("default") {
            Ok(Prefix::Default)
        } else {
            Ok(Prefix::Custom(value.to_string()))
        }
    }

    pub fn to_hmac(&self) -> String {
        match self {
            Prefix::Default => format!("hmac.key"),
            Prefix::Custom(custom) => format!("{}.key", custom),
        }
    }

    /// Generates file names for storing RSA keys.
    ///
    /// # Arguments
    ///
    /// * `extension` - A string representing the file extension.
    ///   Supported extensions: `.pem` and `.der`.
    ///   - If `.pem` is used, then returns (name, name.pub)
    ///   - If `.der` is used, then returns (name.der, name.pub.der)
    ///
    /// # Returns
    ///
    /// Returns a tuple of two strings:
    /// * The file name for the private key.
    /// * The file name for the public key.
    ///
    /// # Examples
    ///
    /// ```
    /// let prefix = Prefix::Default;
    /// let hmac_key_file = prefix.to_hmac();
    /// assert_eq!(hmac_key_file, "hmac.key");
    ///
    /// let (private_key_file, public_key_file) = prefix.to_rsa(".pem");
    /// assert_eq!(private_key_file, "rsa");
    /// assert_eq!(public_key_file, "rsa.pub");
    ///
    /// let (private_key_file, public_key_file) = prefix.to_rsa(".der");
    /// assert_eq!(private_key_file, "rsa.der");
    /// assert_eq!(public_key_file, "rsa.pub.der");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if an unsupported extension is provided.
    pub fn to_rsa(&self, extension: &str) -> Result<(String, String)> {
        let base_name = match self {
            Prefix::Default => "rsa".to_string(),
            Prefix::Custom(custom) => custom.clone(),
        };

        match extension {
            ".pem" => Ok((base_name.clone(), format!("{}.pub", base_name))),
            ".der" => Ok((
                format!("{}.der", base_name),
                format!("{}.pub.der", base_name),
            )),
            other => Err(Error::UnsupportedFileExtension(other.to_string())),
        }
    }
}

// endregion: --- Prefix

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Algorithm {
    Rsa,
    Hmac,
}

// region:    --- Line Ending

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Pem,
    Der,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum PemLineEnding {
    Cr,
    Lf,
    CrLf,
}

// endregion: --- Line Ending

impl PemLineEnding {
    fn to_rsa_line_ending(self) -> rsa::pkcs8::LineEnding {
        match self {
            PemLineEnding::Cr => rsa::pkcs8::LineEnding::CR,
            PemLineEnding::Lf => rsa::pkcs8::LineEnding::LF,
            PemLineEnding::CrLf => rsa::pkcs8::LineEnding::CRLF,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.alg == Algorithm::Hmac && cli.format != OutputFormat::Pem {
        eprintln!("Warning: --format is ignored for HMAC keys.");
    }
    if cli.alg == Algorithm::Hmac && cli.line_ending != PemLineEnding::CrLf {
        eprintln!("Warning: --line-ending is ignored for HMAC keys.");
    }

    let do_file = cli.out_dir.is_some();
    let do_stdout = cli.stdout || !do_file;

    match cli.alg {
        Algorithm::Rsa => {
            match cli.key_size {
                None | Some(2048) | Some(3072) | Some(4096) => (),
                _ => {
                    return Err(Error::InvalidRsaSize);
                }
            }
            generate_rsa(&cli, do_stdout, do_file)?;
        }
        Algorithm::Hmac => {
            match cli.key_size {
                None | Some(256) | Some(384) | Some(512) => (),
                _ => {
                    return Err(Error::InvalidHmacSize);
                }
            }
            generate_hmac(&cli, do_stdout, do_file)?;
        }
    }

    Ok(())
}

fn generate_rsa(cli: &Cli, do_stdout: bool, do_file: bool) -> Result<()> {
    let mut stdout = io::stdout();

    let key_size = cli.key_size.unwrap_or(RSA_DEFAULT_KEY_SIZE);

    writeln!(stdout, "Generating RSA key pair with size {}...", key_size)?;
    stdout.flush()?;

    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, key_size)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    let priv_der = priv_key.to_pkcs8_der()?;
    let pub_der = pub_key.to_public_key_der()?;

    let line_ending = cli.line_ending.to_rsa_line_ending();

    if do_stdout {
        match cli.format {
            OutputFormat::Pem => {
                let priv_pem = priv_der.to_pem("PRIVATE KEY", line_ending)?;
                let pub_pem = pub_der.to_pem("PUBLIC KEY", line_ending)?;
                writeln!(stdout, "{}", priv_pem.as_str())?;
                writeln!(stdout, "{}", pub_pem)?;
            }
            OutputFormat::Der => {
                writeln!(
                    stdout,
                    "Private key (DER, base64):\n{}",
                    b64u_encode(priv_der.as_bytes())
                )?;
                writeln!(
                    stdout,
                    "Public key (DER, base64):\n{}",
                    b64u_encode(pub_der.as_bytes())
                )?;
            }
        }

        stdout.flush()?;
    }

    if do_file {
        let out_dir = cli.init_dir()?;

        writeln!(stdout, "Saving keys to {}", out_dir.display())?;
        stdout.flush()?;

        let (priv_path, pub_path) = match cli.format {
            OutputFormat::Pem => {
                let (private, public) = Prefix::from_str(&cli.prefix)?.to_rsa(".pem")?;

                let priv_path = out_dir.join(private);
                let pub_path = out_dir.join(public);

                if !cli.replace && (priv_path.exists() || pub_path.exists()) {
                    return Err(Error::RsaFileExists);
                }

                priv_der.write_pem_file(&priv_path, "PRIVATE KEY", line_ending)?;
                pub_der.write_pem_file(&pub_path, "PUBLIC KEY", line_ending)?;

                (priv_path, pub_path)
            }
            OutputFormat::Der => {
                let (private, public) = Prefix::from_str(&cli.prefix)?.to_rsa(".der")?;

                let priv_path = out_dir.join(private);
                let pub_path = out_dir.join(public);

                if !cli.replace && (priv_path.exists() || pub_path.exists()) {
                    return Err(Error::RsaFileExists);
                }

                priv_der.write_der_file(&priv_path)?;
                pub_der.write_der_file(&pub_path)?;

                (priv_path, pub_path)
            }
        };

        writeln!(stdout, "RSA private key saved to {}", priv_path.display())?;
        writeln!(stdout, "RSA public key saved to {}", pub_path.display())?;

        stdout.flush()?;
    }

    Ok(())
}

fn generate_hmac(cli: &Cli, do_stdout: bool, do_file: bool) -> Result<()> {
    let key_size = cli.key_size.unwrap_or(HMAC_DEFAULT_KEY_SIZE);
    if key_size % 8 != 0 {
        return Err(Error::HmacSizeMustBeMultipleOf8);
    }

    let key_bytes = key_size / 8;

    let mut stdout = io::stdout();
    writeln!(stdout, "Generating HMAC key with {} bytes...", key_bytes)?;
    stdout.flush()?;

    let mut key = vec![0u8; key_bytes];
    OsRng.fill_bytes(&mut key);

    if do_stdout {
        writeln!(stdout, "HMAC key (base64url):\n{}", b64u_encode(&key))?;
        stdout.flush()?;
    }

    if do_file {
        let out_dir = cli.init_dir()?;
        writeln!(stdout, "Saving key to {}", out_dir.display())?;
        stdout.flush()?;

        let name = Prefix::from_str(&cli.prefix)?.to_hmac();

        let key_path = out_dir.join(name);

        if key_path.exists() && !cli.replace {
            return Err(Error::HmacFileExists);
        }

        fs::write(&key_path, &key)?;
        writeln!(stdout, "HMAC key saved to {}", key_path.display())?;
        stdout.flush()?;
    }
    Ok(())
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    RsaFileExists,
    HmacFileExists,
    InvalidRsaSize,
    InvalidHmacSize,
    PrefixEmpty,
    HmacSizeMustBeMultipleOf8,
    UnsupportedFileExtension(String),
    InvalidFilePrefix,

    #[from]
    Rsa(rsa::Error),
    #[from]
    Pkcs8(rsa::pkcs8::Error),
    #[from]
    Pkcs8spki(rsa::pkcs8::spki::Error),
    #[from]
    Der(rsa::pkcs1::der::Error),

    #[from]
    Io(io::Error),
}

// region:    --- Error Boilerplate

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        let msg = match self {
            Error::UnsupportedFileExtension(extension) => {
                format!("Output file extension {} unsupported", extension)
            }
            Error::InvalidFilePrefix => "Unsupported symbols in file extension".into(),
            Error::HmacSizeMustBeMultipleOf8 => {
                "Error: HMAC key size must be a multiple of 8 (bits).".into()
            }
            Error::PrefixEmpty => "Error: Prefix was empty.".into(),
            Error::RsaFileExists => {
                "Error: One or both output files already exist. Use --replace to overwrite.".into()
            }
            Error::HmacFileExists => {
                "Error: Output file already exists. Use --replace to overwrite.".into()
            }
            Error::InvalidHmacSize => {
                "Invalid HMAC key size. Choose 256 [default], 384 or 512.".into()
            }
            Error::InvalidRsaSize => {
                "Invalid RSA key size. Choose 2048 [default], 3072 or 4096.".into()
            }
            Error::Io(error) => error.to_string(),
            Error::Rsa(error) => error.to_string(),
            Error::Pkcs8(error) => error.to_string(),
            Error::Pkcs8spki(error) => error.to_string(),
            Error::Der(error) => error.to_string(),
        };

        write!(fmt, "{}", msg)
    }
}

impl std::error::Error for Error {}

// endregion: --- Error Boilerplate

// region:    --- Tests

#[cfg(test)]
mod tests {
    pub type Result<T> = core::result::Result<T, Error>;
    pub type Error = Box<dyn std::error::Error>; // For early dev.

    use std::fs::File;

    use assert_cmd::Command;
    use predicates::prelude::*;
    use tempfile::tempdir;

    use crate::Prefix;

    #[test]
    fn test_rsa_key_generation_stdout() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--key-size")
            .arg("2048")
            .arg("--stdout");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(
                "Generating RSA key pair with size 2048",
            ))
            .stdout(predicate::str::contains("PRIVATE KEY"))
            .stdout(predicate::str::contains("PUBLIC KEY"));
    }

    #[test]
    fn test_hmac_key_generation_stdout() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("hmac")
            .arg("--key-size")
            .arg("256")
            .arg("--stdout");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(
                "Generating HMAC key with 32 bytes",
            ))
            .stdout(predicate::str::contains("HMAC key (base64url):"));
    }

    #[test]
    fn test_hmac_key_generation_to_dir() {
        let dir = tempdir().unwrap();
        let out_dir = dir.path().to_str().unwrap();

        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("hmac")
            .arg("--key-size")
            .arg("256")
            .arg("--out-dir")
            .arg(out_dir);

        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Saving key to"));

        let key_name = Prefix::Default.to_hmac();

        let key_file = dir.path().join(key_name);
        assert!(key_file.exists(), "HMAC key file should exist");
    }

    #[test]
    fn test_rsa_key_generation_to_dir() -> Result<()> {
        let dir = tempdir().unwrap();
        let out_dir = dir.path().to_str().unwrap();

        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--key-size")
            .arg("2048")
            .arg("--out-dir")
            .arg(out_dir);

        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Saving keys to"));

        let (private, public) = Prefix::Default.to_rsa(".pem")?;
        let private_path = dir.path().join(private);
        let public_path = dir.path().join(public);

        assert!(private_path.exists(), "Private key file should exist");
        assert!(public_path.exists(), "Public key file should exist");

        Ok(())
    }

    #[test]
    fn test_invalid_rsa_key_size() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--key-size")
            .arg("1234")
            .arg("--stdout");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Invalid RSA key size"));
    }

    #[test]
    fn test_invalid_hmac_key_size() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("hmac")
            .arg("--key-size")
            .arg("123")
            .arg("--stdout");
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("Invalid HMAC key size"));
    }

    #[test]
    fn test_default_behavior_stdout() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg").arg("rsa");
        cmd.assert().success().stdout(predicate::str::contains(
            "Generating RSA key pair with size 2048",
        ));
    }

    #[test]
    fn test_format_der_stdout() {
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--format")
            .arg("der")
            .arg("--stdout");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Private key (DER, base64):"))
            .stdout(predicate::str::contains("Public key (DER, base64):"));
    }

    #[test]
    fn test_replace_flag_error_and_success_rsa() -> Result<()> {
        let dir = tempdir().unwrap();
        let out_dir = dir.path();

        let (priv_key, pub_key) = Prefix::Default.to_rsa(".pem")?;

        // Pre-create files to simulate existing keys
        let priv_key = out_dir.join(priv_key);
        let pub_key = out_dir.join(pub_key);
        let _ = File::create(&priv_key).unwrap();
        let _ = File::create(&pub_key).unwrap();

        // Should fail without --replace
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--out-dir")
            .arg(out_dir)
            .arg("--key-size")
            .arg("2048");
        cmd.assert().failure().stderr(predicate::str::contains(
            "Error: One or both output files already exist. Use --replace to overwrite.",
        ));

        // Should succeed with --replace
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("rsa")
            .arg("--out-dir")
            .arg(out_dir)
            .arg("--key-size")
            .arg("2048")
            .arg("--replace");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("RSA private key saved to"))
            .stdout(predicate::str::contains("RSA public key saved to"));

        Ok(())
    }

    #[test]
    fn test_replace_flag_error_and_success_hmac() {
        let dir = tempdir().unwrap();
        let out_dir = dir.path();

        // Pre-create file to simulate existing key
        let key_file = out_dir.join("hmac.key");
        let _ = File::create(&key_file).unwrap();

        assert!(key_file.exists());

        // Should fail without --replace
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("hmac")
            .arg("--out-dir")
            .arg(out_dir)
            .arg("--key-size")
            .arg("256");
        cmd.assert().failure().stderr(predicate::str::contains(
            "Error: Output file already exists. Use --replace to overwrite.",
        ));

        // Should succeed with --replace
        let mut cmd = Command::cargo_bin("gen-key").unwrap();
        cmd.arg("--alg")
            .arg("hmac")
            .arg("--out-dir")
            .arg(out_dir)
            .arg("--key-size")
            .arg("256")
            .arg("--replace");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("HMAC key saved to"));
    }

    #[test]
    fn test_prefix_to_hmac() {
        // Default prefix
        let prefix = Prefix::Default;
        assert_eq!(prefix.to_hmac(), "hmac.key");

        // Custom prefix
        let prefix = Prefix::Custom("mykey".to_string());
        assert_eq!(prefix.to_hmac(), "mykey.key");
    }

    #[test]
    fn test_prefix_to_rsa_pem() -> Result<()> {
        // Default prefix
        let prefix = Prefix::Default;
        let (priv_file, pub_file) = prefix.to_rsa(".pem")?;
        assert_eq!(priv_file, "rsa");
        assert_eq!(pub_file, "rsa.pub");

        // Custom prefix
        let prefix = Prefix::Custom("mykey".to_string());
        let (priv_file, pub_file) = prefix.to_rsa(".pem")?;
        assert_eq!(priv_file, "mykey");
        assert_eq!(pub_file, "mykey.pub");

        Ok(())
    }

    #[test]
    fn test_prefix_to_rsa_der() -> Result<()> {
        // Default prefix
        let prefix = Prefix::Default;
        let (priv_file, pub_file) = prefix.to_rsa(".der")?;
        assert_eq!(priv_file, "rsa.der");
        assert_eq!(pub_file, "rsa.pub.der");

        // Custom prefix
        let prefix = Prefix::Custom("mykey".to_string());
        let (priv_file, pub_file) = prefix.to_rsa(".der")?;
        assert_eq!(priv_file, "mykey.der");
        assert_eq!(pub_file, "mykey.pub.der");

        Ok(())
    }

    #[test]
    fn test_prefix_to_rsa_invalid_extension() {
        let prefix = Prefix::Default;

        _ = prefix.to_rsa(".txt").is_err();
    }
}

// endregion: --- Tests
