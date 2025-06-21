pub type Result<T> = core::result::Result<T, Error>;
pub type Error = Box<dyn std::error::Error>; // For early dev.

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{BlindedSigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng(); // rand@0.8

    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&std::fs::read_to_string("./certs/priv_key.pem")?)?;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);

    let public_key =
        RsaPublicKey::from_public_key_pem(&std::fs::read_to_string("./certs/pub_key.pem")?)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    // Sign
    let data = b"hello world";
    let signature = signing_key.sign_with_rng(&mut rng, data);
    assert_ne!(signature.to_bytes().as_ref(), data);

    // Verify
    verifying_key
        .verify(data, &signature)
        .expect("failed to verify");

    Ok(())
}
