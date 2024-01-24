#![cfg(feature = "full")]

use {
    crate::{
        derivation_path::DerivationPath,
        pubkey::Pubkey,
        signature::Signature,
        signer::{EncodableKey, EncodableKeypair, SeedDerivable, Signer, SignerError},
    },
    digest::crypto_common::rand_core::CryptoRngCore,
    ed25519_dalek::SigningKey,
    ed25519_dalek_bip32::Error as Bip32Error,
    hmac::Hmac,
    rand::rngs::OsRng,
    std::{
        error,
        io::{Read, Write},
        path::Path,
    },
    wasm_bindgen::prelude::*,
};

/// A vanilla Ed25519 key pair
#[wasm_bindgen]
#[derive(Debug)]
pub struct Keypair(SigningKey);

impl Keypair {
    /// Can be used for generating a Keypair without a dependency on `rand` types
    pub const SECRET_KEY_LENGTH: usize = 32;

    /// Constructs a new, random `Keypair` using a caller-provided RNG
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRngCore,
    {
        Self(SigningKey::generate(csprng))
    }

    /// Constructs a new, random `Keypair` using `OsRng`
    pub fn new() -> Self {
        let mut csprng = OsRng;

        Self(SigningKey::generate(&mut csprng))
    }

    /// Recovers a `Keypair` from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        if bytes.len() < ed25519_dalek::KEYPAIR_LENGTH {
            return Err(ed25519_dalek::SignatureError::from_source(String::from(
                "candidate keypair byte array is too short",
            )));
        }

        let bytes = &bytes[..ed25519_dalek::KEYPAIR_LENGTH].try_into().unwrap();

        Ok(Self(SigningKey::from_keypair_bytes(bytes)?))
    }

    /// Recovers a `Keypair` from a base58-encoded string
    pub fn from_base58_string(s: &str) -> Self {
        Self::from_bytes(&bs58::decode(s).into_vec().unwrap()).unwrap()
    }

    /// Returns this `Keypair` as a base58-encoded string
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.0.to_bytes()).into_string()
    }

    /// Gets this `Keypair`'s SecretKey
    pub fn secret(&self) -> &ed25519_dalek::SecretKey {
        self.0.as_bytes()
    }

    /// Allows Keypair cloning
    ///
    /// Note that the `Clone` trait is intentionally unimplemented because making a
    /// second copy of sensitive secret keys in memory is usually a bad idea.
    ///
    /// Only use this in tests or when strictly required. Consider using [`std::sync::Arc<Keypair>`]
    /// instead.
    pub fn insecure_clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Signer for Keypair {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        Pubkey::from(*self.0.verifying_key().as_bytes())
    }

    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey())
    }

    fn sign_message(&self, message: &[u8]) -> Signature {
        Signer::sign_message(&self, message)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.sign_message(message))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl<T> PartialEq<T> for Keypair
where
    T: Signer,
{
    fn eq(&self, other: &T) -> bool {
        self.pubkey() == other.pubkey()
    }
}

impl EncodableKey for Keypair {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Box<dyn error::Error>> {
        read_keypair(reader)
    }

    fn write<W: Write>(&self, writer: &mut W) -> Result<String, Box<dyn error::Error>> {
        write_keypair(self, writer)
    }
}

impl SeedDerivable for Keypair {
    fn from_seed(seed: &[u8]) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed(seed)
    }

    fn from_seed_and_derivation_path(
        seed: &[u8],
        derivation_path: Option<DerivationPath>,
    ) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed_and_derivation_path(seed, derivation_path)
    }

    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>> {
        keypair_from_seed_phrase_and_passphrase(seed_phrase, passphrase)
    }
}

impl EncodableKeypair for Keypair {
    type Pubkey = Pubkey;

    /// Returns the associated pubkey. Use this function specifically for settings that involve
    /// reading or writing pubkeys. For other settings, use `Signer::pubkey()` instead.
    fn encodable_pubkey(&self) -> Self::Pubkey {
        self.pubkey()
    }
}

/// Reads a JSON-encoded `Keypair` from a `Reader` implementor
pub fn read_keypair<R: Read>(reader: &mut R) -> Result<Keypair, Box<dyn error::Error>> {
    let bytes: Vec<u8> = serde_json::from_reader(reader)?;
    Keypair::from_bytes(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()).into())
}

/// Reads a `Keypair` from a file
pub fn read_keypair_file<F: AsRef<Path>>(path: F) -> Result<Keypair, Box<dyn error::Error>> {
    Keypair::read_from_file(path)
}

/// Writes a `Keypair` to a `Write` implementor with JSON-encoding
pub fn write_keypair<W: Write>(
    keypair: &Keypair,
    writer: &mut W,
) -> Result<String, Box<dyn error::Error>> {
    let keypair_bytes = keypair.0.to_bytes();
    let serialized = serde_json::to_string(&keypair_bytes.to_vec())?;
    writer.write_all(serialized.as_bytes())?;
    Ok(serialized)
}

/// Writes a `Keypair` to a file with JSON-encoding
pub fn write_keypair_file<F: AsRef<Path>>(
    keypair: &Keypair,
    outfile: F,
) -> Result<String, Box<dyn error::Error>> {
    keypair.write_to_file(outfile)
}

/// Constructs a `Keypair` from caller-provided seed entropy
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair, Box<dyn error::Error>> {
    if seed.len() < ed25519_dalek::SECRET_KEY_LENGTH {
        return Err("Seed is too short".into());
    }

    Keypair::from_seed(seed)
}

/// Generates a Keypair using Bip32 Hierarchical Derivation if derivation-path is provided;
/// otherwise generates the base Bip44 Solana keypair from the seed
pub fn keypair_from_seed_and_derivation_path(
    seed: &[u8],
    derivation_path: Option<DerivationPath>,
) -> Result<Keypair, Box<dyn error::Error>> {
    let derivation_path = derivation_path.unwrap_or_default();
    bip32_derived_keypair(seed, derivation_path).map_err(|err| err.to_string().into())
}

/// Generates a Keypair using Bip32 Hierarchical Derivation
fn bip32_derived_keypair(
    seed: &[u8],
    derivation_path: DerivationPath,
) -> Result<Keypair, Bip32Error> {
    let extended = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(seed)
        .and_then(|extended| extended.derive(&derivation_path))?;
    let secret_key = extended.signing_key;

    Ok(Keypair(secret_key))
}

pub fn generate_seed_from_seed_phrase_and_passphrase(
    seed_phrase: &str,
    passphrase: &str,
) -> Vec<u8> {
    const PBKDF2_ROUNDS: u32 = 2048;
    const PBKDF2_BYTES: usize = 64;

    let salt = format!("mnemonic{passphrase}");

    let mut seed = vec![0u8; PBKDF2_BYTES];
    pbkdf2::pbkdf2::<Hmac<sha2::Sha512>>(
        seed_phrase.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ROUNDS,
        &mut seed,
    );
    seed
}

pub fn keypair_from_seed_phrase_and_passphrase(
    seed_phrase: &str,
    passphrase: &str,
) -> Result<Keypair, Box<dyn error::Error>> {
    keypair_from_seed(&generate_seed_from_seed_phrase_and_passphrase(
        seed_phrase,
        passphrase,
    ))
}
