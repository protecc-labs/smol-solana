//! Solana account addresses.

pub use solana_program::pubkey::*;

/// New random Pubkey for tests and benchmarks.
#[cfg(feature = "full")]
pub fn new_rand() -> Pubkey {
    Pubkey::from(rand::random::<[u8; PUBKEY_BYTES]>())
}

#[cfg(feature = "full")]
pub fn write_pubkey_file(outfile: &str, pubkey: Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let printable = format!("{pubkey}");
    let serialized = serde_json::to_string(&printable)?;

    if let Some(outdir) = std::path::Path::new(&outfile).parent() {
        std::fs::create_dir_all(outdir)?;
    }
    let mut f = std::fs::File::create(outfile)?;
    f.write_all(&serialized.into_bytes())?;

    Ok(())
}

#[cfg(feature = "full")]
pub fn read_pubkey_file(infile: &str) -> Result<Pubkey, Box<dyn std::error::Error>> {
    let f = std::fs::File::open(infile)?;
    let printable: String = serde_json::from_reader(f)?;

    use std::str::FromStr;
    Ok(Pubkey::from_str(&printable)?)
}
