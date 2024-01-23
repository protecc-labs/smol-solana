#[cfg(not(target_os = "solana"))]
use crate::{
    encryption::elgamal::{ElGamalCiphertext, ElGamalSecretKey},
    zk_token_elgamal::pod,
};

#[cfg(not(target_os = "solana"))]
impl pod::ElGamalCiphertext {
    pub fn decrypt(self, secret_key: &ElGamalSecretKey) -> Option<u64> {
        let deserialized_ciphertext: Option<ElGamalCiphertext> = self.try_into().ok();
        if let Some(ciphertext) = deserialized_ciphertext {
            ciphertext.decrypt_u32(secret_key)
        } else {
            None
        }
    }
}
