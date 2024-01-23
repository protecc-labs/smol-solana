//! Defines a transaction which supports multiple versions of messages.

#![cfg(feature = "full")]

use {
    crate::{
        hash::Hash,
        message::VersionedMessage,
        sanitize::SanitizeError,
        short_vec,
        signature::Signature,
        signer::SignerError,
        signers::Signers,
        transaction::{Result, Transaction, TransactionError},
    },
    serde::Serialize,
    std::cmp::Ordering,
};

mod sanitized;

pub use sanitized::*;
use {
    crate::program_utils::limited_deserialize,
    solana_program::{
        nonce::NONCED_TX_MARKER_IX_INDEX, system_instruction::SystemInstruction, system_program,
    },
};

/// Type that serializes to the string "legacy"
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Legacy {
    Legacy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum TransactionVersion {
    Legacy(Legacy),
    Number(u8),
}

impl TransactionVersion {
    pub const LEGACY: Self = Self::Legacy(Legacy::Legacy);
}

// NOTE: Serialization-related changes must be paired with the direct read at sigverify.
/// An atomic transaction
#[derive(Debug, PartialEq, Default, Eq, Clone, Serialize, Deserialize, AbiExample)]
pub struct VersionedTransaction {
    /// List of signatures
    #[serde(with = "short_vec")]
    pub signatures: Vec<Signature>,
    /// Message to sign.
    pub message: VersionedMessage,
}

impl From<Transaction> for VersionedTransaction {
    fn from(transaction: Transaction) -> Self {
        Self {
            signatures: transaction.signatures,
            message: VersionedMessage::Legacy(transaction.message),
        }
    }
}

impl VersionedTransaction {
    /// Signs a versioned message and if successful, returns a signed
    /// transaction.
    pub fn try_new<T: Signers + ?Sized>(
        message: VersionedMessage,
        keypairs: &T,
    ) -> std::result::Result<Self, SignerError> {
        let static_account_keys = message.static_account_keys();
        if static_account_keys.len() < message.header().num_required_signatures as usize {
            return Err(SignerError::InvalidInput("invalid message".to_string()));
        }

        let signer_keys = keypairs.try_pubkeys()?;
        let expected_signer_keys =
            &static_account_keys[0..message.header().num_required_signatures as usize];

        match signer_keys.len().cmp(&expected_signer_keys.len()) {
            Ordering::Greater => Err(SignerError::TooManySigners),
            Ordering::Less => Err(SignerError::NotEnoughSigners),
            Ordering::Equal => Ok(()),
        }?;

        let message_data = message.serialize();
        let signature_indexes: Vec<usize> = expected_signer_keys
            .iter()
            .map(|signer_key| {
                signer_keys
                    .iter()
                    .position(|key| key == signer_key)
                    .ok_or(SignerError::KeypairPubkeyMismatch)
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        let unordered_signatures = keypairs.try_sign_message(&message_data)?;
        let signatures: Vec<Signature> = signature_indexes
            .into_iter()
            .map(|index| {
                unordered_signatures
                    .get(index)
                    .copied()
                    .ok_or_else(|| SignerError::InvalidInput("invalid keypairs".to_string()))
            })
            .collect::<std::result::Result<_, SignerError>>()?;

        Ok(Self {
            signatures,
            message,
        })
    }

    pub fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        self.message.sanitize()?;
        self.sanitize_signatures()?;
        Ok(())
    }

    pub(crate) fn sanitize_signatures(&self) -> std::result::Result<(), SanitizeError> {
        let num_required_signatures = usize::from(self.message.header().num_required_signatures);
        match num_required_signatures.cmp(&self.signatures.len()) {
            Ordering::Greater => Err(SanitizeError::IndexOutOfBounds),
            Ordering::Less => Err(SanitizeError::InvalidValue),
            Ordering::Equal => Ok(()),
        }?;

        // Signatures are verified before message keys are loaded so all signers
        // must correspond to static account keys.
        if self.signatures.len() > self.message.static_account_keys().len() {
            return Err(SanitizeError::IndexOutOfBounds);
        }

        Ok(())
    }

    /// Returns the version of the transaction
    pub fn version(&self) -> TransactionVersion {
        match self.message {
            VersionedMessage::Legacy(_) => TransactionVersion::LEGACY,
            VersionedMessage::V0(_) => TransactionVersion::Number(0),
        }
    }

    /// Returns a legacy transaction if the transaction message is legacy.
    pub fn into_legacy_transaction(self) -> Option<Transaction> {
        match self.message {
            VersionedMessage::Legacy(message) => Some(Transaction {
                signatures: self.signatures,
                message,
            }),
            _ => None,
        }
    }

    /// Verify the transaction and hash its message
    pub fn verify_and_hash_message(&self) -> Result<Hash> {
        let message_bytes = self.message.serialize();
        if !self
            ._verify_with_results(&message_bytes)
            .iter()
            .all(|verify_result| *verify_result)
        {
            Err(TransactionError::SignatureFailure)
        } else {
            Ok(VersionedMessage::hash_raw_message(&message_bytes))
        }
    }

    /// Verify the transaction and return a list of verification results
    pub fn verify_with_results(&self) -> Vec<bool> {
        let message_bytes = self.message.serialize();
        self._verify_with_results(&message_bytes)
    }

    fn _verify_with_results(&self, message_bytes: &[u8]) -> Vec<bool> {
        self.signatures
            .iter()
            .zip(self.message.static_account_keys().iter())
            .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), message_bytes))
            .collect()
    }

    /// Returns true if transaction begins with a valid advance nonce
    /// instruction. Since dynamically loaded addresses can't have write locks
    /// demoted without loading addresses, this shouldn't be used in the
    /// runtime.
    pub fn uses_durable_nonce(&self) -> bool {
        let message = &self.message;
        message
            .instructions()
            .get(NONCED_TX_MARKER_IX_INDEX as usize)
            .filter(|instruction| {
                // Is system program
                matches!(
                    message.static_account_keys().get(instruction.program_id_index as usize),
                    Some(program_id) if system_program::check_id(program_id)
                )
                // Is a nonce advance instruction
                && matches!(
                    limited_deserialize(&instruction.data),
                    Ok(SystemInstruction::AdvanceNonceAccount)
                )
                // Nonce account is writable
                && matches!(
                    instruction.accounts.first(),
                    Some(index) if message.is_maybe_writable(*index as usize)
                )
            })
            .is_some()
    }
}
