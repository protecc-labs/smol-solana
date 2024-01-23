use {
    super::VersionedTransaction,
    crate::{sanitize::SanitizeError, signature::Signature},
    solana_program::message::SanitizedVersionedMessage,
};

/// Wraps a sanitized `VersionedTransaction` to provide a safe API
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedTransaction {
    /// List of signatures
    pub(crate) signatures: Vec<Signature>,
    /// Message to sign.
    pub(crate) message: SanitizedVersionedMessage,
}

impl TryFrom<VersionedTransaction> for SanitizedVersionedTransaction {
    type Error = SanitizeError;
    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        Self::try_new(tx)
    }
}

impl SanitizedVersionedTransaction {
    pub fn try_new(tx: VersionedTransaction) -> Result<Self, SanitizeError> {
        tx.sanitize_signatures()?;
        Ok(Self {
            signatures: tx.signatures,
            message: SanitizedVersionedMessage::try_from(tx.message)?,
        })
    }

    pub fn get_message(&self) -> &SanitizedVersionedMessage {
        &self.message
    }

    /// Consumes the SanitizedVersionedTransaction, returning the fields individually.
    pub fn destruct(self) -> (Vec<Signature>, SanitizedVersionedMessage) {
        (self.signatures, self.message)
    }
}
