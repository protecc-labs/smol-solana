use {
    crate::bank::Bank,
    solana_sdk::transaction::{Result, SanitizedTransaction},
    std::borrow::Cow,
};

// Represents the results of trying to lock a set of accounts
pub struct TransactionBatch<'a, 'b> {
    lock_results: Vec<Result<()>>,
    bank: &'a Bank,
    sanitized_txs: Cow<'b, [SanitizedTransaction]>,
    needs_unlock: bool,
}

impl<'a, 'b> TransactionBatch<'a, 'b> {
    pub fn new(
        lock_results: Vec<Result<()>>,
        bank: &'a Bank,
        sanitized_txs: Cow<'b, [SanitizedTransaction]>,
    ) -> Self {
        assert_eq!(lock_results.len(), sanitized_txs.len());
        Self {
            lock_results,
            bank,
            sanitized_txs,
            needs_unlock: true,
        }
    }

    pub fn lock_results(&self) -> &Vec<Result<()>> {
        &self.lock_results
    }

    pub fn sanitized_transactions(&self) -> &[SanitizedTransaction] {
        &self.sanitized_txs
    }

    pub fn bank(&self) -> &Bank {
        self.bank
    }

    pub fn set_needs_unlock(&mut self, needs_unlock: bool) {
        self.needs_unlock = needs_unlock;
    }

    pub fn needs_unlock(&self) -> bool {
        self.needs_unlock
    }
}

// Unlock all locked accounts in destructor.
impl<'a, 'b> Drop for TransactionBatch<'a, 'b> {
    fn drop(&mut self) {
        self.bank.unlock_accounts(self)
    }
}
