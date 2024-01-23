//! trait for abstracting underlying storage of pubkey and account pairs to be written
use {
    crate::{account_storage::meta::StoredAccountMeta, accounts_hash::AccountHash},
    solana_sdk::{account::ReadableAccount, clock::Slot, pubkey::Pubkey},
};

/// abstract access to pubkey, account, slot, target_slot of either:
/// a. (slot, &[&Pubkey, &ReadableAccount])
/// b. (slot, &[&Pubkey, &ReadableAccount, Slot]) (we will use this later)
/// This trait avoids having to allocate redundant data when there is a duplicated slot parameter.
/// All legacy callers do not have a unique slot per account to store.
pub trait StorableAccounts<'a, T: ReadableAccount + Sync>: Sync {
    /// pubkey at 'index'
    fn pubkey(&self, index: usize) -> &Pubkey;
    /// account at 'index'
    fn account(&self, index: usize) -> &T;
    /// None if account is zero lamports
    fn account_default_if_zero_lamport(&self, index: usize) -> Option<&T> {
        let account = self.account(index);
        (account.lamports() != 0).then_some(account)
    }
    // current slot for account at 'index'
    fn slot(&self, index: usize) -> Slot;
    /// slot that all accounts are to be written to
    fn target_slot(&self) -> Slot;
    /// true if no accounts to write
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// # accounts to write
    fn len(&self) -> usize;
    /// are there accounts from multiple slots
    /// only used for an assert
    fn contains_multiple_slots(&self) -> bool {
        false
    }

    /// true iff the impl can provide hash and write_version
    /// Otherwise, hash and write_version have to be provided separately to store functions.
    fn has_hash_and_write_version(&self) -> bool {
        false
    }

    /// return hash for account at 'index'
    /// Should only be called if 'has_hash_and_write_version' = true
    fn hash(&self, _index: usize) -> &AccountHash {
        // this should never be called if has_hash_and_write_version returns false
        unimplemented!();
    }

    /// return write_version for account at 'index'
    /// Should only be called if 'has_hash_and_write_version' = true
    fn write_version(&self, _index: usize) -> u64 {
        // this should never be called if has_hash_and_write_version returns false
        unimplemented!();
    }
}

/// accounts that are moving from 'old_slot' to 'target_slot'
/// since all accounts are from the same old slot, we don't need to create a slice with per-account slot
/// but, we need slot(_) to return 'old_slot' for all accounts
/// Created a struct instead of a tuple to make the code easier to read.
pub struct StorableAccountsMovingSlots<'a, T: ReadableAccount + Sync> {
    pub accounts: &'a [(&'a Pubkey, &'a T)],
    /// accounts will be written to this slot
    pub target_slot: Slot,
    /// slot where accounts are currently stored
    pub old_slot: Slot,
}

impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T> for StorableAccountsMovingSlots<'a, T> {
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.accounts[index].0
    }
    fn account(&self, index: usize) -> &T {
        self.accounts[index].1
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot, but it is different than 'target_slot'
        self.old_slot
    }
    fn target_slot(&self) -> Slot {
        self.target_slot
    }
    fn len(&self) -> usize {
        self.accounts.len()
    }
}

impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T> for (Slot, &'a [(&'a Pubkey, &'a T)]) {
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.1[index].0
    }
    fn account(&self, index: usize) -> &T {
        self.1[index].1
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot when per-account slot is not included in the source data
        self.target_slot()
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
}

impl<'a, T: ReadableAccount + Sync> StorableAccounts<'a, T> for (Slot, &'a [&'a (Pubkey, T)]) {
    fn pubkey(&self, index: usize) -> &Pubkey {
        &self.1[index].0
    }
    fn account(&self, index: usize) -> &T {
        &self.1[index].1
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot when per-account slot is not included in the source data
        self.target_slot()
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
}

impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>> for (Slot, &'a [&'a StoredAccountMeta<'a>]) {
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.account(index).pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        self.1[index]
    }
    fn slot(&self, _index: usize) -> Slot {
        // per-index slot is not unique per slot when per-account slot is not included in the source data
        self.0
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn has_hash_and_write_version(&self) -> bool {
        true
    }
    fn hash(&self, index: usize) -> &AccountHash {
        self.account(index).hash()
    }
    fn write_version(&self, index: usize) -> u64 {
        self.account(index).write_version()
    }
}

/// holds slices of accounts being moved FROM a common source slot to 'target_slot'
pub struct StorableAccountsBySlot<'a> {
    target_slot: Slot,
    /// each element is (source slot, accounts moving FROM source slot)
    slots_and_accounts: &'a [(Slot, &'a [&'a StoredAccountMeta<'a>])],

    /// This is calculated based off slots_and_accounts.
    /// cumulative offset of all account slices prior to this one
    /// starting_offsets[0] is the starting offset of slots_and_accounts[1]
    /// The starting offset of slots_and_accounts[0] is always 0
    starting_offsets: Vec<usize>,
    /// true if there is more than 1 slot represented in slots_and_accounts
    contains_multiple_slots: bool,
    /// total len of all accounts, across all slots_and_accounts
    len: usize,
}

impl<'a> StorableAccountsBySlot<'a> {
    /// each element of slots_and_accounts is (source slot, accounts moving FROM source slot)
    pub fn new(
        target_slot: Slot,
        slots_and_accounts: &'a [(Slot, &'a [&'a StoredAccountMeta<'a>])],
    ) -> Self {
        let mut cumulative_len = 0usize;
        let mut starting_offsets = Vec::with_capacity(slots_and_accounts.len());
        let first_slot = slots_and_accounts
            .first()
            .map(|(slot, _)| *slot)
            .unwrap_or_default();
        let mut contains_multiple_slots = false;
        for (slot, accounts) in slots_and_accounts {
            cumulative_len = cumulative_len.saturating_add(accounts.len());
            starting_offsets.push(cumulative_len);
            contains_multiple_slots |= &first_slot != slot;
        }
        Self {
            target_slot,
            slots_and_accounts,
            starting_offsets,
            contains_multiple_slots,
            len: cumulative_len,
        }
    }
    /// given an overall index for all accounts in self:
    /// return (slots_and_accounts index, index within those accounts)
    fn find_internal_index(&self, index: usize) -> (usize, usize) {
        // search offsets for the accounts slice that contains 'index'.
        // This could be a binary search.
        for (offset_index, next_offset) in self.starting_offsets.iter().enumerate() {
            if next_offset > &index {
                // offset of prior entry
                let prior_offset = if offset_index > 0 {
                    self.starting_offsets[offset_index.saturating_sub(1)]
                } else {
                    0
                };
                return (offset_index, index - prior_offset);
            }
        }
        panic!("failed");
    }
}

impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>> for StorableAccountsBySlot<'a> {
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.account(index).pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        let indexes = self.find_internal_index(index);
        self.slots_and_accounts[indexes.0].1[indexes.1]
    }
    fn slot(&self, index: usize) -> Slot {
        let indexes = self.find_internal_index(index);
        self.slots_and_accounts[indexes.0].0
    }
    fn target_slot(&self) -> Slot {
        self.target_slot
    }
    fn len(&self) -> usize {
        self.len
    }
    fn contains_multiple_slots(&self) -> bool {
        self.contains_multiple_slots
    }
    fn has_hash_and_write_version(&self) -> bool {
        true
    }
    fn hash(&self, index: usize) -> &AccountHash {
        self.account(index).hash()
    }
    fn write_version(&self, index: usize) -> u64 {
        self.account(index).write_version()
    }
}

/// this tuple contains a single different source slot that applies to all accounts
/// accounts are StoredAccountMeta
impl<'a> StorableAccounts<'a, StoredAccountMeta<'a>>
    for (Slot, &'a [&'a StoredAccountMeta<'a>], Slot)
{
    fn pubkey(&self, index: usize) -> &Pubkey {
        self.account(index).pubkey()
    }
    fn account(&self, index: usize) -> &StoredAccountMeta<'a> {
        self.1[index]
    }
    fn slot(&self, _index: usize) -> Slot {
        // same other slot for all accounts
        self.2
    }
    fn target_slot(&self) -> Slot {
        self.0
    }
    fn len(&self) -> usize {
        self.1.len()
    }
    fn has_hash_and_write_version(&self) -> bool {
        true
    }
    fn hash(&self, index: usize) -> &AccountHash {
        self.account(index).hash()
    }
    fn write_version(&self, index: usize) -> u64 {
        self.account(index).write_version()
    }
}
