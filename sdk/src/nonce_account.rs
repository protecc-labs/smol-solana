//! Functions related to nonce accounts.

use {
    crate::{
        account::{AccountSharedData, ReadableAccount},
        account_utils::StateMut,
        hash::Hash,
        nonce::{
            state::{Data, Versions},
            State,
        },
    },
    std::cell::RefCell,
};

pub fn create_account(lamports: u64) -> RefCell<AccountSharedData> {
    RefCell::new(
        AccountSharedData::new_data_with_space(
            lamports,
            &Versions::new(State::Uninitialized),
            State::size(),
            &crate::system_program::id(),
        )
        .expect("nonce_account"),
    )
}

/// Checks if the recent_blockhash field in Transaction verifies, and returns
/// nonce account data if so.
pub fn verify_nonce_account(
    account: &AccountSharedData,
    recent_blockhash: &Hash, // Transaction.message.recent_blockhash
) -> Option<Data> {
    (account.owner() == &crate::system_program::id())
        .then(|| {
            StateMut::<Versions>::state(account)
                .ok()?
                .verify_recent_blockhash(recent_blockhash)
                .cloned()
        })
        .flatten()
}

pub fn lamports_per_signature_of(account: &AccountSharedData) -> Option<u64> {
    match StateMut::<Versions>::state(account).ok()?.state() {
        State::Initialized(data) => Some(data.fee_calculator.lamports_per_signature),
        State::Uninitialized => None,
    }
}
