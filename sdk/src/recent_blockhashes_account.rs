//! Helpers for the recent blockhashes sysvar.

#[allow(deprecated)]
use solana_program::sysvar::recent_blockhashes::{
    IntoIterSorted, IterItem, RecentBlockhashes, MAX_ENTRIES,
};
use {
    crate::{
        account::{
            create_account_shared_data_with_fields, to_account, AccountSharedData,
            InheritableAccountFields, DUMMY_INHERITABLE_ACCOUNT_FIELDS,
        },
        clock::INITIAL_RENT_EPOCH,
    },
    std::{collections::BinaryHeap, iter::FromIterator},
};

#[deprecated(
    since = "1.9.0",
    note = "Please do not use, will no longer be available in the future"
)]
#[allow(deprecated)]
pub fn update_account<'a, I>(
    account: &mut AccountSharedData,
    recent_blockhash_iter: I,
) -> Option<()>
where
    I: IntoIterator<Item = IterItem<'a>>,
{
    let sorted = BinaryHeap::from_iter(recent_blockhash_iter);
    #[allow(deprecated)]
    let sorted_iter = IntoIterSorted::new(sorted);
    #[allow(deprecated)]
    let recent_blockhash_iter = sorted_iter.take(MAX_ENTRIES);
    #[allow(deprecated)]
    let recent_blockhashes: RecentBlockhashes = recent_blockhash_iter.collect();
    to_account(&recent_blockhashes, account)
}

#[deprecated(
    since = "1.5.17",
    note = "Please use `create_account_with_data_for_test` instead"
)]
#[allow(deprecated)]
pub fn create_account_with_data<'a, I>(lamports: u64, recent_blockhash_iter: I) -> AccountSharedData
where
    I: IntoIterator<Item = IterItem<'a>>,
{
    #[allow(deprecated)]
    create_account_with_data_and_fields(recent_blockhash_iter, (lamports, INITIAL_RENT_EPOCH))
}

#[deprecated(
    since = "1.9.0",
    note = "Please do not use, will no longer be available in the future"
)]
#[allow(deprecated)]
pub fn create_account_with_data_and_fields<'a, I>(
    recent_blockhash_iter: I,
    fields: InheritableAccountFields,
) -> AccountSharedData
where
    I: IntoIterator<Item = IterItem<'a>>,
{
    let mut account = create_account_shared_data_with_fields::<RecentBlockhashes>(
        &RecentBlockhashes::default(),
        fields,
    );
    update_account(&mut account, recent_blockhash_iter).unwrap();
    account
}

#[deprecated(
    since = "1.9.0",
    note = "Please do not use, will no longer be available in the future"
)]
#[allow(deprecated)]
pub fn create_account_with_data_for_test<'a, I>(recent_blockhash_iter: I) -> AccountSharedData
where
    I: IntoIterator<Item = IterItem<'a>>,
{
    create_account_with_data_and_fields(recent_blockhash_iter, DUMMY_INHERITABLE_ACCOUNT_FIELDS)
}
