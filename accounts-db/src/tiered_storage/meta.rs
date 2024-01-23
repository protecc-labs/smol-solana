//! The account meta and related structs for the tiered storage.

use {
    crate::{accounts_hash::AccountHash, tiered_storage::owners::OwnerOffset},
    bytemuck::{Pod, Zeroable},
    modular_bitfield::prelude::*,
    solana_sdk::stake_history::Epoch,
};

/// The struct that handles the account meta flags.
#[bitfield(bits = 32)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Pod, Zeroable)]
pub struct AccountMetaFlags {
    /// whether the account meta has rent epoch
    pub has_rent_epoch: bool,
    /// whether the account meta has account hash
    pub has_account_hash: bool,
    /// whether the account is executable
    pub executable: bool,
    /// the reserved bits.
    reserved: B29,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<AccountMetaFlags>() == 4);

/// A trait that allows different implementations of the account meta that
/// support different tiers of the accounts storage.
pub trait TieredAccountMeta: Sized {
    /// Constructs a TieredAcountMeta instance.
    fn new() -> Self;

    /// A builder function that initializes lamports.
    fn with_lamports(self, lamports: u64) -> Self;

    /// A builder function that initializes the number of padding bytes
    /// for the account data associated with the current meta.
    fn with_account_data_padding(self, padding: u8) -> Self;

    /// A builder function that initializes the owner offset.
    fn with_owner_offset(self, owner_offset: OwnerOffset) -> Self;

    /// A builder function that initializes the account data size.
    /// The size here represents the logical data size without compression.
    fn with_account_data_size(self, account_data_size: u64) -> Self;

    /// A builder function that initializes the AccountMetaFlags of the current
    /// meta.
    fn with_flags(self, flags: &AccountMetaFlags) -> Self;

    /// Returns the balance of the lamports associated with the account.
    fn lamports(&self) -> u64;

    /// Returns the number of padding bytes for the associated account data
    fn account_data_padding(&self) -> u8;

    /// Returns the offset to the accounts' owner in the current AccountsFile.
    fn owner_offset(&self) -> OwnerOffset;

    /// Returns the AccountMetaFlags of the current meta.
    fn flags(&self) -> &AccountMetaFlags;

    /// Returns true if the TieredAccountMeta implementation supports multiple
    /// accounts sharing one account block.
    fn supports_shared_account_block() -> bool;

    /// Returns the epoch that this account will next owe rent by parsing
    /// the specified account block.  None will be returned if this account
    /// does not persist this optional field.
    fn rent_epoch(&self, _account_block: &[u8]) -> Option<Epoch>;

    /// Returns the account hash by parsing the specified account block.  None
    /// will be returned if this account does not persist this optional field.
    fn account_hash<'a>(&self, _account_block: &'a [u8]) -> Option<&'a AccountHash>;

    /// Returns the offset of the optional fields based on the specified account
    /// block.
    fn optional_fields_offset(&self, _account_block: &[u8]) -> usize;

    /// Returns the length of the data associated to this account based on the
    /// specified account block.
    fn account_data_size(&self, _account_block: &[u8]) -> usize;

    /// Returns the data associated to this account based on the specified
    /// account block.
    fn account_data<'a>(&self, _account_block: &'a [u8]) -> &'a [u8];
}

impl AccountMetaFlags {
    pub fn new_from(optional_fields: &AccountMetaOptionalFields) -> Self {
        let mut flags = AccountMetaFlags::default();
        flags.set_has_rent_epoch(optional_fields.rent_epoch.is_some());
        flags.set_has_account_hash(optional_fields.account_hash.is_some());
        flags.set_executable(false);
        flags
    }
}

/// The in-memory struct for the optional fields for tiered account meta.
///
/// Note that the storage representation of the optional fields might be
/// different from its in-memory representation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountMetaOptionalFields {
    /// the epoch at which its associated account will next owe rent
    pub rent_epoch: Option<Epoch>,
    /// the hash of its associated account
    pub account_hash: Option<AccountHash>,
}

impl AccountMetaOptionalFields {
    /// The size of the optional fields in bytes (excluding the boolean flags).
    pub fn size(&self) -> usize {
        self.rent_epoch.map_or(0, |_| std::mem::size_of::<Epoch>())
            + self
                .account_hash
                .map_or(0, |_| std::mem::size_of::<AccountHash>())
    }

    /// Given the specified AccountMetaFlags, returns the size of its
    /// associated AccountMetaOptionalFields.
    pub fn size_from_flags(flags: &AccountMetaFlags) -> usize {
        let mut fields_size = 0;
        if flags.has_rent_epoch() {
            fields_size += std::mem::size_of::<Epoch>();
        }
        if flags.has_account_hash() {
            fields_size += std::mem::size_of::<AccountHash>();
        }

        fields_size
    }

    /// Given the specified AccountMetaFlags, returns the relative offset
    /// of its rent_epoch field to the offset of its optional fields entry.
    pub fn rent_epoch_offset(_flags: &AccountMetaFlags) -> usize {
        0
    }

    /// Given the specified AccountMetaFlags, returns the relative offset
    /// of its account_hash field to the offset of its optional fields entry.
    pub fn account_hash_offset(flags: &AccountMetaFlags) -> usize {
        let mut offset = Self::rent_epoch_offset(flags);
        // rent_epoch is the previous field to account hash
        if flags.has_rent_epoch() {
            offset += std::mem::size_of::<Epoch>();
        }
        offset
    }
}
