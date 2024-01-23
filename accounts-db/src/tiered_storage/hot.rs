//! The account meta and related structs for hot accounts.

use {
    crate::{
        account_storage::meta::StoredAccountMeta,
        accounts_file::MatchAccountOwnerError,
        accounts_hash::AccountHash,
        tiered_storage::{
            byte_block,
            file::TieredStorageFile,
            footer::{AccountBlockFormat, AccountMetaFormat, TieredStorageFooter},
            index::{AccountOffset, IndexBlockFormat, IndexOffset},
            meta::{AccountMetaFlags, AccountMetaOptionalFields, TieredAccountMeta},
            mmap_utils::{get_pod, get_slice},
            owners::{OwnerOffset, OwnersBlockFormat},
            readable::TieredReadableAccount,
            TieredStorageError, TieredStorageFormat, TieredStorageResult,
        },
    },
    bytemuck::{Pod, Zeroable},
    memmap2::{Mmap, MmapOptions},
    modular_bitfield::prelude::*,
    solana_sdk::{pubkey::Pubkey, stake_history::Epoch},
    std::{fs::OpenOptions, option::Option, path::Path},
};

pub const HOT_FORMAT: TieredStorageFormat = TieredStorageFormat {
    meta_entry_size: std::mem::size_of::<HotAccountMeta>(),
    account_meta_format: AccountMetaFormat::Hot,
    owners_block_format: OwnersBlockFormat::AddressesOnly,
    index_block_format: IndexBlockFormat::AddressesThenOffsets,
    account_block_format: AccountBlockFormat::AlignedRaw,
};

/// An helper function that creates a new default footer for hot
/// accounts storage.
fn new_hot_footer() -> TieredStorageFooter {
    TieredStorageFooter {
        account_meta_format: HOT_FORMAT.account_meta_format,
        account_meta_entry_size: HOT_FORMAT.meta_entry_size as u32,
        account_block_format: HOT_FORMAT.account_block_format,
        index_block_format: HOT_FORMAT.index_block_format,
        owners_block_format: HOT_FORMAT.owners_block_format,
        ..TieredStorageFooter::default()
    }
}

/// The maximum number of padding bytes used in a hot account entry.
const MAX_HOT_PADDING: u8 = 7;

/// The maximum allowed value for the owner index of a hot account.
const MAX_HOT_OWNER_OFFSET: OwnerOffset = OwnerOffset((1 << 29) - 1);

/// The byte alignment for hot accounts.  This alignment serves duo purposes.
/// First, it allows hot accounts to be directly accessed when the underlying
/// file is mmapped.  In addition, as all hot accounts are aligned, it allows
/// each hot accounts file to handle more accounts with the same number of
/// bytes in HotAccountOffset.
pub(crate) const HOT_ACCOUNT_ALIGNMENT: usize = 8;

/// The maximum supported offset for hot accounts storage.
const MAX_HOT_ACCOUNT_OFFSET: usize = u32::MAX as usize * HOT_ACCOUNT_ALIGNMENT;

#[bitfield(bits = 32)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Pod, Zeroable)]
struct HotMetaPackedFields {
    /// A hot account entry consists of the following elements:
    ///
    /// * HotAccountMeta
    /// * [u8] account data
    /// * 0-7 bytes padding
    /// * optional fields
    ///
    /// The following field records the number of padding bytes used
    /// in its hot account entry.
    padding: B3,
    /// The index to the owner of a hot account inside an AccountsFile.
    owner_offset: B29,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotMetaPackedFields>() == 4);

/// The offset to access a hot account.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Pod, Zeroable)]
pub struct HotAccountOffset(u32);

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotAccountOffset>() == 4);

impl AccountOffset for HotAccountOffset {}

impl HotAccountOffset {
    /// Creates a new AccountOffset instance
    pub fn new(offset: usize) -> TieredStorageResult<Self> {
        if offset > MAX_HOT_ACCOUNT_OFFSET {
            return Err(TieredStorageError::OffsetOutOfBounds(
                offset,
                MAX_HOT_ACCOUNT_OFFSET,
            ));
        }

        // Hot accounts are aligned based on HOT_ACCOUNT_ALIGNMENT.
        if offset % HOT_ACCOUNT_ALIGNMENT != 0 {
            return Err(TieredStorageError::OffsetAlignmentError(
                offset,
                HOT_ACCOUNT_ALIGNMENT,
            ));
        }

        Ok(HotAccountOffset((offset / HOT_ACCOUNT_ALIGNMENT) as u32))
    }

    /// Returns the offset to the account.
    fn offset(&self) -> usize {
        self.0 as usize * HOT_ACCOUNT_ALIGNMENT
    }
}

/// The storage and in-memory representation of the metadata entry for a
/// hot account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct HotAccountMeta {
    /// The balance of this account.
    lamports: u64,
    /// Stores important fields in a packed struct.
    packed_fields: HotMetaPackedFields,
    /// Stores boolean flags and existence of each optional field.
    flags: AccountMetaFlags,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<HotAccountMeta>() == 8 + 4 + 4);

impl TieredAccountMeta for HotAccountMeta {
    /// Construct a HotAccountMeta instance.
    fn new() -> Self {
        HotAccountMeta {
            lamports: 0,
            packed_fields: HotMetaPackedFields::default(),
            flags: AccountMetaFlags::new(),
        }
    }

    /// A builder function that initializes lamports.
    fn with_lamports(mut self, lamports: u64) -> Self {
        self.lamports = lamports;
        self
    }

    /// A builder function that initializes the number of padding bytes
    /// for the account data associated with the current meta.
    fn with_account_data_padding(mut self, padding: u8) -> Self {
        if padding > MAX_HOT_PADDING {
            panic!("padding exceeds MAX_HOT_PADDING");
        }
        self.packed_fields.set_padding(padding);
        self
    }

    /// A builder function that initializes the owner's index.
    fn with_owner_offset(mut self, owner_offset: OwnerOffset) -> Self {
        if owner_offset > MAX_HOT_OWNER_OFFSET {
            panic!("owner_offset exceeds MAX_HOT_OWNER_OFFSET");
        }
        self.packed_fields.set_owner_offset(owner_offset.0);
        self
    }

    /// A builder function that initializes the account data size.
    fn with_account_data_size(self, _account_data_size: u64) -> Self {
        // Hot meta does not store its data size as it derives its data length
        // by comparing the offets of two consecutive account meta entries.
        self
    }

    /// A builder function that initializes the AccountMetaFlags of the current
    /// meta.
    fn with_flags(mut self, flags: &AccountMetaFlags) -> Self {
        self.flags = *flags;
        self
    }

    /// Returns the balance of the lamports associated with the account.
    fn lamports(&self) -> u64 {
        self.lamports
    }

    /// Returns the number of padding bytes for the associated account data
    fn account_data_padding(&self) -> u8 {
        self.packed_fields.padding()
    }

    /// Returns the index to the accounts' owner in the current AccountsFile.
    fn owner_offset(&self) -> OwnerOffset {
        OwnerOffset(self.packed_fields.owner_offset())
    }

    /// Returns the AccountMetaFlags of the current meta.
    fn flags(&self) -> &AccountMetaFlags {
        &self.flags
    }

    /// Always returns false as HotAccountMeta does not support multiple
    /// meta entries sharing the same account block.
    fn supports_shared_account_block() -> bool {
        false
    }

    /// Returns the epoch that this account will next owe rent by parsing
    /// the specified account block.  None will be returned if this account
    /// does not persist this optional field.
    fn rent_epoch(&self, account_block: &[u8]) -> Option<Epoch> {
        self.flags()
            .has_rent_epoch()
            .then(|| {
                let offset = self.optional_fields_offset(account_block)
                    + AccountMetaOptionalFields::rent_epoch_offset(self.flags());
                byte_block::read_pod::<Epoch>(account_block, offset).copied()
            })
            .flatten()
    }

    /// Returns the account hash by parsing the specified account block.  None
    /// will be returned if this account does not persist this optional field.
    fn account_hash<'a>(&self, account_block: &'a [u8]) -> Option<&'a AccountHash> {
        self.flags()
            .has_account_hash()
            .then(|| {
                let offset = self.optional_fields_offset(account_block)
                    + AccountMetaOptionalFields::account_hash_offset(self.flags());
                byte_block::read_pod::<AccountHash>(account_block, offset)
            })
            .flatten()
    }

    /// Returns the offset of the optional fields based on the specified account
    /// block.
    fn optional_fields_offset(&self, account_block: &[u8]) -> usize {
        account_block
            .len()
            .saturating_sub(AccountMetaOptionalFields::size_from_flags(&self.flags))
    }

    /// Returns the length of the data associated to this account based on the
    /// specified account block.
    fn account_data_size(&self, account_block: &[u8]) -> usize {
        self.optional_fields_offset(account_block)
            .saturating_sub(self.account_data_padding() as usize)
    }

    /// Returns the data associated to this account based on the specified
    /// account block.
    fn account_data<'a>(&self, account_block: &'a [u8]) -> &'a [u8] {
        &account_block[..self.account_data_size(account_block)]
    }
}

/// The reader to a hot accounts file.
#[derive(Debug)]
pub struct HotStorageReader {
    mmap: Mmap,
    footer: TieredStorageFooter,
}

impl HotStorageReader {
    /// Constructs a HotStorageReader from the specified path.
    pub fn new_from_path(path: impl AsRef<Path>) -> TieredStorageResult<Self> {
        let file = OpenOptions::new().read(true).open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        // Here we are copying the footer, as accessing any data in a
        // TieredStorage instance requires accessing its Footer.
        // This can help improve cache locality and reduce the overhead
        // of indirection associated with memory-mapped accesses.
        let footer = *TieredStorageFooter::new_from_mmap(&mmap)?;

        Ok(Self { mmap, footer })
    }

    /// Returns the footer of the underlying tiered-storage accounts file.
    pub fn footer(&self) -> &TieredStorageFooter {
        &self.footer
    }

    /// Returns the number of files inside the underlying tiered-storage
    /// accounts file.
    pub fn num_accounts(&self) -> usize {
        self.footer.account_entry_count as usize
    }

    /// Returns the account meta located at the specified offset.
    fn get_account_meta_from_offset(
        &self,
        account_offset: HotAccountOffset,
    ) -> TieredStorageResult<&HotAccountMeta> {
        let offset = account_offset.offset();

        assert!(
            offset.saturating_add(std::mem::size_of::<HotAccountMeta>())
                <= self.footer.index_block_offset as usize,
            "reading HotAccountOffset ({}) would exceed accounts blocks offset boundary ({}).",
            offset,
            self.footer.index_block_offset,
        );
        let (meta, _) = get_pod::<HotAccountMeta>(&self.mmap, offset)?;
        Ok(meta)
    }

    /// Returns the offset to the account given the specified index.
    fn get_account_offset(
        &self,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<HotAccountOffset> {
        self.footer
            .index_block_format
            .get_account_offset::<HotAccountOffset>(&self.mmap, &self.footer, index_offset)
    }

    /// Returns the address of the account associated with the specified index.
    fn get_account_address(&self, index: IndexOffset) -> TieredStorageResult<&Pubkey> {
        self.footer
            .index_block_format
            .get_account_address(&self.mmap, &self.footer, index)
    }

    /// Returns the address of the account owner given the specified
    /// owner_offset.
    fn get_owner_address(&self, owner_offset: OwnerOffset) -> TieredStorageResult<&Pubkey> {
        self.footer
            .owners_block_format
            .get_owner_address(&self.mmap, &self.footer, owner_offset)
    }

    /// Returns Ok(index_of_matching_owner) if the account owner at
    /// `account_offset` is one of the pubkeys in `owners`.
    ///
    /// Returns Err(MatchAccountOwnerError::NoMatch) if the account has 0
    /// lamports or the owner is not one of the pubkeys in `owners`.
    ///
    /// Returns Err(MatchAccountOwnerError::UnableToLoad) if there is any internal
    /// error that causes the data unable to load, including `account_offset`
    /// causes a data overrun.
    pub fn account_matches_owners(
        &self,
        account_offset: HotAccountOffset,
        owners: &[&Pubkey],
    ) -> Result<usize, MatchAccountOwnerError> {
        let account_meta = self
            .get_account_meta_from_offset(account_offset)
            .map_err(|_| MatchAccountOwnerError::UnableToLoad)?;

        if account_meta.lamports() == 0 {
            Err(MatchAccountOwnerError::NoMatch)
        } else {
            let account_owner = self
                .get_owner_address(account_meta.owner_offset())
                .map_err(|_| MatchAccountOwnerError::UnableToLoad)?;

            owners
                .iter()
                .position(|candidate| &account_owner == candidate)
                .ok_or(MatchAccountOwnerError::NoMatch)
        }
    }

    /// Returns the size of the account block based on its account offset
    /// and index offset.
    ///
    /// The account block size information is omitted in the hot accounts file
    /// as it can be derived by comparing the offset of the next hot account
    /// meta in the index block.
    fn get_account_block_size(
        &self,
        account_offset: HotAccountOffset,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<usize> {
        // the offset that points to the hot account meta.
        let account_meta_offset = account_offset.offset();

        // Obtain the ending offset of the account block.  If the current
        // account is the last account, then the ending offset is the
        // index_block_offset.
        let account_block_ending_offset =
            if index_offset.0.saturating_add(1) == self.footer.account_entry_count {
                self.footer.index_block_offset as usize
            } else {
                self.get_account_offset(IndexOffset(index_offset.0.saturating_add(1)))?
                    .offset()
            };

        // With the ending offset, minus the starting offset (i.e.,
        // the account meta offset) and the HotAccountMeta size, the reminder
        // is the account block size (account data + optional fields).
        Ok(account_block_ending_offset
            .saturating_sub(account_meta_offset)
            .saturating_sub(std::mem::size_of::<HotAccountMeta>()))
    }

    /// Returns the account block that contains the account associated with
    /// the specified index given the offset to the account meta and its index.
    fn get_account_block(
        &self,
        account_offset: HotAccountOffset,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<&[u8]> {
        let (data, _) = get_slice(
            &self.mmap,
            account_offset.offset() + std::mem::size_of::<HotAccountMeta>(),
            self.get_account_block_size(account_offset, index_offset)?,
        )?;

        Ok(data)
    }

    /// Returns the account located at the specified index offset.
    pub fn get_account(
        &self,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<Option<(StoredAccountMeta<'_>, usize)>> {
        if index_offset.0 >= self.footer.account_entry_count {
            return Ok(None);
        }

        let account_offset = self.get_account_offset(index_offset)?;

        let meta = self.get_account_meta_from_offset(account_offset)?;
        let address = self.get_account_address(index_offset)?;
        let owner = self.get_owner_address(meta.owner_offset())?;
        let account_block = self.get_account_block(account_offset, index_offset)?;

        Ok(Some((
            StoredAccountMeta::Hot(TieredReadableAccount {
                meta,
                address,
                owner,
                index: index_offset.0 as usize,
                account_block,
            }),
            index_offset.0.saturating_add(1) as usize,
        )))
    }
}

/// The writer that creates a hot accounts file.
#[derive(Debug)]
pub struct HotStorageWriter {
    storage: TieredStorageFile,
}

impl HotStorageWriter {
    /// Create a new HotStorageWriter with the specified path.
    pub fn new(file_path: impl AsRef<Path>) -> TieredStorageResult<Self> {
        Ok(Self {
            storage: TieredStorageFile::new_writable(file_path)?,
        })
    }
}
