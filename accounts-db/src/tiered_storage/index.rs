use {
    crate::tiered_storage::{
        file::TieredStorageFile, footer::TieredStorageFooter, mmap_utils::get_pod,
        TieredStorageResult,
    },
    bytemuck::{Pod, Zeroable},
    memmap2::Mmap,
    solana_sdk::pubkey::Pubkey,
};

/// The in-memory struct for the writing index block.
#[derive(Debug)]
pub struct AccountIndexWriterEntry<'a, Offset: AccountOffset> {
    /// The account address.
    pub address: &'a Pubkey,
    /// The offset to the account.
    pub offset: Offset,
}

/// The offset to an account.
pub trait AccountOffset: Clone + Copy + Pod + Zeroable {}

/// The offset to an account/address entry in the accounts index block.
/// This can be used to obtain the AccountOffset and address by looking through
/// the accounts index block.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod, Zeroable)]
pub struct IndexOffset(pub u32);

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<IndexOffset>() == 4);

/// The index format of a tiered accounts file.
#[repr(u16)]
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    PartialEq,
    num_enum::IntoPrimitive,
    num_enum::TryFromPrimitive,
)]
pub enum IndexBlockFormat {
    /// This format optimizes the storage size by storing only account addresses
    /// and block offsets.  It skips storing the size of account data by storing
    /// account block entries and index block entries in the same order.
    #[default]
    AddressesThenOffsets = 0,
}

// Ensure there are no implicit padding bytes
const _: () = assert!(std::mem::size_of::<IndexBlockFormat>() == 2);

impl IndexBlockFormat {
    /// Persists the specified index_entries to the specified file and returns
    /// the total number of bytes written.
    pub fn write_index_block(
        &self,
        file: &TieredStorageFile,
        index_entries: &[AccountIndexWriterEntry<impl AccountOffset>],
    ) -> TieredStorageResult<usize> {
        match self {
            Self::AddressesThenOffsets => {
                let mut bytes_written = 0;
                for index_entry in index_entries {
                    bytes_written += file.write_pod(index_entry.address)?;
                }
                for index_entry in index_entries {
                    bytes_written += file.write_pod(&index_entry.offset)?;
                }
                Ok(bytes_written)
            }
        }
    }

    /// Returns the address of the account given the specified index.
    pub fn get_account_address<'a>(
        &self,
        mmap: &'a Mmap,
        footer: &TieredStorageFooter,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<&'a Pubkey> {
        let offset = match self {
            Self::AddressesThenOffsets => {
                debug_assert!(index_offset.0 < footer.account_entry_count);
                footer.index_block_offset as usize
                    + std::mem::size_of::<Pubkey>() * (index_offset.0 as usize)
            }
        };

        debug_assert!(
            offset.saturating_add(std::mem::size_of::<Pubkey>())
                <= footer.owners_block_offset as usize,
            "reading IndexOffset ({}) would exceed index block boundary ({}).",
            offset,
            footer.owners_block_offset,
        );

        let (address, _) = get_pod::<Pubkey>(mmap, offset)?;
        Ok(address)
    }

    /// Returns the offset to the account given the specified index.
    pub fn get_account_offset<Offset: AccountOffset>(
        &self,
        mmap: &Mmap,
        footer: &TieredStorageFooter,
        index_offset: IndexOffset,
    ) -> TieredStorageResult<Offset> {
        let offset = match self {
            Self::AddressesThenOffsets => {
                debug_assert!(index_offset.0 < footer.account_entry_count);
                footer.index_block_offset as usize
                    + std::mem::size_of::<Pubkey>() * footer.account_entry_count as usize
                    + std::mem::size_of::<Offset>() * index_offset.0 as usize
            }
        };

        debug_assert!(
            offset.saturating_add(std::mem::size_of::<Offset>())
                <= footer.owners_block_offset as usize,
            "reading IndexOffset ({}) would exceed index block boundary ({}).",
            offset,
            footer.owners_block_offset,
        );

        let (account_offset, _) = get_pod::<Offset>(mmap, offset)?;

        Ok(*account_offset)
    }

    /// Returns the size of one index entry.
    pub fn entry_size<Offset: AccountOffset>(&self) -> usize {
        match self {
            Self::AddressesThenOffsets => {
                std::mem::size_of::<Pubkey>() + std::mem::size_of::<Offset>()
            }
        }
    }
}
