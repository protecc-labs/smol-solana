//! Persistent storage for accounts.
//!
//! For more information, see:
//!
//! <https://docs.solanalabs.com/implemented-proposals/persistent-account-storage>

use {
    crate::{
        account_storage::meta::{
            AccountMeta, StorableAccountsWithHashesAndWriteVersions, StoredAccountInfo,
            StoredAccountMeta, StoredMeta, StoredMetaWriteVersion,
        },
        accounts_file::{AccountsFileError, MatchAccountOwnerError, Result, ALIGN_BOUNDARY_OFFSET},
        accounts_hash::AccountHash,
        storable_accounts::StorableAccounts,
        u64_align,
    },
    log::*,
    memmap2::MmapMut,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        clock::Slot,
        pubkey::Pubkey,
        stake_history::Epoch,
    },
    std::{
        borrow::Borrow,
        convert::TryFrom,
        fs::{remove_file, OpenOptions},
        io::{Seek, SeekFrom, Write},
        mem,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Mutex,
        },
    },
    thiserror::Error,
};

pub mod test_utils;

/// size of the fixed sized fields in an append vec
/// we need to add data len and align it to get the actual stored size
pub const STORE_META_OVERHEAD: usize = 136;

/// Returns the size this item will take to store plus possible alignment padding bytes before the next entry.
/// fixed-size portion of per-account data written
/// plus 'data_len', aligned to next boundary
pub fn aligned_stored_size(data_len: usize) -> usize {
    u64_align!(STORE_META_OVERHEAD + data_len)
}

pub const MAXIMUM_APPEND_VEC_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

#[derive(Error, Debug)]
/// An enum for AppendVec related errors.
pub enum AppendVecError {
    #[error("too small file size {0} for AppendVec")]
    FileSizeTooSmall(usize),

    #[error("too large file size {0} for AppendVec")]
    FileSizeTooLarge(usize),

    #[error("incorrect layout/length/data in the appendvec at path {}", .0.display())]
    IncorrectLayout(PathBuf),

    #[error("offset ({0}) is larger than file size ({1})")]
    OffsetOutOfBounds(usize, usize),
}

pub struct AppendVecAccountsIter<'append_vec> {
    append_vec: &'append_vec AppendVec,
    offset: usize,
}

impl<'append_vec> AppendVecAccountsIter<'append_vec> {
    pub fn new(append_vec: &'append_vec AppendVec) -> Self {
        Self {
            append_vec,
            offset: 0,
        }
    }
}

impl<'append_vec> Iterator for AppendVecAccountsIter<'append_vec> {
    type Item = StoredAccountMeta<'append_vec>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((account, next_offset)) = self.append_vec.get_account(self.offset) {
            self.offset = next_offset;
            Some(account)
        } else {
            None
        }
    }
}

/// References to account data stored elsewhere. Getting an `Account` requires cloning
/// (see `StoredAccountMeta::clone_account()`).
#[derive(PartialEq, Eq, Debug)]
pub struct AppendVecStoredAccountMeta<'append_vec> {
    pub meta: &'append_vec StoredMeta,
    /// account data
    pub account_meta: &'append_vec AccountMeta,
    pub(crate) data: &'append_vec [u8],
    pub(crate) offset: usize,
    pub(crate) stored_size: usize,
    pub(crate) hash: &'append_vec AccountHash,
}

impl<'append_vec> AppendVecStoredAccountMeta<'append_vec> {
    pub fn pubkey(&self) -> &'append_vec Pubkey {
        &self.meta.pubkey
    }

    pub fn hash(&self) -> &'append_vec AccountHash {
        self.hash
    }

    pub fn stored_size(&self) -> usize {
        self.stored_size
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn data(&self) -> &'append_vec [u8] {
        self.data
    }

    pub fn data_len(&self) -> u64 {
        self.meta.data_len
    }

    pub fn write_version(&self) -> StoredMetaWriteVersion {
        self.meta.write_version_obsolete
    }

    pub fn meta(&self) -> &StoredMeta {
        self.meta
    }

    pub fn set_meta(&mut self, meta: &'append_vec StoredMeta) {
        self.meta = meta;
    }

    pub(crate) fn sanitize(&self) -> bool {
        self.sanitize_executable() && self.sanitize_lamports()
    }

    fn sanitize_executable(&self) -> bool {
        // Sanitize executable to ensure higher 7-bits are cleared correctly.
        self.ref_executable_byte() & !1 == 0
    }

    fn sanitize_lamports(&self) -> bool {
        // Sanitize 0 lamports to ensure to be same as AccountSharedData::default()
        self.account_meta.lamports != 0
            || self.to_account_shared_data() == AccountSharedData::default()
    }

    fn ref_executable_byte(&self) -> &u8 {
        // Use extra references to avoid value silently clamped to 1 (=true) and 0 (=false)
        // Yes, this really happens; see test_new_from_file_crafted_executable
        let executable_bool: &bool = &self.account_meta.executable;
        // UNSAFE: Force to interpret mmap-backed bool as u8 to really read the actual memory content
        let executable_byte: &u8 = unsafe { &*(executable_bool as *const bool as *const u8) };
        executable_byte
    }
}

impl<'append_vec> ReadableAccount for AppendVecStoredAccountMeta<'append_vec> {
    fn lamports(&self) -> u64 {
        self.account_meta.lamports
    }
    fn data(&self) -> &'append_vec [u8] {
        self.data()
    }
    fn owner(&self) -> &'append_vec Pubkey {
        &self.account_meta.owner
    }
    fn executable(&self) -> bool {
        self.account_meta.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.account_meta.rent_epoch
    }
}

/// A thread-safe, file-backed block of memory used to store `Account` instances. Append operations
/// are serialized such that only one thread updates the internal `append_lock` at a time. No
/// restrictions are placed on reading. That is, one may read items from one thread while another
/// is appending new items.
#[derive(Debug, AbiExample)]
pub struct AppendVec {
    /// The file path where the data is stored.
    path: PathBuf,

    /// A file-backed block of memory that is used to store the data for each appended item.
    map: MmapMut,

    /// A lock used to serialize append operations.
    append_lock: Mutex<()>,

    /// The number of bytes used to store items, not the number of items.
    current_len: AtomicUsize,

    /// The number of bytes available for storing items.
    file_size: u64,
}

lazy_static! {
    pub static ref APPEND_VEC_MMAPPED_FILES_OPEN: AtomicU64 = AtomicU64::default();
}

impl Drop for AppendVec {
    fn drop(&mut self) {
        APPEND_VEC_MMAPPED_FILES_OPEN.fetch_sub(1, Ordering::Relaxed);
        if let Err(_err) = remove_file(&self.path) {
            // promote this to panic soon.
            // disabled due to many false positive warnings while running tests.
            // blocked by rpc's upgrade to jsonrpc v17
            //error!("AppendVec failed to remove {}: {err}", &self.path.display());
            inc_new_counter_info!("append_vec_drop_fail", 1);
        }
    }
}

impl AppendVec {
    pub fn new(file: &Path, create: bool, size: usize) -> Self {
        let initial_len = 0;
        AppendVec::sanitize_len_and_size(initial_len, size).unwrap();

        if create {
            let _ignored = remove_file(file);
        }

        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .open(file)
            .map_err(|e| {
                panic!(
                    "Unable to {} data file {} in current dir({:?}): {:?}",
                    if create { "create" } else { "open" },
                    file.display(),
                    std::env::current_dir(),
                    e
                );
            })
            .unwrap();

        // Theoretical performance optimization: write a zero to the end of
        // the file so that we won't have to resize it later, which may be
        // expensive.
        data.seek(SeekFrom::Start((size - 1) as u64)).unwrap();
        data.write_all(&[0]).unwrap();
        data.rewind().unwrap();
        data.flush().unwrap();

        //UNSAFE: Required to create a Mmap
        let map = unsafe { MmapMut::map_mut(&data) };
        let map = map.unwrap_or_else(|e| {
            error!(
                "Failed to map the data file (size: {}): {}.\n
                    Please increase sysctl vm.max_map_count or equivalent for your platform.",
                size, e
            );
            std::process::exit(1);
        });
        APPEND_VEC_MMAPPED_FILES_OPEN.fetch_add(1, Ordering::Relaxed);

        AppendVec {
            path: file.to_path_buf(),
            map,
            // This mutex forces append to be single threaded, but concurrent with reads
            // See UNSAFE usage in `append_ptr`
            append_lock: Mutex::new(()),
            current_len: AtomicUsize::new(initial_len),
            file_size: size as u64,
        }
    }

    fn sanitize_len_and_size(current_len: usize, file_size: usize) -> Result<()> {
        if file_size == 0 {
            Err(AccountsFileError::AppendVecError(
                AppendVecError::FileSizeTooSmall(file_size),
            ))
        } else if usize::try_from(MAXIMUM_APPEND_VEC_FILE_SIZE)
            .map(|max| file_size > max)
            .unwrap_or(true)
        {
            Err(AccountsFileError::AppendVecError(
                AppendVecError::FileSizeTooLarge(file_size),
            ))
        } else if current_len > file_size {
            Err(AccountsFileError::AppendVecError(
                AppendVecError::OffsetOutOfBounds(current_len, file_size),
            ))
        } else {
            Ok(())
        }
    }

    pub fn flush(&self) -> Result<()> {
        self.map.flush()?;
        Ok(())
    }

    pub fn reset(&self) {
        // This mutex forces append to be single threaded, but concurrent with reads
        // See UNSAFE usage in `append_ptr`
        let _lock = self.append_lock.lock().unwrap();
        self.current_len.store(0, Ordering::Release);
    }

    /// how many more bytes can be stored in this append vec
    pub fn remaining_bytes(&self) -> u64 {
        self.capacity()
            .saturating_sub(u64_align!(self.len()) as u64)
    }

    pub fn len(&self) -> usize {
        self.current_len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> u64 {
        self.file_size
    }

    pub fn file_name(slot: Slot, id: impl std::fmt::Display) -> String {
        format!("{slot}.{id}")
    }

    pub fn new_from_file<P: AsRef<Path>>(path: P, current_len: usize) -> Result<(Self, usize)> {
        let new = Self::new_from_file_unchecked(&path, current_len)?;

        let (sanitized, num_accounts) = new.sanitize_layout_and_length();
        if !sanitized {
            // This info show the failing accountvec file path.  It helps debugging
            // the appendvec data corrupution issues related to recycling.
            return Err(AccountsFileError::AppendVecError(
                AppendVecError::IncorrectLayout(path.as_ref().to_path_buf()),
            ));
        }

        Ok((new, num_accounts))
    }

    /// Creates an appendvec from file without performing sanitize checks or counting the number of accounts
    pub fn new_from_file_unchecked<P: AsRef<Path>>(path: P, current_len: usize) -> Result<Self> {
        let file_size = std::fs::metadata(&path)?.len();
        Self::sanitize_len_and_size(current_len, file_size as usize)?;

        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&path)?;

        let map = unsafe {
            let result = MmapMut::map_mut(&data);
            if result.is_err() {
                // for vm.max_map_count, error is: {code: 12, kind: Other, message: "Cannot allocate memory"}
                info!("memory map error: {:?}. This may be because vm.max_map_count is not set correctly.", result);
            }
            result?
        };
        APPEND_VEC_MMAPPED_FILES_OPEN.fetch_add(1, Ordering::Relaxed);

        Ok(AppendVec {
            path: path.as_ref().to_path_buf(),
            map,
            append_lock: Mutex::new(()),
            current_len: AtomicUsize::new(current_len),
            file_size,
        })
    }

    fn sanitize_layout_and_length(&self) -> (bool, usize) {
        let mut offset = 0;

        // This discards allocated accounts immediately after check at each loop iteration.
        //
        // This code should not reuse AppendVec.accounts() method as the current form or
        // extend it to be reused here because it would allow attackers to accumulate
        // some measurable amount of memory needlessly.
        let mut num_accounts = 0;
        while let Some((account, next_offset)) = self.get_account(offset) {
            if !account.sanitize() {
                return (false, num_accounts);
            }
            offset = next_offset;
            num_accounts += 1;
        }
        let aligned_current_len = u64_align!(self.current_len.load(Ordering::Acquire));

        (offset == aligned_current_len, num_accounts)
    }

    /// Get a reference to the data at `offset` of `size` bytes if that slice
    /// doesn't overrun the internal buffer. Otherwise return None.
    /// Also return the offset of the first byte after the requested data that
    /// falls on a 64-byte boundary.
    fn get_slice(&self, offset: usize, size: usize) -> Option<(&[u8], usize)> {
        let (next, overflow) = offset.overflowing_add(size);
        if overflow || next > self.len() {
            return None;
        }
        let data = &self.map[offset..next];
        let next = u64_align!(next);

        Some((
            //UNSAFE: This unsafe creates a slice that represents a chunk of self.map memory
            //The lifetime of this slice is tied to &self, since it points to self.map memory
            unsafe { std::slice::from_raw_parts(data.as_ptr(), size) },
            next,
        ))
    }

    /// Copy `len` bytes from `src` to the first 64-byte boundary after position `offset` of
    /// the internal buffer. Then update `offset` to the first byte after the copied data.
    fn append_ptr(&self, offset: &mut usize, src: *const u8, len: usize) {
        let pos = u64_align!(*offset);
        let data = &self.map[pos..(pos + len)];
        //UNSAFE: This mut append is safe because only 1 thread can append at a time
        //Mutex<()> guarantees exclusive write access to the memory occupied in
        //the range.
        unsafe {
            let dst = data.as_ptr() as *mut u8;
            std::ptr::copy(src, dst, len);
        };
        *offset = pos + len;
    }

    /// Copy each value in `vals`, in order, to the first 64-byte boundary after position `offset`.
    /// If there is sufficient space, then update `offset` and the internal `current_len` to the
    /// first byte after the copied data and return the starting position of the copied data.
    /// Otherwise return None and leave `offset` unchanged.
    fn append_ptrs_locked(&self, offset: &mut usize, vals: &[(*const u8, usize)]) -> Option<usize> {
        let mut end = *offset;
        for val in vals {
            end = u64_align!(end);
            end += val.1;
        }

        if (self.file_size as usize) < end {
            return None;
        }

        let pos = u64_align!(*offset);
        for val in vals {
            self.append_ptr(offset, val.0, val.1)
        }
        self.current_len.store(*offset, Ordering::Release);
        Some(pos)
    }

    /// Return a reference to the type at `offset` if its data doesn't overrun the internal buffer.
    /// Otherwise return None. Also return the offset of the first byte after the requested data
    /// that falls on a 64-byte boundary.
    fn get_type<T>(&self, offset: usize) -> Option<(&T, usize)> {
        let (data, next) = self.get_slice(offset, mem::size_of::<T>())?;
        let ptr: *const T = data.as_ptr() as *const T;
        //UNSAFE: The cast is safe because the slice is aligned and fits into the memory
        //and the lifetime of the &T is tied to self, which holds the underlying memory map
        Some((unsafe { &*ptr }, next))
    }

    /// Return stored account metadata for the account at `offset` if its data doesn't overrun
    /// the internal buffer. Otherwise return None. Also return the offset of the first byte
    /// after the requested data that falls on a 64-byte boundary.
    pub fn get_account(&self, offset: usize) -> Option<(StoredAccountMeta, usize)> {
        let (meta, next): (&StoredMeta, _) = self.get_type(offset)?;
        let (account_meta, next): (&AccountMeta, _) = self.get_type(next)?;
        let (hash, next): (&AccountHash, _) = self.get_type(next)?;
        let (data, next) = self.get_slice(next, meta.data_len as usize)?;
        let stored_size = next - offset;
        Some((
            StoredAccountMeta::AppendVec(AppendVecStoredAccountMeta {
                meta,
                account_meta,
                data,
                offset,
                stored_size,
                hash,
            }),
            next,
        ))
    }

    fn get_account_meta(&self, offset: usize) -> Option<&AccountMeta> {
        // Skip over StoredMeta data in the account
        let offset = offset.checked_add(mem::size_of::<StoredMeta>())?;
        // u64_align! does an unchecked add for alignment. Check that it won't cause an overflow.
        offset.checked_add(ALIGN_BOUNDARY_OFFSET - 1)?;
        let (account_meta, _): (&AccountMeta, _) = self.get_type(u64_align!(offset))?;
        Some(account_meta)
    }

    /// Return Ok(index_of_matching_owner) if the account owner at `offset` is one of the pubkeys in `owners`.
    /// Return Err(MatchAccountOwnerError::NoMatch) if the account has 0 lamports or the owner is not one of
    /// the pubkeys in `owners`.
    /// Return Err(MatchAccountOwnerError::UnableToLoad) if the `offset` value causes a data overrun.
    pub fn account_matches_owners(
        &self,
        offset: usize,
        owners: &[Pubkey],
    ) -> std::result::Result<usize, MatchAccountOwnerError> {
        let account_meta = self
            .get_account_meta(offset)
            .ok_or(MatchAccountOwnerError::UnableToLoad)?;
        if account_meta.lamports == 0 {
            Err(MatchAccountOwnerError::NoMatch)
        } else {
            owners
                .iter()
                .position(|entry| &account_meta.owner == entry)
                .ok_or(MatchAccountOwnerError::NoMatch)
        }
    }

    #[cfg(test)]
    pub fn get_account_test(
        &self,
        offset: usize,
    ) -> Option<(StoredMeta, solana_sdk::account::AccountSharedData)> {
        let (stored_account, _) = self.get_account(offset)?;
        let meta = stored_account.meta().clone();
        Some((meta, stored_account.to_account_shared_data()))
    }

    pub fn get_path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Return iterator for account metadata
    pub fn account_iter(&self) -> AppendVecAccountsIter {
        AppendVecAccountsIter::new(self)
    }

    /// Return a vector of account metadata for each account, starting from `offset`.
    pub fn accounts(&self, mut offset: usize) -> Vec<StoredAccountMeta> {
        let mut accounts = vec![];
        while let Some((account, next)) = self.get_account(offset) {
            accounts.push(account);
            offset = next;
        }
        accounts
    }

    /// Copy each account metadata, account and hash to the internal buffer.
    /// If there is no room to write the first entry, None is returned.
    /// Otherwise, returns the starting offset of each account metadata.
    /// Plus, the final return value is the offset where the next entry would be appended.
    /// So, return.len() is 1 + (number of accounts written)
    /// After each account is appended, the internal `current_len` is updated
    /// and will be available to other threads.
    pub fn append_accounts<
        'a,
        'b,
        T: ReadableAccount + Sync,
        U: StorableAccounts<'a, T>,
        V: Borrow<AccountHash>,
    >(
        &self,
        accounts: &StorableAccountsWithHashesAndWriteVersions<'a, 'b, T, U, V>,
        skip: usize,
    ) -> Option<Vec<StoredAccountInfo>> {
        let _lock = self.append_lock.lock().unwrap();
        let mut offset = self.len();

        let len = accounts.accounts.len();
        let mut offsets = Vec::with_capacity(len);
        for i in skip..len {
            let (account, pubkey, hash, write_version_obsolete) = accounts.get(i);
            let account_meta = account
                .map(|account| AccountMeta {
                    lamports: account.lamports(),
                    owner: *account.owner(),
                    rent_epoch: account.rent_epoch(),
                    executable: account.executable(),
                })
                .unwrap_or_default();

            let stored_meta = StoredMeta {
                pubkey: *pubkey,
                data_len: account
                    .map(|account| account.data().len())
                    .unwrap_or_default() as u64,
                write_version_obsolete,
            };
            let meta_ptr = &stored_meta as *const StoredMeta;
            let account_meta_ptr = &account_meta as *const AccountMeta;
            let data_len = stored_meta.data_len as usize;
            let data_ptr = account
                .map(|account| account.data())
                .unwrap_or_default()
                .as_ptr();
            let hash_ptr = bytemuck::bytes_of(hash).as_ptr();
            let ptrs = [
                (meta_ptr as *const u8, mem::size_of::<StoredMeta>()),
                (account_meta_ptr as *const u8, mem::size_of::<AccountMeta>()),
                (hash_ptr, mem::size_of::<AccountHash>()),
                (data_ptr, data_len),
            ];
            if let Some(res) = self.append_ptrs_locked(&mut offset, &ptrs) {
                offsets.push(res)
            } else {
                break;
            }
        }

        if offsets.is_empty() {
            None
        } else {
            // The last entry in this offset needs to be the u64 aligned offset, because that's
            // where the *next* entry will begin to be stored.
            offsets.push(u64_align!(offset));
            let mut rv = Vec::with_capacity(len);
            for offsets in offsets.windows(2) {
                rv.push(StoredAccountInfo {
                    offset: offsets[0],
                    size: offsets[1] - offsets[0],
                });
            }

            Some(rv)
        }
    }
}
