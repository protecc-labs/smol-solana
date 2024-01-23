//! Persistent accounts are stored at this path location:
//!  `<path>/<pid>/data/`
//!
//! The persistent store would allow for this mode of operation:
//!  - Concurrent single thread append with many concurrent readers.
//!
//! The underlying memory is memory mapped to a file. The accounts would be
//! stored across multiple files and the mappings of file and offset of a
//! particular account would be stored in a shared index. This will allow for
//! concurrent commits without blocking reads, which will sequentially write
//! to memory, ssd or disk, and should be as fast as the hardware allow for.
//! The only required in memory data structure with a write lock is the index,
//! which should be fast to update.
//!
//! [`AppendVec`]'s only store accounts for single slots.  To bootstrap the
//! index from a persistent store of [`AppendVec`]'s, the entries include
//! a "write_version".  A single global atomic `AccountsDb::write_version`
//! tracks the number of commits to the entire data store. So the latest
//! commit for each slot entry would be indexed.

#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::{
        account_info::{AccountInfo, StorageLocation},
        account_storage::{
            meta::{
                StorableAccountsWithHashesAndWriteVersions, StoredAccountMeta,
                StoredMetaWriteVersion,
            },
            AccountStorage, AccountStorageStatus, ShrinkInProgress,
        },
        accounts_cache::{AccountsCache, CachedAccount, SlotCache},
        accounts_file::{
            AccountsFile, AccountsFileError, MatchAccountOwnerError, ALIGN_BOUNDARY_OFFSET,
        },
        accounts_hash::{
            AccountHash, AccountsDeltaHash, AccountsHash, AccountsHashKind, AccountsHasher,
            CalcAccountsHashConfig, CalculateHashIntermediate, HashStats, IncrementalAccountsHash,
            SerdeAccountsDeltaHash, SerdeAccountsHash, SerdeIncrementalAccountsHash,
            ZeroLamportAccounts,
        },
        accounts_index::{
            AccountIndexGetResult, AccountMapEntry, AccountSecondaryIndexes, AccountsIndex,
            AccountsIndexConfig, AccountsIndexRootsStats, AccountsIndexScanResult, DiskIndexValue,
            IndexKey, IndexValue, IsCached, RefCount, ScanConfig, ScanResult, SlotList,
            UpsertReclaim, ZeroLamport, ACCOUNTS_INDEX_CONFIG_FOR_BENCHMARKS,
            ACCOUNTS_INDEX_CONFIG_FOR_TESTING,
        },
        accounts_index_storage::Startup,
        accounts_partition::RentPayingAccountsByPartition,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        active_stats::{ActiveStatItem, ActiveStats},
        ancestors::Ancestors,
        ancient_append_vecs::{
            get_ancient_append_vec_capacity, is_ancient, AccountsToStore, StorageSelector,
        },
        append_vec::{
            aligned_stored_size, AppendVec, APPEND_VEC_MMAPPED_FILES_OPEN, STORE_META_OVERHEAD,
        },
        cache_hash_data::{CacheHashData, CacheHashDataFileReference},
        contains::Contains,
        epoch_accounts_hash::EpochAccountsHashManager,
        in_mem_accounts_index::StartupStats,
        partitioned_rewards::{PartitionedEpochRewardsConfig, TestPartitionedEpochRewards},
        pubkey_bins::PubkeyBinCalculator24,
        read_only_accounts_cache::ReadOnlyAccountsCache,
        rent_collector::RentCollector,
        sorted_storages::SortedStorages,
        storable_accounts::StorableAccounts,
        u64_align, utils,
        verify_accounts_hash_in_background::VerifyAccountsHashInBackground,
    },
    blake3::traits::digest::Digest,
    crossbeam_channel::{unbounded, Receiver, Sender},
    dashmap::{DashMap, DashSet},
    log::*,
    rand::{thread_rng, Rng},
    rayon::{prelude::*, ThreadPool},
    seqlock::SeqLock,
    serde::{Deserialize, Serialize},
    smallvec::SmallVec,
    solana_measure::{measure::Measure, measure_us},
    solana_nohash_hasher::{IntMap, IntSet},
    solana_rayon_threadlimit::get_thread_count,
    solana_sdk::{
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        clock::{BankId, Epoch, Slot},
        epoch_schedule::EpochSchedule,
        genesis_config::{ClusterType, GenesisConfig},
        hash::Hash,
        pubkey::Pubkey,
        saturating_add_assign,
        timing::AtomicInterval,
        transaction::SanitizedTransaction,
    },
    std::{
        borrow::{Borrow, Cow},
        boxed::Box,
        collections::{hash_map, BTreeSet, HashMap, HashSet},
        fs,
        hash::{Hash as StdHash, Hasher as StdHasher},
        io::Result as IoResult,
        ops::{Range, RangeBounds},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
            Arc, Condvar, Mutex, RwLock,
        },
        thread::{sleep, Builder},
        time::{Duration, Instant},
    },
    tempfile::TempDir,
};

const PAGE_SIZE: u64 = 4 * 1024;
pub(crate) const MAX_RECYCLE_STORES: usize = 1000;
// when the accounts write cache exceeds this many bytes, we will flush it
// this can be specified on the command line, too (--accounts-db-cache-limit-mb)
const WRITE_CACHE_LIMIT_BYTES_DEFAULT: u64 = 15_000_000_000;
const SCAN_SLOT_PAR_ITER_THRESHOLD: usize = 4000;

const UNREF_ACCOUNTS_BATCH_SIZE: usize = 10_000;

pub const DEFAULT_FILE_SIZE: u64 = PAGE_SIZE * 1024;
pub const DEFAULT_NUM_THREADS: u32 = 8;
pub const DEFAULT_NUM_DIRS: u32 = 4;

// When calculating hashes, it is helpful to break the pubkeys found into bins based on the pubkey value.
// More bins means smaller vectors to sort, copy, etc.
pub const PUBKEY_BINS_FOR_CALCULATING_HASHES: usize = 65536;

// Without chunks, we end up with 1 output vec for each outer snapshot storage.
// This results in too many vectors to be efficient.
// Chunks when scanning storages to calculate hashes.
// If this is too big, we don't get enough parallelism of scanning storages.
// If this is too small, then we produce too many output vectors to iterate.
// Metrics indicate a sweet spot in the 2.5k-5k range for mnb.
const MAX_ITEMS_PER_CHUNK: Slot = 2_500;

// When getting accounts for shrinking from the index, this is the # of accounts to lookup per thread.
// This allows us to split up accounts index accesses across multiple threads.
const SHRINK_COLLECT_CHUNK_SIZE: usize = 50;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CreateAncientStorage {
    /// ancient storages are created by appending
    #[default]
    Append,
    /// ancient storages are created by 1-shot write to pack multiple accounts together more efficiently with new formats
    Pack,
}

#[derive(Debug)]
enum StoreTo<'a> {
    /// write to cache
    Cache,
    /// write to storage
    Storage(&'a Arc<AccountStorageEntry>),
}

impl<'a> StoreTo<'a> {
    fn is_cached(&self) -> bool {
        matches!(self, StoreTo::Cache)
    }
}

enum ScanAccountStorageResult {
    /// this data has already been scanned and cached
    CacheFileAlreadyExists(CacheHashDataFileReference),
    /// this data needs to be scanned and cached
    CacheFileNeedsToBeCreated((String, Range<Slot>)),
}

#[derive(Default, Debug)]
/// hold alive accounts
/// alive means in the accounts index
pub(crate) struct AliveAccounts<'a> {
    /// slot the accounts are currently stored in
    pub(crate) slot: Slot,
    pub(crate) accounts: Vec<&'a StoredAccountMeta<'a>>,
    pub(crate) bytes: usize,
}

/// separate pubkeys into those with a single refcount and those with > 1 refcount
#[derive(Debug)]
pub(crate) struct ShrinkCollectAliveSeparatedByRefs<'a> {
    /// accounts where ref_count = 1
    pub(crate) one_ref: AliveAccounts<'a>,
    /// account where ref_count > 1, but this slot contains the alive entry with the highest slot
    pub(crate) many_refs_this_is_newest_alive: AliveAccounts<'a>,
    /// account where ref_count > 1, and this slot is NOT the highest alive entry in the index for the pubkey
    pub(crate) many_refs_old_alive: AliveAccounts<'a>,
}

/// Configuration Parameters for running accounts hash and total lamports verification
#[derive(Debug, Clone)]
pub struct VerifyAccountsHashAndLamportsConfig<'a> {
    /// bank ancestors
    pub ancestors: &'a Ancestors,
    /// true to verify hash calculation
    pub test_hash_calculation: bool,
    /// epoch_schedule
    pub epoch_schedule: &'a EpochSchedule,
    /// rent_collector
    pub rent_collector: &'a RentCollector,
    /// true to ignore mismatches
    pub ignore_mismatch: bool,
    /// true to dump debug log if mismatch happens
    pub store_detailed_debug_info: bool,
    /// true to use dedicated background thread pool for verification
    pub use_bg_thread_pool: bool,
}

pub(crate) trait ShrinkCollectRefs<'a>: Sync + Send {
    fn with_capacity(capacity: usize, slot: Slot) -> Self;
    fn collect(&mut self, other: Self);
    fn add(
        &mut self,
        ref_count: u64,
        account: &'a StoredAccountMeta<'a>,
        slot_list: &[(Slot, AccountInfo)],
    );
    fn len(&self) -> usize;
    fn alive_bytes(&self) -> usize;
    fn alive_accounts(&self) -> &Vec<&'a StoredAccountMeta<'a>>;
}

impl<'a> ShrinkCollectRefs<'a> for AliveAccounts<'a> {
    fn collect(&mut self, mut other: Self) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.accounts.append(&mut other.accounts);
    }
    fn with_capacity(capacity: usize, slot: Slot) -> Self {
        Self {
            accounts: Vec::with_capacity(capacity),
            bytes: 0,
            slot,
        }
    }
    fn add(
        &mut self,
        _ref_count: u64,
        account: &'a StoredAccountMeta<'a>,
        _slot_list: &[(Slot, AccountInfo)],
    ) {
        self.accounts.push(account);
        self.bytes = self.bytes.saturating_add(account.stored_size());
    }
    fn len(&self) -> usize {
        self.accounts.len()
    }
    fn alive_bytes(&self) -> usize {
        self.bytes
    }
    fn alive_accounts(&self) -> &Vec<&'a StoredAccountMeta<'a>> {
        &self.accounts
    }
}

impl<'a> ShrinkCollectRefs<'a> for ShrinkCollectAliveSeparatedByRefs<'a> {
    fn collect(&mut self, other: Self) {
        self.one_ref.collect(other.one_ref);
        self.many_refs_this_is_newest_alive
            .collect(other.many_refs_this_is_newest_alive);
        self.many_refs_old_alive.collect(other.many_refs_old_alive);
    }
    fn with_capacity(capacity: usize, slot: Slot) -> Self {
        Self {
            one_ref: AliveAccounts::with_capacity(capacity, slot),
            many_refs_this_is_newest_alive: AliveAccounts::with_capacity(0, slot),
            many_refs_old_alive: AliveAccounts::with_capacity(0, slot),
        }
    }
    fn add(
        &mut self,
        ref_count: u64,
        account: &'a StoredAccountMeta<'a>,
        slot_list: &[(Slot, AccountInfo)],
    ) {
        let other = if ref_count == 1 {
            &mut self.one_ref
        } else if slot_list.len() == 1
            || !slot_list
                .iter()
                .any(|(slot_list_slot, _info)| slot_list_slot > &self.many_refs_old_alive.slot)
        {
            // this entry is alive but is newer than any other slot in the index
            &mut self.many_refs_this_is_newest_alive
        } else {
            // This entry is alive but is older than at least one other slot in the index.
            // We would expect clean to get rid of the entry for THIS slot at some point, but clean hasn't done that yet.
            &mut self.many_refs_old_alive
        };
        other.add(ref_count, account, slot_list);
    }
    fn len(&self) -> usize {
        self.one_ref
            .len()
            .saturating_add(self.many_refs_old_alive.len())
            .saturating_add(self.many_refs_this_is_newest_alive.len())
    }
    fn alive_bytes(&self) -> usize {
        self.one_ref
            .alive_bytes()
            .saturating_add(self.many_refs_old_alive.alive_bytes())
            .saturating_add(self.many_refs_this_is_newest_alive.alive_bytes())
    }
    fn alive_accounts(&self) -> &Vec<&'a StoredAccountMeta<'a>> {
        unimplemented!("illegal use");
    }
}

pub enum StoreReclaims {
    /// normal reclaim mode
    Default,
    /// do not return reclaims from accounts index upsert
    Ignore,
}

/// while combining into ancient append vecs, we need to keep track of the current one that is receiving new data
/// The pattern for callers is:
/// 1. this is a mut local
/// 2. do some version of create/new
/// 3. use it (slot, append_vec, etc.)
/// 4. re-create it sometimes
/// 5. goto 3
/// If a caller uses it before initializing it, it will be a runtime unwrap() error, similar to an assert.
/// That condition is an illegal use pattern and is justifiably an assertable condition.
#[derive(Default)]
struct CurrentAncientAppendVec {
    slot_and_append_vec: Option<(Slot, Arc<AccountStorageEntry>)>,
}

impl CurrentAncientAppendVec {
    fn new(slot: Slot, append_vec: Arc<AccountStorageEntry>) -> CurrentAncientAppendVec {
        Self {
            slot_and_append_vec: Some((slot, append_vec)),
        }
    }

    /// Create ancient append vec for a slot
    ///     min_bytes: the new append vec needs to have at least this capacity
    #[must_use]
    fn create_ancient_append_vec<'a>(
        &mut self,
        slot: Slot,
        db: &'a AccountsDb,
        min_bytes: usize,
    ) -> ShrinkInProgress<'a> {
        let size = get_ancient_append_vec_capacity().max(min_bytes as u64);
        let shrink_in_progress = db.get_store_for_shrink(slot, size);
        *self = Self::new(slot, Arc::clone(shrink_in_progress.new_storage()));
        shrink_in_progress
    }
    #[must_use]
    fn create_if_necessary<'a>(
        &mut self,
        slot: Slot,
        db: &'a AccountsDb,
        min_bytes: usize,
    ) -> Option<ShrinkInProgress<'a>> {
        if self.slot_and_append_vec.is_none() {
            Some(self.create_ancient_append_vec(slot, db, min_bytes))
        } else {
            None
        }
    }

    /// note this requires that 'slot_and_append_vec' is Some
    fn slot(&self) -> Slot {
        self.slot_and_append_vec.as_ref().unwrap().0
    }

    /// note this requires that 'slot_and_append_vec' is Some
    fn append_vec(&self) -> &Arc<AccountStorageEntry> {
        &self.slot_and_append_vec.as_ref().unwrap().1
    }

    /// helper function to cleanup call to 'store_accounts_frozen'
    /// return timing and bytes written
    fn store_ancient_accounts(
        &self,
        db: &AccountsDb,
        accounts_to_store: &AccountsToStore,
        storage_selector: StorageSelector,
    ) -> (StoreAccountsTiming, u64) {
        let accounts = accounts_to_store.get(storage_selector);

        let previous_available = self.append_vec().accounts.remaining_bytes();
        let timing = db.store_accounts_frozen(
            (self.slot(), accounts, accounts_to_store.slot()),
            None::<Vec<AccountHash>>,
            self.append_vec(),
            None,
            StoreReclaims::Ignore,
        );
        let bytes_written =
            previous_available.saturating_sub(self.append_vec().accounts.remaining_bytes());
        assert_eq!(
            bytes_written,
            u64_align!(accounts_to_store.get_bytes(storage_selector)) as u64
        );

        (timing, bytes_written)
    }
}

/// specifies how to return zero lamport accounts from a load
#[derive(Clone, Copy)]
enum LoadZeroLamports {
    /// return None if loaded account has zero lamports
    None,
    /// return Some(account with zero lamports) if loaded account has zero lamports
    /// This used to be the only behavior.
    /// Note that this is non-deterministic if clean is running asynchronously.
    /// If a zero lamport account exists in the index, then Some is returned.
    /// Once it is cleaned from the index, None is returned.
    #[cfg(feature = "dev-context-only-utils")]
    SomeWithZeroLamportAccountForTests,
}

#[derive(Debug)]
struct AncientSlotPubkeysInner {
    pubkeys: HashSet<Pubkey>,
    slot: Slot,
}

#[derive(Debug, Default)]
struct AncientSlotPubkeys {
    inner: Option<AncientSlotPubkeysInner>,
}

impl AncientSlotPubkeys {
    /// All accounts in 'slot' will be moved to 'current_ancient'
    /// If 'slot' is different than the 'current_ancient'.slot, then an account in 'slot' may ALREADY be in the current ancient append vec.
    /// In that case, we need to unref the pubkey because it will now only be referenced from 'current_ancient'.slot and no longer from 'slot'.
    /// 'self' is also changed to accumulate the pubkeys that now exist in 'current_ancient'
    /// When 'slot' differs from the previous inner slot, then we have moved to a new ancient append vec, and inner.pubkeys gets reset to the
    ///  pubkeys in the new 'current_ancient'.append_vec
    fn maybe_unref_accounts_already_in_ancient(
        &mut self,
        slot: Slot,
        db: &AccountsDb,
        current_ancient: &CurrentAncientAppendVec,
        to_store: &AccountsToStore,
    ) {
        if slot != current_ancient.slot() {
            // we are taking accounts from 'slot' and putting them into 'current_ancient.slot()'
            // StorageSelector::Primary here because only the accounts that are moving from 'slot' to 'current_ancient.slot()'
            // Any overflow accounts will get written into a new append vec AT 'slot', so they don't need to be unrefed
            let accounts = to_store.get(StorageSelector::Primary);
            if Some(current_ancient.slot()) != self.inner.as_ref().map(|ap| ap.slot) {
                let pubkeys = current_ancient
                    .append_vec()
                    .accounts
                    .account_iter()
                    .map(|account| *account.pubkey())
                    .collect::<HashSet<_>>();
                self.inner = Some(AncientSlotPubkeysInner {
                    pubkeys,
                    slot: current_ancient.slot(),
                });
            }
            // accounts in 'slot' but ALSO already in the ancient append vec at a different slot need to be unref'd since 'slot' is going away
            // unwrap cannot fail because the code above will cause us to set it to Some(...) if it is None
            db.unref_accounts_already_in_storage(
                accounts,
                self.inner.as_mut().map(|p| &mut p.pubkeys).unwrap(),
            );
        }
    }
}

#[derive(Debug)]
pub(crate) struct ShrinkCollect<'a, T: ShrinkCollectRefs<'a>> {
    pub(crate) slot: Slot,
    pub(crate) capacity: u64,
    pub(crate) unrefed_pubkeys: Vec<&'a Pubkey>,
    pub(crate) alive_accounts: T,
    /// total size in storage of all alive accounts
    pub(crate) alive_total_bytes: usize,
    pub(crate) total_starting_accounts: usize,
    /// true if all alive accounts are zero lamports
    pub(crate) all_are_zero_lamports: bool,
    /// index entries that need to be held in memory while shrink is in progress
    /// These aren't read - they are just held so that entries cannot be flushed.
    pub(crate) _index_entries_being_shrunk: Vec<AccountMapEntry<AccountInfo>>,
}

pub const ACCOUNTS_DB_CONFIG_FOR_TESTING: AccountsDbConfig = AccountsDbConfig {
    index: Some(ACCOUNTS_INDEX_CONFIG_FOR_TESTING),
    base_working_path: None,
    accounts_hash_cache_path: None,
    write_cache_limit_bytes: None,
    ancient_append_vec_offset: None,
    skip_initial_hash_calc: false,
    exhaustively_verify_refcounts: false,
    create_ancient_storage: CreateAncientStorage::Pack,
    test_partitioned_epoch_rewards: TestPartitionedEpochRewards::CompareResults,
    test_skip_rewrites_but_include_in_bank_hash: false,
};
pub const ACCOUNTS_DB_CONFIG_FOR_BENCHMARKS: AccountsDbConfig = AccountsDbConfig {
    index: Some(ACCOUNTS_INDEX_CONFIG_FOR_BENCHMARKS),
    base_working_path: None,
    accounts_hash_cache_path: None,
    write_cache_limit_bytes: None,
    ancient_append_vec_offset: None,
    skip_initial_hash_calc: false,
    exhaustively_verify_refcounts: false,
    create_ancient_storage: CreateAncientStorage::Pack,
    test_partitioned_epoch_rewards: TestPartitionedEpochRewards::None,
    test_skip_rewrites_but_include_in_bank_hash: false,
};

pub type BinnedHashData = Vec<Vec<CalculateHashIntermediate>>;

struct LoadAccountsIndexForShrink<'a, T: ShrinkCollectRefs<'a>> {
    /// all alive accounts
    alive_accounts: T,
    /// pubkeys that were unref'd in the accounts index because they were dead
    unrefed_pubkeys: Vec<&'a Pubkey>,
    /// true if all alive accounts are zero lamport accounts
    all_are_zero_lamports: bool,
    /// index entries we need to hold onto to keep them from getting flushed
    index_entries_being_shrunk: Vec<AccountMapEntry<AccountInfo>>,
}

pub struct GetUniqueAccountsResult<'a> {
    pub stored_accounts: Vec<StoredAccountMeta<'a>>,
    pub capacity: u64,
}

pub struct AccountsAddRootTiming {
    pub index_us: u64,
    pub cache_us: u64,
    pub store_us: u64,
}

const ANCIENT_APPEND_VEC_DEFAULT_OFFSET: Option<i64> = Some(-10_000);

#[derive(Debug, Default, Clone)]
pub struct AccountsDbConfig {
    pub index: Option<AccountsIndexConfig>,
    /// Base directory for various necessary files
    pub base_working_path: Option<PathBuf>,
    pub accounts_hash_cache_path: Option<PathBuf>,
    pub write_cache_limit_bytes: Option<u64>,
    /// if None, ancient append vecs are set to ANCIENT_APPEND_VEC_DEFAULT_OFFSET
    /// Some(offset) means include slots up to (max_slot - (slots_per_epoch - 'offset'))
    pub ancient_append_vec_offset: Option<i64>,
    pub test_skip_rewrites_but_include_in_bank_hash: bool,
    pub skip_initial_hash_calc: bool,
    pub exhaustively_verify_refcounts: bool,
    /// how to create ancient storages
    pub create_ancient_storage: CreateAncientStorage,
    pub test_partitioned_epoch_rewards: TestPartitionedEpochRewards,
}

#[cfg(not(test))]
const ABSURD_CONSECUTIVE_FAILED_ITERATIONS: usize = 100;

#[derive(Debug, Clone, Copy)]
pub enum AccountShrinkThreshold {
    /// Measure the total space sparseness across all candidates
    /// And select the candidates by using the top sparse account storage entries to shrink.
    /// The value is the overall shrink threshold measured as ratio of the total live bytes
    /// over the total bytes.
    TotalSpace { shrink_ratio: f64 },
    /// Use the following option to shrink all stores whose alive ratio is below
    /// the specified threshold.
    IndividualStore { shrink_ratio: f64 },
}
pub const DEFAULT_ACCOUNTS_SHRINK_OPTIMIZE_TOTAL_SPACE: bool = true;
pub const DEFAULT_ACCOUNTS_SHRINK_RATIO: f64 = 0.80;
// The default extra account space in percentage from the ideal target
const DEFAULT_ACCOUNTS_SHRINK_THRESHOLD_OPTION: AccountShrinkThreshold =
    AccountShrinkThreshold::TotalSpace {
        shrink_ratio: DEFAULT_ACCOUNTS_SHRINK_RATIO,
    };

impl Default for AccountShrinkThreshold {
    fn default() -> AccountShrinkThreshold {
        DEFAULT_ACCOUNTS_SHRINK_THRESHOLD_OPTION
    }
}

pub enum ScanStorageResult<R, B> {
    Cached(Vec<R>),
    Stored(B),
}

#[derive(Debug, Default)]
pub struct IndexGenerationInfo {
    pub accounts_data_len: u64,
    pub rent_paying_accounts_by_partition: RentPayingAccountsByPartition,
}

#[derive(Debug, Default)]
struct SlotIndexGenerationInfo {
    insert_time_us: u64,
    num_accounts: u64,
    num_accounts_rent_paying: usize,
    accounts_data_len: u64,
    amount_to_top_off_rent: u64,
    rent_paying_accounts_by_partition: Vec<Pubkey>,
}

#[derive(Default, Debug)]
struct GenerateIndexTimings {
    pub total_time_us: u64,
    pub index_time: u64,
    pub scan_time: u64,
    pub insertion_time_us: u64,
    pub min_bin_size: usize,
    pub max_bin_size: usize,
    pub total_items: usize,
    pub storage_size_storages_us: u64,
    pub index_flush_us: u64,
    pub rent_paying: AtomicUsize,
    pub amount_to_top_off_rent: AtomicU64,
    pub total_including_duplicates: u64,
    pub accounts_data_len_dedup_time_us: u64,
    pub total_duplicate_slot_keys: u64,
    pub populate_duplicate_keys_us: u64,
    pub total_slots: u64,
    pub slots_to_clean: u64,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct StorageSizeAndCount {
    /// total size stored, including both alive and dead bytes
    pub stored_size: usize,
    /// number of accounts in the storage including both alive and dead accounts
    pub count: usize,
}
type StorageSizeAndCountMap = DashMap<AppendVecId, StorageSizeAndCount>;

impl GenerateIndexTimings {
    pub fn report(&self, startup_stats: &StartupStats) {
        datapoint_info!(
            "generate_index",
            ("overall_us", self.total_time_us, i64),
            // we cannot accurately measure index insertion time because of many threads and lock contention
            ("total_us", self.index_time, i64),
            ("scan_stores_us", self.scan_time, i64),
            ("insertion_time_us", self.insertion_time_us, i64),
            ("min_bin_size", self.min_bin_size as i64, i64),
            ("max_bin_size", self.max_bin_size as i64, i64),
            (
                "storage_size_storages_us",
                self.storage_size_storages_us as i64,
                i64
            ),
            ("index_flush_us", self.index_flush_us as i64, i64),
            (
                "total_rent_paying",
                self.rent_paying.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "amount_to_top_off_rent",
                self.amount_to_top_off_rent.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_items_including_duplicates",
                self.total_including_duplicates as i64,
                i64
            ),
            ("total_items", self.total_items as i64, i64),
            (
                "accounts_data_len_dedup_time_us",
                self.accounts_data_len_dedup_time_us as i64,
                i64
            ),
            (
                "total_duplicate_slot_keys",
                self.total_duplicate_slot_keys as i64,
                i64
            ),
            (
                "populate_duplicate_keys_us",
                self.populate_duplicate_keys_us as i64,
                i64
            ),
            ("total_slots", self.total_slots, i64),
            ("slots_to_clean", self.slots_to_clean, i64),
            (
                "copy_data_us",
                startup_stats.copy_data_us.swap(0, Ordering::Relaxed),
                i64
            ),
        );
    }
}

impl IndexValue for AccountInfo {}
impl DiskIndexValue for AccountInfo {}

impl ZeroLamport for AccountSharedData {
    fn is_zero_lamport(&self) -> bool {
        self.lamports() == 0
    }
}

impl ZeroLamport for Account {
    fn is_zero_lamport(&self) -> bool {
        self.lamports() == 0
    }
}

struct MultiThreadProgress<'a> {
    last_update: Instant,
    my_last_report_count: u64,
    total_count: &'a AtomicU64,
    report_delay_secs: u64,
    first_caller: bool,
    ultimate_count: u64,
    start_time: Instant,
}

impl<'a> MultiThreadProgress<'a> {
    fn new(total_count: &'a AtomicU64, report_delay_secs: u64, ultimate_count: u64) -> Self {
        Self {
            last_update: Instant::now(),
            my_last_report_count: 0,
            total_count,
            report_delay_secs,
            first_caller: false,
            ultimate_count,
            start_time: Instant::now(),
        }
    }
    fn report(&mut self, my_current_count: u64) {
        let now = Instant::now();
        if now.duration_since(self.last_update).as_secs() >= self.report_delay_secs {
            let my_total_newly_processed_slots_since_last_report =
                my_current_count - self.my_last_report_count;

            self.my_last_report_count = my_current_count;
            let previous_total_processed_slots_across_all_threads = self.total_count.fetch_add(
                my_total_newly_processed_slots_since_last_report,
                Ordering::Relaxed,
            );
            self.first_caller =
                self.first_caller || 0 == previous_total_processed_slots_across_all_threads;
            if self.first_caller {
                let total = previous_total_processed_slots_across_all_threads
                    + my_total_newly_processed_slots_since_last_report;
                info!(
                    "generating index: {}/{} slots... ({}/s)",
                    total,
                    self.ultimate_count,
                    total / self.start_time.elapsed().as_secs().max(1),
                );
            }
            self.last_update = now;
        }
    }
}

/// An offset into the AccountsDb::storage vector
pub type AtomicAppendVecId = AtomicU32;
pub type AppendVecId = u32;

type AccountSlots = HashMap<Pubkey, HashSet<Slot>>;
type SlotOffsets = HashMap<Slot, HashSet<usize>>;
type ReclaimResult = (AccountSlots, SlotOffsets);
type PubkeysRemovedFromAccountsIndex = HashSet<Pubkey>;
type ShrinkCandidates = IntSet<Slot>;

// Some hints for applicability of additional sanity checks for the do_load fast-path;
// Slower fallback code path will be taken if the fast path has failed over the retry
// threshold, regardless of these hints. Also, load cannot fail not-deterministically
// even under very rare circumstances, unlike previously did allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadHint {
    // Caller hints that it's loading transactions for a block which is
    // descended from the current root, and at the tip of its fork.
    // Thereby, further this assumes AccountIndex::max_root should not increase
    // during this load, meaning there should be no squash.
    // Overall, this enables us to assert!() strictly while running the fast-path for
    // account loading, while maintaining the determinism of account loading and resultant
    // transaction execution thereof.
    FixedMaxRoot,
    // Caller can't hint the above safety assumption. Generally RPC and miscellaneous
    // other call-site falls into this category. The likelihood of slower path is slightly
    // increased as well.
    Unspecified,
}

#[derive(Debug)]
pub enum LoadedAccountAccessor<'a> {
    // StoredAccountMeta can't be held directly here due to its lifetime dependency to
    // AccountStorageEntry
    Stored(Option<(Arc<AccountStorageEntry>, usize)>),
    // None value in Cached variant means the cache was flushed
    Cached(Option<Cow<'a, CachedAccount>>),
}

mod geyser_plugin_utils;

impl<'a> LoadedAccountAccessor<'a> {
    fn check_and_get_loaded_account(&mut self) -> LoadedAccount {
        // all of these following .expect() and .unwrap() are like serious logic errors,
        // ideal for representing this as rust type system....

        match self {
            LoadedAccountAccessor::Cached(None) | LoadedAccountAccessor::Stored(None) => {
                panic!("Should have already been taken care of when creating this LoadedAccountAccessor");
            }
            LoadedAccountAccessor::Cached(Some(_cached_account)) => {
                // Cached(Some(x)) variant always produces `Some` for get_loaded_account() since
                // it just returns the inner `x` without additional fetches
                self.get_loaded_account().unwrap()
            }
            LoadedAccountAccessor::Stored(Some(_maybe_storage_entry)) => {
                // If we do find the storage entry, we can guarantee that the storage entry is
                // safe to read from because we grabbed a reference to the storage entry while it
                // was still in the storage map. This means even if the storage entry is removed
                // from the storage map after we grabbed the storage entry, the recycler should not
                // reset the storage entry until we drop the reference to the storage entry.
                self.get_loaded_account()
                    .expect("If a storage entry was found in the storage map, it must not have been reset yet")
            }
        }
    }

    fn get_loaded_account(&mut self) -> Option<LoadedAccount> {
        match self {
            LoadedAccountAccessor::Cached(cached_account) => {
                let cached_account: Cow<'a, CachedAccount> = cached_account.take().expect(
                    "Cache flushed/purged should be handled before trying to fetch account",
                );
                Some(LoadedAccount::Cached(cached_account))
            }
            LoadedAccountAccessor::Stored(maybe_storage_entry) => {
                // storage entry may not be present if slot was cleaned up in
                // between reading the accounts index and calling this function to
                // get account meta from the storage entry here
                maybe_storage_entry
                    .as_ref()
                    .and_then(|(storage_entry, offset)| {
                        storage_entry
                            .get_stored_account_meta(*offset)
                            .map(LoadedAccount::Stored)
                    })
            }
        }
    }

    fn account_matches_owners(&self, owners: &[Pubkey]) -> Result<usize, MatchAccountOwnerError> {
        match self {
            LoadedAccountAccessor::Cached(cached_account) => cached_account
                .as_ref()
                .and_then(|cached_account| {
                    if cached_account.account.is_zero_lamport() {
                        None
                    } else {
                        owners
                            .iter()
                            .position(|entry| cached_account.account.owner() == entry)
                    }
                })
                .ok_or(MatchAccountOwnerError::NoMatch),
            LoadedAccountAccessor::Stored(maybe_storage_entry) => {
                // storage entry may not be present if slot was cleaned up in
                // between reading the accounts index and calling this function to
                // get account meta from the storage entry here
                maybe_storage_entry
                    .as_ref()
                    .map(|(storage_entry, offset)| {
                        storage_entry
                            .accounts
                            .account_matches_owners(*offset, owners)
                    })
                    .unwrap_or(Err(MatchAccountOwnerError::UnableToLoad))
            }
        }
    }
}

pub enum LoadedAccount<'a> {
    Stored(StoredAccountMeta<'a>),
    Cached(Cow<'a, CachedAccount>),
}

impl<'a> LoadedAccount<'a> {
    pub fn loaded_hash(&self) -> AccountHash {
        match self {
            LoadedAccount::Stored(stored_account_meta) => *stored_account_meta.hash(),
            LoadedAccount::Cached(cached_account) => cached_account.hash(),
        }
    }

    pub fn pubkey(&self) -> &Pubkey {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.pubkey(),
            LoadedAccount::Cached(cached_account) => cached_account.pubkey(),
        }
    }

    pub fn compute_hash(&self, pubkey: &Pubkey) -> AccountHash {
        match self {
            LoadedAccount::Stored(stored_account_meta) => {
                AccountsDb::hash_account(stored_account_meta, stored_account_meta.pubkey())
            }
            LoadedAccount::Cached(cached_account) => {
                AccountsDb::hash_account(&cached_account.account, pubkey)
            }
        }
    }

    pub fn take_account(self) -> AccountSharedData {
        match self {
            LoadedAccount::Stored(stored_account_meta) => {
                stored_account_meta.to_account_shared_data()
            }
            LoadedAccount::Cached(cached_account) => match cached_account {
                Cow::Owned(cached_account) => cached_account.account.clone(),
                Cow::Borrowed(cached_account) => cached_account.account.clone(),
            },
        }
    }

    pub fn is_cached(&self) -> bool {
        match self {
            LoadedAccount::Stored(_) => false,
            LoadedAccount::Cached(_) => true,
        }
    }
}

impl<'a> ReadableAccount for LoadedAccount<'a> {
    fn lamports(&self) -> u64 {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.lamports(),
            LoadedAccount::Cached(cached_account) => cached_account.account.lamports(),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.data(),
            LoadedAccount::Cached(cached_account) => cached_account.account.data(),
        }
    }
    fn owner(&self) -> &Pubkey {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.owner(),
            LoadedAccount::Cached(cached_account) => cached_account.account.owner(),
        }
    }
    fn executable(&self) -> bool {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.executable(),
            LoadedAccount::Cached(cached_account) => cached_account.account.executable(),
        }
    }
    fn rent_epoch(&self) -> Epoch {
        match self {
            LoadedAccount::Stored(stored_account_meta) => stored_account_meta.rent_epoch(),
            LoadedAccount::Cached(cached_account) => cached_account.account.rent_epoch(),
        }
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        match self {
            LoadedAccount::Stored(_stored_account_meta) => AccountSharedData::create(
                self.lamports(),
                self.data().to_vec(),
                *self.owner(),
                self.executable(),
                self.rent_epoch(),
            ),
            // clone here to prevent data copy
            LoadedAccount::Cached(cached_account) => cached_account.account.clone(),
        }
    }
}

#[derive(Debug)]
pub enum AccountsHashVerificationError {
    MissingAccountsHash,
    MismatchedAccountsHash,
    MismatchedTotalLamports(u64, u64),
}

#[derive(Default)]
struct CleanKeyTimings {
    collect_delta_keys_us: u64,
    delta_insert_us: u64,
    hashset_to_vec_us: u64,
    dirty_store_processing_us: u64,
    delta_key_count: u64,
    dirty_pubkeys_count: u64,
    oldest_dirty_slot: Slot,
    /// number of ancient append vecs that were scanned because they were dirty when clean started
    dirty_ancient_stores: usize,
}

/// Persistent storage structure holding the accounts
#[derive(Debug)]
pub struct AccountStorageEntry {
    pub(crate) id: AtomicAppendVecId,

    pub(crate) slot: AtomicU64,

    /// storage holding the accounts
    pub accounts: AccountsFile,

    /// Keeps track of the number of accounts stored in a specific AppendVec.
    ///  This is periodically checked to reuse the stores that do not have
    ///  any accounts in it
    /// status corresponding to the storage, lets us know that
    ///  the append_vec, once maxed out, then emptied, can be reclaimed
    count_and_status: SeqLock<(usize, AccountStorageStatus)>,

    /// This is the total number of accounts stored ever since initialized to keep
    /// track of lifetime count of all store operations. And this differs from
    /// count_and_status in that this field won't be decremented.
    ///
    /// This is used as a rough estimate for slot shrinking. As such a relaxed
    /// use case, this value ARE NOT strictly synchronized with count_and_status!
    approx_store_count: AtomicUsize,

    alive_bytes: AtomicUsize,
}

impl AccountStorageEntry {
    pub fn new(path: &Path, slot: Slot, id: AppendVecId, file_size: u64) -> Self {
        let tail = AccountsFile::file_name(slot, id);
        let path = Path::new(path).join(tail);
        let accounts = AccountsFile::AppendVec(AppendVec::new(&path, true, file_size as usize));

        Self {
            id: AtomicAppendVecId::new(id),
            slot: AtomicU64::new(slot),
            accounts,
            count_and_status: SeqLock::new((0, AccountStorageStatus::Available)),
            approx_store_count: AtomicUsize::new(0),
            alive_bytes: AtomicUsize::new(0),
        }
    }

    pub fn new_existing(
        slot: Slot,
        id: AppendVecId,
        accounts: AccountsFile,
        num_accounts: usize,
    ) -> Self {
        Self {
            id: AtomicAppendVecId::new(id),
            slot: AtomicU64::new(slot),
            accounts,
            count_and_status: SeqLock::new((0, AccountStorageStatus::Available)),
            approx_store_count: AtomicUsize::new(num_accounts),
            alive_bytes: AtomicUsize::new(0),
        }
    }

    pub fn set_status(&self, mut status: AccountStorageStatus) {
        let mut count_and_status = self.count_and_status.lock_write();

        let count = count_and_status.0;

        if status == AccountStorageStatus::Full && count == 0 {
            // this case arises when the append_vec is full (store_ptrs fails),
            //  but all accounts have already been removed from the storage
            //
            // the only time it's safe to call reset() on an append_vec is when
            //  every account has been removed
            //          **and**
            //  the append_vec has previously been completely full
            //
            self.accounts.reset();
            status = AccountStorageStatus::Available;
        }

        *count_and_status = (count, status);
    }

    pub fn recycle(&self, slot: Slot, id: AppendVecId) {
        let mut count_and_status = self.count_and_status.lock_write();
        self.accounts.reset();
        *count_and_status = (0, AccountStorageStatus::Available);
        self.slot.store(slot, Ordering::Release);
        self.id.store(id, Ordering::Release);
        self.approx_store_count.store(0, Ordering::Relaxed);
        self.alive_bytes.store(0, Ordering::Release);
    }

    pub fn status(&self) -> AccountStorageStatus {
        self.count_and_status.read().1
    }

    pub fn count(&self) -> usize {
        self.count_and_status.read().0
    }

    pub fn approx_stored_count(&self) -> usize {
        self.approx_store_count.load(Ordering::Relaxed)
    }

    pub fn alive_bytes(&self) -> usize {
        self.alive_bytes.load(Ordering::SeqCst)
    }

    pub fn written_bytes(&self) -> u64 {
        self.accounts.len() as u64
    }

    pub fn capacity(&self) -> u64 {
        self.accounts.capacity()
    }

    pub fn has_accounts(&self) -> bool {
        self.count() > 0
    }

    pub fn slot(&self) -> Slot {
        self.slot.load(Ordering::Acquire)
    }

    pub fn append_vec_id(&self) -> AppendVecId {
        self.id.load(Ordering::Acquire)
    }

    pub fn flush(&self) -> Result<(), AccountsFileError> {
        self.accounts.flush()
    }

    fn get_stored_account_meta(&self, offset: usize) -> Option<StoredAccountMeta> {
        Some(self.accounts.get_account(offset)?.0)
    }

    fn add_account(&self, num_bytes: usize) {
        let mut count_and_status = self.count_and_status.lock_write();
        *count_and_status = (count_and_status.0 + 1, count_and_status.1);
        self.approx_store_count.fetch_add(1, Ordering::Relaxed);
        self.alive_bytes.fetch_add(num_bytes, Ordering::SeqCst);
    }

    fn try_available(&self) -> bool {
        let mut count_and_status = self.count_and_status.lock_write();
        let (count, status) = *count_and_status;

        if status == AccountStorageStatus::Available {
            *count_and_status = (count, AccountStorageStatus::Candidate);
            true
        } else {
            false
        }
    }

    pub fn all_accounts(&self) -> Vec<StoredAccountMeta> {
        self.accounts.accounts(0)
    }

    fn remove_account(&self, num_bytes: usize, reset_accounts: bool) -> usize {
        let mut count_and_status = self.count_and_status.lock_write();
        let (mut count, mut status) = *count_and_status;

        if count == 1 && status == AccountStorageStatus::Full && reset_accounts {
            // this case arises when we remove the last account from the
            //  storage, but we've learned from previous write attempts that
            //  the storage is full
            //
            // the only time it's safe to call reset() on an append_vec is when
            //  every account has been removed
            //          **and**
            //  the append_vec has previously been completely full
            //
            // otherwise, the storage may be in flight with a store()
            //   call
            self.accounts.reset();
            status = AccountStorageStatus::Available;
        }

        // Some code path is removing accounts too many; this may result in an
        // unintended reveal of old state for unrelated accounts.
        assert!(
            count > 0,
            "double remove of account in slot: {}/store: {}!!",
            self.slot(),
            self.append_vec_id(),
        );

        self.alive_bytes.fetch_sub(num_bytes, Ordering::SeqCst);
        count -= 1;
        *count_and_status = (count, status);
        count
    }

    pub fn get_path(&self) -> PathBuf {
        self.accounts.get_path()
    }
}

pub fn get_temp_accounts_paths(count: u32) -> IoResult<(Vec<TempDir>, Vec<PathBuf>)> {
    let temp_dirs: IoResult<Vec<TempDir>> = (0..count).map(|_| TempDir::new()).collect();
    let temp_dirs = temp_dirs?;

    let paths: IoResult<Vec<_>> = temp_dirs
        .iter()
        .map(|temp_dir| {
            utils::create_accounts_run_and_snapshot_dirs(temp_dir)
                .map(|(run_dir, _snapshot_dir)| run_dir)
        })
        .collect();
    let paths = paths?;
    Ok((temp_dirs, paths))
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct BankHashStats {
    pub num_updated_accounts: u64,
    pub num_removed_accounts: u64,
    pub num_lamports_stored: u64,
    pub total_data_len: u64,
    pub num_executable_accounts: u64,
}

impl BankHashStats {
    pub fn update<T: ReadableAccount + ZeroLamport>(&mut self, account: &T) {
        if account.is_zero_lamport() {
            self.num_removed_accounts += 1;
        } else {
            self.num_updated_accounts += 1;
        }
        self.total_data_len = self
            .total_data_len
            .wrapping_add(account.data().len() as u64);
        if account.executable() {
            self.num_executable_accounts += 1;
        }
        self.num_lamports_stored = self.num_lamports_stored.wrapping_add(account.lamports());
    }

    pub fn accumulate(&mut self, other: &BankHashStats) {
        self.num_updated_accounts += other.num_updated_accounts;
        self.num_removed_accounts += other.num_removed_accounts;
        self.total_data_len = self.total_data_len.wrapping_add(other.total_data_len);
        self.num_lamports_stored = self
            .num_lamports_stored
            .wrapping_add(other.num_lamports_stored);
        self.num_executable_accounts += other.num_executable_accounts;
    }
}

#[derive(Default, Debug)]
pub struct StoreAccountsTiming {
    store_accounts_elapsed: u64,
    update_index_elapsed: u64,
    handle_reclaims_elapsed: u64,
}

impl StoreAccountsTiming {
    fn accumulate(&mut self, other: &Self) {
        self.store_accounts_elapsed += other.store_accounts_elapsed;
        self.update_index_elapsed += other.update_index_elapsed;
        self.handle_reclaims_elapsed += other.handle_reclaims_elapsed;
    }
}

#[derive(Debug, Default)]
struct RecycleStores {
    entries: Vec<(Instant, Arc<AccountStorageEntry>)>,
    total_bytes: u64,
}

// 30 min should be enough to be certain there won't be any prospective recycle uses for given
// store entry
// That's because it already processed ~2500 slots and ~25 passes of AccountsBackgroundService
pub const EXPIRATION_TTL_SECONDS: u64 = 1800;

impl RecycleStores {
    fn add_entry(&mut self, new_entry: Arc<AccountStorageEntry>) {
        self.total_bytes += new_entry.capacity();
        self.entries.push((Instant::now(), new_entry))
    }

    fn iter(&self) -> std::slice::Iter<(Instant, Arc<AccountStorageEntry>)> {
        self.entries.iter()
    }

    fn add_entries(&mut self, new_entries: Vec<Arc<AccountStorageEntry>>) {
        let now = Instant::now();
        for new_entry in new_entries {
            self.total_bytes += new_entry.capacity();
            self.entries.push((now, new_entry));
        }
    }

    fn expire_old_entries(&mut self) -> Vec<Arc<AccountStorageEntry>> {
        let mut expired = vec![];
        let now = Instant::now();
        let mut expired_bytes = 0;
        self.entries.retain(|(recycled_time, entry)| {
            if now.duration_since(*recycled_time).as_secs() > EXPIRATION_TTL_SECONDS {
                if Arc::strong_count(entry) >= 2 {
                    warn!(
                        "Expiring still in-use recycled StorageEntry anyway...: id: {} slot: {}",
                        entry.append_vec_id(),
                        entry.slot(),
                    );
                }
                expired_bytes += entry.capacity();
                expired.push(entry.clone());
                false
            } else {
                true
            }
        });

        self.total_bytes -= expired_bytes;

        expired
    }

    fn remove_entry(&mut self, index: usize) -> Arc<AccountStorageEntry> {
        let (_added_time, removed_entry) = self.entries.swap_remove(index);
        self.total_bytes -= removed_entry.capacity();
        removed_entry
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Removing unrooted slots in Accounts Background Service needs to be synchronized with flushing
/// slots from the Accounts Cache.  This keeps track of those slots and the Mutex + Condvar for
/// synchronization.
#[derive(Debug, Default)]
struct RemoveUnrootedSlotsSynchronization {
    // slots being flushed from the cache or being purged
    slots_under_contention: Mutex<IntSet<Slot>>,
    signal: Condvar,
}

type AccountInfoAccountsIndex = AccountsIndex<AccountInfo, AccountInfo>;

// This structure handles the load/store of the accounts
#[derive(Debug)]
pub struct AccountsDb {
    /// Keeps tracks of index into AppendVec on a per slot basis
    pub accounts_index: AccountInfoAccountsIndex,

    /// Some(offset) iff we want to squash old append vecs together into 'ancient append vecs'
    /// Some(offset) means for slots up to (max_slot - (slots_per_epoch - 'offset')), put them in ancient append vecs
    pub ancient_append_vec_offset: Option<i64>,

    /// true iff we want to skip the initial hash calculation on startup
    pub skip_initial_hash_calc: bool,

    pub storage: AccountStorage,

    /// from AccountsDbConfig
    create_ancient_storage: CreateAncientStorage,

    /// true if this client should skip rewrites but still include those rewrites in the bank hash as if rewrites had occurred.
    pub test_skip_rewrites_but_include_in_bank_hash: bool,

    pub accounts_cache: AccountsCache,

    write_cache_limit_bytes: Option<u64>,

    sender_bg_hasher: Option<Sender<CachedAccount>>,
    read_only_accounts_cache: ReadOnlyAccountsCache,

    recycle_stores: RwLock<RecycleStores>,

    /// distribute the accounts across storage lists
    pub next_id: AtomicAppendVecId,

    /// Set of shrinkable stores organized by map of slot to append_vec_id
    pub shrink_candidate_slots: Mutex<ShrinkCandidates>,

    pub write_version: AtomicU64,

    /// Set of storage paths to pick from
    pub paths: Vec<PathBuf>,

    /// Base directory for various necessary files
    base_working_path: PathBuf,
    // used by tests - held until we are dropped
    #[allow(dead_code)]
    base_working_temp_dir: Option<TempDir>,

    accounts_hash_cache_path: PathBuf,

    pub shrink_paths: RwLock<Option<Vec<PathBuf>>>,

    /// Directory of paths this accounts_db needs to hold/remove
    #[allow(dead_code)]
    pub temp_paths: Option<Vec<TempDir>>,

    /// Starting file size of appendvecs
    file_size: u64,

    /// Thread pool used for par_iter
    pub thread_pool: ThreadPool,

    pub thread_pool_clean: ThreadPool,

    bank_hash_stats: Mutex<HashMap<Slot, BankHashStats>>,
    accounts_delta_hashes: Mutex<HashMap<Slot, AccountsDeltaHash>>,
    accounts_hashes: Mutex<HashMap<Slot, (AccountsHash, /*capitalization*/ u64)>>,
    incremental_accounts_hashes:
        Mutex<HashMap<Slot, (IncrementalAccountsHash, /*capitalization*/ u64)>>,

    pub stats: AccountsStats,

    clean_accounts_stats: CleanAccountsStats,

    // Stats for purges called outside of clean_accounts()
    external_purge_slots_stats: PurgeStats,

    pub shrink_stats: ShrinkStats,

    pub(crate) shrink_ancient_stats: ShrinkAncientStats,

    pub cluster_type: Option<ClusterType>,

    pub account_indexes: AccountSecondaryIndexes,

    /// Set of unique keys per slot which is used
    /// to drive clean_accounts
    /// Generated by calculate_accounts_delta_hash
    uncleaned_pubkeys: DashMap<Slot, Vec<Pubkey>>,

    #[cfg(test)]
    load_delay: u64,

    #[cfg(test)]
    load_limit: AtomicU64,

    /// true if drop_callback is attached to the bank.
    is_bank_drop_callback_enabled: AtomicBool,

    /// Set of slots currently being flushed by `flush_slot_cache()` or removed
    /// by `remove_unrooted_slot()`. Used to ensure `remove_unrooted_slots(slots)`
    /// can safely clear the set of unrooted slots `slots`.
    remove_unrooted_slots_synchronization: RemoveUnrootedSlotsSynchronization,

    shrink_ratio: AccountShrinkThreshold,

    /// Set of stores which are recently rooted or had accounts removed
    /// such that potentially a 0-lamport account update could be present which
    /// means we can remove the account from the index entirely.
    dirty_stores: DashMap<Slot, Arc<AccountStorageEntry>>,

    /// Zero-lamport accounts that are *not* purged during clean because they need to stay alive
    /// for incremental snapshot support.
    zero_lamport_accounts_to_purge_after_full_snapshot: DashSet<(Slot, Pubkey)>,

    /// GeyserPlugin accounts update notifier
    accounts_update_notifier: Option<AccountsUpdateNotifier>,

    pub(crate) active_stats: ActiveStats,

    pub verify_accounts_hash_in_bg: VerifyAccountsHashInBackground,

    /// Used to disable logging dead slots during removal.
    /// allow disabling noisy log
    pub log_dead_slots: AtomicBool,

    /// debug feature to scan every append vec and verify refcounts are equal
    exhaustively_verify_refcounts: bool,

    /// this will live here until the feature for partitioned epoch rewards is activated.
    /// At that point, this and other code can be deleted.
    pub partitioned_epoch_rewards_config: PartitionedEpochRewardsConfig,

    /// the full accounts hash calculation as of a predetermined block height 'N'
    /// to be included in the bank hash at a predetermined block height 'M'
    /// The cadence is once per epoch, all nodes calculate a full accounts hash as of a known slot calculated using 'N'
    /// Some time later (to allow for slow calculation time), the bank hash at a slot calculated using 'M' includes the full accounts hash.
    /// Thus, the state of all accounts on a validator is known to be correct at least once per epoch.
    pub epoch_accounts_hash_manager: EpochAccountsHashManager,
}

#[derive(Debug, Default)]
pub struct AccountsStats {
    delta_hash_scan_time_total_us: AtomicU64,
    delta_hash_accumulate_time_total_us: AtomicU64,
    delta_hash_num: AtomicU64,
    skipped_rewrites_num: AtomicUsize,

    last_store_report: AtomicInterval,
    store_hash_accounts: AtomicU64,
    calc_stored_meta: AtomicU64,
    store_accounts: AtomicU64,
    store_update_index: AtomicU64,
    store_handle_reclaims: AtomicU64,
    store_append_accounts: AtomicU64,
    pub stakes_cache_check_and_store_us: AtomicU64,
    store_num_accounts: AtomicU64,
    store_total_data: AtomicU64,
    recycle_store_count: AtomicU64,
    create_store_count: AtomicU64,
    store_get_slot_store: AtomicU64,
    store_find_existing: AtomicU64,
    dropped_stores: AtomicU64,
    store_uncleaned_update: AtomicU64,
    handle_dead_keys_us: AtomicU64,
    purge_exact_us: AtomicU64,
    purge_exact_count: AtomicU64,
}

#[derive(Debug, Default)]
pub struct PurgeStats {
    last_report: AtomicInterval,
    safety_checks_elapsed: AtomicU64,
    remove_cache_elapsed: AtomicU64,
    remove_storage_entries_elapsed: AtomicU64,
    drop_storage_entries_elapsed: AtomicU64,
    num_cached_slots_removed: AtomicUsize,
    num_stored_slots_removed: AtomicUsize,
    total_removed_storage_entries: AtomicUsize,
    total_removed_cached_bytes: AtomicU64,
    total_removed_stored_bytes: AtomicU64,
    recycle_stores_write_elapsed: AtomicU64,
    scan_storages_elapsed: AtomicU64,
    purge_accounts_index_elapsed: AtomicU64,
    handle_reclaims_elapsed: AtomicU64,
}

impl PurgeStats {
    fn report(&self, metric_name: &'static str, report_interval_ms: Option<u64>) {
        let should_report = report_interval_ms
            .map(|report_interval_ms| self.last_report.should_update(report_interval_ms))
            .unwrap_or(true);

        if should_report {
            datapoint_info!(
                metric_name,
                (
                    "safety_checks_elapsed",
                    self.safety_checks_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "remove_cache_elapsed",
                    self.remove_cache_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "remove_storage_entries_elapsed",
                    self.remove_storage_entries_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "drop_storage_entries_elapsed",
                    self.drop_storage_entries_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "num_cached_slots_removed",
                    self.num_cached_slots_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "num_stored_slots_removed",
                    self.num_stored_slots_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_storage_entries",
                    self.total_removed_storage_entries
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_cached_bytes",
                    self.total_removed_cached_bytes.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "total_removed_stored_bytes",
                    self.total_removed_stored_bytes.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "recycle_stores_write_elapsed",
                    self.recycle_stores_write_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "scan_storages_elapsed",
                    self.scan_storages_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "purge_accounts_index_elapsed",
                    self.purge_accounts_index_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "handle_reclaims_elapsed",
                    self.handle_reclaims_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
            );
        }
    }
}

/// results from 'split_storages_ancient'
#[derive(Debug, Default, PartialEq)]
struct SplitAncientStorages {
    /// # ancient slots
    ancient_slot_count: usize,
    /// the specific ancient slots
    ancient_slots: Vec<Slot>,
    /// lowest slot that is not an ancient append vec
    first_non_ancient_slot: Slot,
    /// slot # of beginning of first aligned chunk starting from the first non ancient slot
    first_chunk_start: Slot,
    /// # non-ancient slots to scan
    non_ancient_slot_count: usize,
    /// # chunks to use to iterate the storages
    /// all ancient chunks, the special 0 and last chunks for non-full chunks, and all the 'full' chunks of normal slots
    chunk_count: usize,
    /// start and end(exclusive) of normal (non-ancient) slots to be scanned
    normal_slot_range: Range<Slot>,
}

impl SplitAncientStorages {
    /// When calculating accounts hash, we break the slots/storages into chunks that remain the same during an entire epoch.
    /// a slot is in this chunk of slots:
    /// start:         (slot / MAX_ITEMS_PER_CHUNK) * MAX_ITEMS_PER_CHUNK
    /// end_exclusive: start + MAX_ITEMS_PER_CHUNK
    /// So a slot remains in the same chunk whenever it is included in the accounts hash.
    /// When the slot gets deleted or gets consumed in an ancient append vec, it will no longer be in its chunk.
    /// The results of scanning a chunk of appendvecs can be cached to avoid scanning large amounts of data over and over.
    fn new(oldest_non_ancient_slot: Option<Slot>, snapshot_storages: &SortedStorages) -> Self {
        let range = snapshot_storages.range();

        let (ancient_slots, first_non_ancient_slot) = if let Some(oldest_non_ancient_slot) =
            oldest_non_ancient_slot
        {
            // any ancient append vecs should definitely be cached
            // We need to break the ranges into:
            // 1. individual ancient append vecs (may be empty)
            // 2. first unevenly divided chunk starting at 1 epoch old slot (may be empty)
            // 3. evenly divided full chunks in the middle
            // 4. unevenly divided chunk of most recent slots (may be empty)
            let ancient_slots =
                Self::get_ancient_slots(oldest_non_ancient_slot, snapshot_storages, |storage| {
                    storage.capacity() > get_ancient_append_vec_capacity() * 50 / 100
                });

            let first_non_ancient_slot = ancient_slots
                .last()
                .map(|last_ancient_slot| last_ancient_slot.saturating_add(1))
                .unwrap_or(range.start);

            (ancient_slots, first_non_ancient_slot)
        } else {
            (vec![], range.start)
        };

        Self::new_with_ancient_info(range, ancient_slots, first_non_ancient_slot)
    }

    /// return all ancient append vec slots from the early slots referenced by 'snapshot_storages'
    /// `treat_as_ancient` returns true if the storage at this slot is large and should be treated individually by accounts hash calculation.
    /// `treat_as_ancient` is a fn so that we can test this well. Otherwise, we have to generate large append vecs to pass the intended checks.
    fn get_ancient_slots(
        oldest_non_ancient_slot: Slot,
        snapshot_storages: &SortedStorages,
        treat_as_ancient: impl Fn(&AccountStorageEntry) -> bool,
    ) -> Vec<Slot> {
        let range = snapshot_storages.range();
        let mut i = 0;
        let mut len_truncate = 0;
        let mut possible_ancient_slots = snapshot_storages
            .iter_range(&(range.start..oldest_non_ancient_slot))
            .filter_map(|(slot, storage)| {
                storage.map(|storage| {
                    i += 1;
                    if treat_as_ancient(storage) {
                        // even though the slot is in range of being an ancient append vec, if it isn't actually a large append vec,
                        // then we are better off treating all these slots as normally cachable to reduce work in dedup.
                        // Since this one is large, for the moment, this one becomes the highest slot where we want to individually cache files.
                        len_truncate = i;
                    }
                    slot
                })
            })
            .collect::<Vec<_>>();
        possible_ancient_slots.truncate(len_truncate);
        possible_ancient_slots
    }

    /// create once ancient slots have been identified
    /// This is easier to test, removing SortedStorages as a type to deal with here.
    fn new_with_ancient_info(
        range: &Range<Slot>,
        ancient_slots: Vec<Slot>,
        first_non_ancient_slot: Slot,
    ) -> Self {
        if range.is_empty() {
            // Corner case mainly for tests, but gives us a consistent base case. Makes more sense to return default here than anything else.
            // caller is asking to split for empty set of slots
            return SplitAncientStorages::default();
        }

        let max_slot_inclusive = range.end.saturating_sub(1);
        let ancient_slot_count = ancient_slots.len();
        let first_chunk_start = ((first_non_ancient_slot + MAX_ITEMS_PER_CHUNK)
            / MAX_ITEMS_PER_CHUNK)
            * MAX_ITEMS_PER_CHUNK;

        let non_ancient_slot_count = (max_slot_inclusive - first_non_ancient_slot + 1) as usize;

        let normal_slot_range = Range {
            start: first_non_ancient_slot,
            end: range.end,
        };

        // 2 is for 2 special chunks - unaligned slots at the beginning and end
        let chunk_count =
            ancient_slot_count + 2 + non_ancient_slot_count / (MAX_ITEMS_PER_CHUNK as usize);

        SplitAncientStorages {
            ancient_slot_count,
            ancient_slots,
            first_non_ancient_slot,
            first_chunk_start,
            non_ancient_slot_count,
            chunk_count,
            normal_slot_range,
        }
    }

    /// given 'normal_chunk', return the starting slot of that chunk in the normal/non-ancient range
    /// a normal_chunk is 0<=normal_chunk<=non_ancient_chunk_count
    /// non_ancient_chunk_count is chunk_count-ancient_slot_count
    fn get_starting_slot_from_normal_chunk(&self, normal_chunk: usize) -> Slot {
        if normal_chunk == 0 {
            self.normal_slot_range.start
        } else {
            assert!(
                normal_chunk.saturating_add(self.ancient_slot_count) < self.chunk_count,
                "out of bounds: {}, {}",
                normal_chunk,
                self.chunk_count
            );

            let normal_chunk = normal_chunk.saturating_sub(1);
            (self.first_chunk_start + MAX_ITEMS_PER_CHUNK * (normal_chunk as Slot))
                .max(self.normal_slot_range.start)
        }
    }

    /// ancient slots are the first chunks
    fn is_chunk_ancient(&self, chunk: usize) -> bool {
        chunk < self.ancient_slot_count
    }

    /// given chunk in 0<=chunk<self.chunk_count
    /// return the range of slots in that chunk
    /// None indicates the range is empty for that chunk.
    fn get_slot_range(&self, chunk: usize) -> Option<Range<Slot>> {
        let range = if self.is_chunk_ancient(chunk) {
            // ancient append vecs are handled individually
            let slot = self.ancient_slots[chunk];
            Range {
                start: slot,
                end: slot + 1,
            }
        } else {
            // normal chunks are after ancient chunks
            let normal_chunk = chunk - self.ancient_slot_count;
            if normal_chunk == 0 {
                // first slot
                Range {
                    start: self.normal_slot_range.start,
                    end: self.first_chunk_start.min(self.normal_slot_range.end),
                }
            } else {
                // normal full chunk or the last chunk
                let first_slot = self.get_starting_slot_from_normal_chunk(normal_chunk);
                Range {
                    start: first_slot,
                    end: (first_slot + MAX_ITEMS_PER_CHUNK).min(self.normal_slot_range.end),
                }
            }
        };
        // return empty range as None
        (!range.is_empty()).then_some(range)
    }
}

#[derive(Debug, Default)]
struct FlushStats {
    num_flushed: usize,
    num_purged: usize,
    total_size: u64,
}

#[derive(Debug, Default)]
struct LatestAccountsIndexRootsStats {
    roots_len: AtomicUsize,
    uncleaned_roots_len: AtomicUsize,
    roots_range: AtomicU64,
    rooted_cleaned_count: AtomicUsize,
    unrooted_cleaned_count: AtomicUsize,
    clean_unref_from_storage_us: AtomicU64,
    clean_dead_slot_us: AtomicU64,
}

impl LatestAccountsIndexRootsStats {
    fn update(&self, accounts_index_roots_stats: &AccountsIndexRootsStats) {
        if let Some(value) = accounts_index_roots_stats.roots_len {
            self.roots_len.store(value, Ordering::Relaxed);
        }
        if let Some(value) = accounts_index_roots_stats.uncleaned_roots_len {
            self.uncleaned_roots_len.store(value, Ordering::Relaxed);
        }
        if let Some(value) = accounts_index_roots_stats.roots_range {
            self.roots_range.store(value, Ordering::Relaxed);
        }
        self.rooted_cleaned_count.fetch_add(
            accounts_index_roots_stats.rooted_cleaned_count,
            Ordering::Relaxed,
        );
        self.unrooted_cleaned_count.fetch_add(
            accounts_index_roots_stats.unrooted_cleaned_count,
            Ordering::Relaxed,
        );
        self.clean_unref_from_storage_us.fetch_add(
            accounts_index_roots_stats.clean_unref_from_storage_us,
            Ordering::Relaxed,
        );
        self.clean_dead_slot_us.fetch_add(
            accounts_index_roots_stats.clean_dead_slot_us,
            Ordering::Relaxed,
        );
    }

    fn report(&self) {
        datapoint_info!(
            "accounts_index_roots_len",
            (
                "roots_len",
                self.roots_len.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "uncleaned_roots_len",
                self.uncleaned_roots_len.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "roots_range_width",
                self.roots_range.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "unrooted_cleaned_count",
                self.unrooted_cleaned_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "rooted_cleaned_count",
                self.rooted_cleaned_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "clean_unref_from_storage_us",
                self.clean_unref_from_storage_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "clean_dead_slot_us",
                self.clean_dead_slot_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "append_vecs_open",
                APPEND_VEC_MMAPPED_FILES_OPEN.load(Ordering::Relaxed) as i64,
                i64
            )
        );

        // Don't need to reset since this tracks the latest updates, not a cumulative total
    }
}

#[derive(Debug, Default)]
struct CleanAccountsStats {
    purge_stats: PurgeStats,
    latest_accounts_index_roots_stats: LatestAccountsIndexRootsStats,

    // stats held here and reported by clean_accounts
    clean_old_root_us: AtomicU64,
    clean_old_root_reclaim_us: AtomicU64,
    reset_uncleaned_roots_us: AtomicU64,
    remove_dead_accounts_remove_us: AtomicU64,
    remove_dead_accounts_shrink_us: AtomicU64,
    clean_stored_dead_slots_us: AtomicU64,
}

impl CleanAccountsStats {
    fn report(&self) {
        self.purge_stats.report("clean_purge_slots_stats", None);
        self.latest_accounts_index_roots_stats.report();
    }
}

#[derive(Debug, Default)]
pub(crate) struct ShrinkAncientStats {
    pub(crate) shrink_stats: ShrinkStats,
    pub(crate) ancient_append_vecs_shrunk: AtomicU64,
    pub(crate) total_us: AtomicU64,
    pub(crate) random_shrink: AtomicU64,
    pub(crate) slots_considered: AtomicU64,
    pub(crate) ancient_scanned: AtomicU64,
    pub(crate) bytes_ancient_created: AtomicU64,
}

#[derive(Debug, Default)]
pub(crate) struct ShrinkStatsSub {
    pub(crate) store_accounts_timing: StoreAccountsTiming,
    pub(crate) rewrite_elapsed_us: u64,
    pub(crate) create_and_insert_store_elapsed_us: u64,
    pub(crate) unpackable_slots_count: usize,
    pub(crate) newest_alive_packed_count: usize,
}

impl ShrinkStatsSub {
    pub(crate) fn accumulate(&mut self, other: &Self) {
        self.store_accounts_timing
            .accumulate(&other.store_accounts_timing);
        saturating_add_assign!(self.rewrite_elapsed_us, other.rewrite_elapsed_us);
        saturating_add_assign!(
            self.create_and_insert_store_elapsed_us,
            other.create_and_insert_store_elapsed_us
        );
        saturating_add_assign!(self.unpackable_slots_count, other.unpackable_slots_count);
        saturating_add_assign!(
            self.newest_alive_packed_count,
            other.newest_alive_packed_count
        );
    }
}
#[derive(Debug, Default)]
pub struct ShrinkStats {
    last_report: AtomicInterval,
    pub(crate) num_slots_shrunk: AtomicUsize,
    storage_read_elapsed: AtomicU64,
    index_read_elapsed: AtomicU64,
    create_and_insert_store_elapsed: AtomicU64,
    store_accounts_elapsed: AtomicU64,
    update_index_elapsed: AtomicU64,
    handle_reclaims_elapsed: AtomicU64,
    remove_old_stores_shrink_us: AtomicU64,
    rewrite_elapsed: AtomicU64,
    unpackable_slots_count: AtomicU64,
    newest_alive_packed_count: AtomicU64,
    drop_storage_entries_elapsed: AtomicU64,
    recycle_stores_write_elapsed: AtomicU64,
    accounts_removed: AtomicUsize,
    bytes_removed: AtomicU64,
    bytes_written: AtomicU64,
    skipped_shrink: AtomicU64,
    dead_accounts: AtomicU64,
    alive_accounts: AtomicU64,
    accounts_loaded: AtomicU64,
}

impl ShrinkStats {
    fn report(&self) {
        if self.last_report.should_update(1000) {
            datapoint_info!(
                "shrink_stats",
                (
                    "num_slots_shrunk",
                    self.num_slots_shrunk.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "storage_read_elapsed",
                    self.storage_read_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "index_read_elapsed",
                    self.index_read_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "create_and_insert_store_elapsed",
                    self.create_and_insert_store_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "store_accounts_elapsed",
                    self.store_accounts_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "update_index_elapsed",
                    self.update_index_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "handle_reclaims_elapsed",
                    self.handle_reclaims_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "remove_old_stores_shrink_us",
                    self.remove_old_stores_shrink_us.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "rewrite_elapsed",
                    self.rewrite_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "drop_storage_entries_elapsed",
                    self.drop_storage_entries_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "recycle_stores_write_time",
                    self.recycle_stores_write_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "accounts_removed",
                    self.accounts_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "bytes_removed",
                    self.bytes_removed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "bytes_written",
                    self.bytes_written.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "skipped_shrink",
                    self.skipped_shrink.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "alive_accounts",
                    self.alive_accounts.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dead_accounts",
                    self.dead_accounts.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "accounts_loaded",
                    self.accounts_loaded.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
            );
        }
    }
}

impl ShrinkAncientStats {
    pub(crate) fn report(&self) {
        datapoint_info!(
            "shrink_ancient_stats",
            (
                "num_slots_shrunk",
                self.shrink_stats
                    .num_slots_shrunk
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "storage_read_elapsed",
                self.shrink_stats
                    .storage_read_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "index_read_elapsed",
                self.shrink_stats
                    .index_read_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "create_and_insert_store_elapsed",
                self.shrink_stats
                    .create_and_insert_store_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "store_accounts_elapsed",
                self.shrink_stats
                    .store_accounts_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "update_index_elapsed",
                self.shrink_stats
                    .update_index_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "handle_reclaims_elapsed",
                self.shrink_stats
                    .handle_reclaims_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "remove_old_stores_shrink_us",
                self.shrink_stats
                    .remove_old_stores_shrink_us
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "rewrite_elapsed",
                self.shrink_stats.rewrite_elapsed.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "unpackable_slots_count",
                self.shrink_stats
                    .unpackable_slots_count
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "newest_alive_packed_count",
                self.shrink_stats
                    .newest_alive_packed_count
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "drop_storage_entries_elapsed",
                self.shrink_stats
                    .drop_storage_entries_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "recycle_stores_write_time",
                self.shrink_stats
                    .recycle_stores_write_elapsed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "accounts_removed",
                self.shrink_stats
                    .accounts_removed
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "bytes_removed",
                self.shrink_stats.bytes_removed.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "bytes_written",
                self.shrink_stats.bytes_written.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "alive_accounts",
                self.shrink_stats.alive_accounts.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "dead_accounts",
                self.shrink_stats.dead_accounts.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "accounts_loaded",
                self.shrink_stats.accounts_loaded.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "ancient_append_vecs_shrunk",
                self.ancient_append_vecs_shrunk.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "random",
                self.random_shrink.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "slots_considered",
                self.slots_considered.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "ancient_scanned",
                self.ancient_scanned.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_us",
                self.total_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "bytes_ancient_created",
                self.bytes_ancient_created.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );
    }
}

pub fn quarter_thread_count() -> usize {
    std::cmp::max(2, num_cpus::get() / 4)
}

pub fn make_min_priority_thread_pool() -> ThreadPool {
    // Use lower thread count to reduce priority.
    let num_threads = quarter_thread_count();
    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("solAccountsLo{i:02}"))
        .num_threads(num_threads)
        .build()
        .unwrap()
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for AccountsDb {
    fn example() -> Self {
        let accounts_db = AccountsDb::new_single_for_tests();
        let key = Pubkey::default();
        let some_data_len = 5;
        let some_slot: Slot = 0;
        let account = AccountSharedData::new(1, some_data_len, &key);
        accounts_db.store_uncached(some_slot, &[(&key, &account)]);
        accounts_db.add_root(0);

        accounts_db
    }
}

impl<'a> ZeroLamport for StoredAccountMeta<'a> {
    fn is_zero_lamport(&self) -> bool {
        self.lamports() == 0
    }
}

/// called on a struct while scanning append vecs
trait AppendVecScan: Send + Sync + Clone {
    /// return true if this pubkey should be included
    fn filter(&mut self, pubkey: &Pubkey) -> bool;
    /// set current slot of the scan
    fn set_slot(&mut self, slot: Slot);
    /// found `account` in the append vec
    fn found_account(&mut self, account: &LoadedAccount);
    /// scanning is done
    fn scanning_complete(self) -> BinnedHashData;
    /// initialize accumulator
    fn init_accum(&mut self, count: usize);
}

#[derive(Clone)]
/// state to keep while scanning append vec accounts for hash calculation
/// These would have been captured in a fn from within the scan function.
/// Some of these are constant across all pubkeys, some are constant across a slot.
/// Some could be unique per pubkey.
struct ScanState<'a> {
    /// slot we're currently scanning
    current_slot: Slot,
    /// accumulated results
    accum: BinnedHashData,
    bin_calculator: &'a PubkeyBinCalculator24,
    bin_range: &'a Range<usize>,
    config: &'a CalcAccountsHashConfig<'a>,
    mismatch_found: Arc<AtomicU64>,
    range: usize,
    sort_time: Arc<AtomicU64>,
    pubkey_to_bin_index: usize,
}

impl<'a> AppendVecScan for ScanState<'a> {
    fn set_slot(&mut self, slot: Slot) {
        self.current_slot = slot;
    }
    fn filter(&mut self, pubkey: &Pubkey) -> bool {
        self.pubkey_to_bin_index = self.bin_calculator.bin_from_pubkey(pubkey);
        self.bin_range.contains(&self.pubkey_to_bin_index)
    }
    fn init_accum(&mut self, count: usize) {
        if self.accum.is_empty() {
            self.accum.append(&mut vec![Vec::new(); count]);
        }
    }
    fn found_account(&mut self, loaded_account: &LoadedAccount) {
        let pubkey = loaded_account.pubkey();
        assert!(self.bin_range.contains(&self.pubkey_to_bin_index)); // get rid of this once we have confidence

        // when we are scanning with bin ranges, we don't need to use exact bin numbers. Subtract to make first bin we care about at index 0.
        self.pubkey_to_bin_index -= self.bin_range.start;

        let balance = loaded_account.lamports();
        let mut loaded_hash = loaded_account.loaded_hash();

        let hash_is_missing = loaded_hash == AccountHash(Hash::default());
        if self.config.check_hash || hash_is_missing {
            let computed_hash = loaded_account.compute_hash(pubkey);
            if hash_is_missing {
                loaded_hash = computed_hash;
            } else if self.config.check_hash && computed_hash != loaded_hash {
                info!(
                    "hash mismatch found: computed: {}, loaded: {}, pubkey: {}",
                    computed_hash.0, loaded_hash.0, pubkey
                );
                self.mismatch_found.fetch_add(1, Ordering::Relaxed);
            }
        }
        let source_item = CalculateHashIntermediate {
            hash: loaded_hash,
            lamports: balance,
            pubkey: *pubkey,
        };
        self.init_accum(self.range);
        self.accum[self.pubkey_to_bin_index].push(source_item);
    }
    fn scanning_complete(mut self) -> BinnedHashData {
        let timing = AccountsDb::sort_slot_storage_scan(&mut self.accum);
        self.sort_time.fetch_add(timing, Ordering::Relaxed);
        self.accum
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubkeyHashAccount {
    pub pubkey: Pubkey,
    pub hash: AccountHash,
    pub account: AccountSharedData,
}

impl AccountsDb {
    pub const DEFAULT_ACCOUNTS_HASH_CACHE_DIR: &'static str = "accounts_hash_cache";

    pub fn default_for_tests() -> Self {
        Self::default_with_accounts_index(AccountInfoAccountsIndex::default_for_tests(), None, None)
    }

    fn default_with_accounts_index(
        accounts_index: AccountInfoAccountsIndex,
        base_working_path: Option<PathBuf>,
        accounts_hash_cache_path: Option<PathBuf>,
    ) -> Self {
        let num_threads = get_thread_count();
        // 400M bytes
        const MAX_READ_ONLY_CACHE_DATA_SIZE: usize = 400_000_000;
        // read only cache does not update lru on read of an entry unless it has been at least this many ms since the last lru update
        const READ_ONLY_CACHE_MS_TO_SKIP_LRU_UPDATE: u32 = 100;

        let (base_working_path, base_working_temp_dir) =
            if let Some(base_working_path) = base_working_path {
                (base_working_path, None)
            } else {
                let base_working_temp_dir = TempDir::new().unwrap();
                let base_working_path = base_working_temp_dir.path().to_path_buf();
                (base_working_path, Some(base_working_temp_dir))
            };

        let accounts_hash_cache_path = accounts_hash_cache_path.unwrap_or_else(|| {
            let accounts_hash_cache_path =
                base_working_path.join(Self::DEFAULT_ACCOUNTS_HASH_CACHE_DIR);
            if !accounts_hash_cache_path.exists() {
                fs::create_dir(&accounts_hash_cache_path).expect("create accounts hash cache dir");
            }
            accounts_hash_cache_path
        });

        let mut bank_hash_stats = HashMap::new();
        bank_hash_stats.insert(0, BankHashStats::default());

        // Increase the stack for accounts threads
        // rayon needs a lot of stack
        const ACCOUNTS_STACK_SIZE: usize = 8 * 1024 * 1024;

        AccountsDb {
            create_ancient_storage: CreateAncientStorage::Pack,
            verify_accounts_hash_in_bg: VerifyAccountsHashInBackground::default(),
            active_stats: ActiveStats::default(),
            skip_initial_hash_calc: false,
            ancient_append_vec_offset: None,
            accounts_index,
            storage: AccountStorage::default(),
            accounts_cache: AccountsCache::default(),
            sender_bg_hasher: None,
            read_only_accounts_cache: ReadOnlyAccountsCache::new(
                MAX_READ_ONLY_CACHE_DATA_SIZE,
                READ_ONLY_CACHE_MS_TO_SKIP_LRU_UPDATE,
            ),
            recycle_stores: RwLock::new(RecycleStores::default()),
            uncleaned_pubkeys: DashMap::new(),
            next_id: AtomicAppendVecId::new(0),
            shrink_candidate_slots: Mutex::new(ShrinkCandidates::default()),
            write_cache_limit_bytes: None,
            write_version: AtomicU64::new(0),
            paths: vec![],
            base_working_path,
            base_working_temp_dir,
            accounts_hash_cache_path,
            shrink_paths: RwLock::new(None),
            temp_paths: None,
            file_size: DEFAULT_FILE_SIZE,
            thread_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .thread_name(|i| format!("solAccounts{i:02}"))
                .stack_size(ACCOUNTS_STACK_SIZE)
                .build()
                .unwrap(),
            thread_pool_clean: make_min_priority_thread_pool(),
            bank_hash_stats: Mutex::new(bank_hash_stats),
            accounts_delta_hashes: Mutex::new(HashMap::new()),
            accounts_hashes: Mutex::new(HashMap::new()),
            incremental_accounts_hashes: Mutex::new(HashMap::new()),
            external_purge_slots_stats: PurgeStats::default(),
            clean_accounts_stats: CleanAccountsStats::default(),
            shrink_stats: ShrinkStats::default(),
            shrink_ancient_stats: ShrinkAncientStats::default(),
            stats: AccountsStats::default(),
            cluster_type: None,
            account_indexes: AccountSecondaryIndexes::default(),
            #[cfg(test)]
            load_delay: u64::default(),
            #[cfg(test)]
            load_limit: AtomicU64::default(),
            is_bank_drop_callback_enabled: AtomicBool::default(),
            remove_unrooted_slots_synchronization: RemoveUnrootedSlotsSynchronization::default(),
            shrink_ratio: AccountShrinkThreshold::default(),
            dirty_stores: DashMap::default(),
            zero_lamport_accounts_to_purge_after_full_snapshot: DashSet::default(),
            accounts_update_notifier: None,
            log_dead_slots: AtomicBool::new(true),
            exhaustively_verify_refcounts: false,
            partitioned_epoch_rewards_config: PartitionedEpochRewardsConfig::default(),
            epoch_accounts_hash_manager: EpochAccountsHashManager::new_invalid(),
            test_skip_rewrites_but_include_in_bank_hash: false,
        }
    }

    pub fn new_single_for_tests() -> Self {
        AccountsDb::new_for_tests(Vec::new(), &ClusterType::Development)
    }

    pub fn new_for_tests(paths: Vec<PathBuf>, cluster_type: &ClusterType) -> Self {
        AccountsDb::new_with_config(
            paths,
            cluster_type,
            AccountSecondaryIndexes::default(),
            AccountShrinkThreshold::default(),
            Some(ACCOUNTS_DB_CONFIG_FOR_TESTING),
            None,
            Arc::default(),
        )
    }

    pub fn new_with_config(
        paths: Vec<PathBuf>,
        cluster_type: &ClusterType,
        account_indexes: AccountSecondaryIndexes,
        shrink_ratio: AccountShrinkThreshold,
        mut accounts_db_config: Option<AccountsDbConfig>,
        accounts_update_notifier: Option<AccountsUpdateNotifier>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        let accounts_index = AccountsIndex::new(
            accounts_db_config.as_mut().and_then(|x| x.index.take()),
            exit,
        );
        let base_working_path = accounts_db_config
            .as_ref()
            .and_then(|x| x.base_working_path.clone());
        let accounts_hash_cache_path = accounts_db_config
            .as_ref()
            .and_then(|config| config.accounts_hash_cache_path.clone());
        let skip_initial_hash_calc = accounts_db_config
            .as_ref()
            .map(|config| config.skip_initial_hash_calc)
            .unwrap_or_default();

        let ancient_append_vec_offset = accounts_db_config
            .as_ref()
            .and_then(|config| config.ancient_append_vec_offset)
            .or(ANCIENT_APPEND_VEC_DEFAULT_OFFSET);

        let exhaustively_verify_refcounts = accounts_db_config
            .as_ref()
            .map(|config| config.exhaustively_verify_refcounts)
            .unwrap_or_default();

        let create_ancient_storage = accounts_db_config
            .as_ref()
            .map(|config| config.create_ancient_storage)
            .unwrap_or(CreateAncientStorage::Append);

        let test_partitioned_epoch_rewards = accounts_db_config
            .as_ref()
            .map(|config| config.test_partitioned_epoch_rewards)
            .unwrap_or_default();

        let test_skip_rewrites_but_include_in_bank_hash = accounts_db_config
            .as_ref()
            .map(|config| config.test_skip_rewrites_but_include_in_bank_hash)
            .unwrap_or_default();

        let partitioned_epoch_rewards_config: PartitionedEpochRewardsConfig =
            PartitionedEpochRewardsConfig::new(test_partitioned_epoch_rewards);

        let paths_is_empty = paths.is_empty();
        let mut new = Self {
            paths,
            skip_initial_hash_calc,
            ancient_append_vec_offset,
            cluster_type: Some(*cluster_type),
            account_indexes,
            shrink_ratio,
            accounts_update_notifier,
            create_ancient_storage,
            write_cache_limit_bytes: accounts_db_config
                .as_ref()
                .and_then(|x| x.write_cache_limit_bytes),
            partitioned_epoch_rewards_config,
            exhaustively_verify_refcounts,
            test_skip_rewrites_but_include_in_bank_hash,
            ..Self::default_with_accounts_index(
                accounts_index,
                base_working_path,
                accounts_hash_cache_path,
            )
        };
        if paths_is_empty {
            // Create a temporary set of accounts directories, used primarily
            // for testing
            let (temp_dirs, paths) = get_temp_accounts_paths(DEFAULT_NUM_DIRS).unwrap();
            new.accounts_update_notifier = None;
            new.paths = paths;
            new.temp_paths = Some(temp_dirs);
        };

        new.start_background_hasher();
        {
            for path in new.paths.iter() {
                std::fs::create_dir_all(path).expect("Create directory failed.");
            }
        }
        new
    }

    pub fn set_shrink_paths(&self, paths: Vec<PathBuf>) {
        assert!(!paths.is_empty());
        let mut shrink_paths = self.shrink_paths.write().unwrap();
        for path in &paths {
            std::fs::create_dir_all(path).expect("Create directory failed.");
        }
        *shrink_paths = Some(paths);
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Get the base working directory
    pub fn get_base_working_path(&self) -> PathBuf {
        self.base_working_path.clone()
    }

    fn next_id(&self) -> AppendVecId {
        let next_id = self.next_id.fetch_add(1, Ordering::AcqRel);
        assert!(next_id != AppendVecId::MAX, "We've run out of storage ids!");
        next_id
    }

    fn new_storage_entry(&self, slot: Slot, path: &Path, size: u64) -> AccountStorageEntry {
        AccountStorageEntry::new(path, slot, self.next_id(), size)
    }

    pub fn expected_cluster_type(&self) -> ClusterType {
        self.cluster_type
            .expect("Cluster type must be set at initialization")
    }

    /// Reclaim older states of accounts older than max_clean_root_inclusive for AccountsDb bloat mitigation.
    /// Any accounts which are removed from the accounts index are returned in PubkeysRemovedFromAccountsIndex.
    /// These should NOT be unref'd later from the accounts index.
    fn clean_accounts_older_than_root(
        &self,
        purges: Vec<Pubkey>,
        max_clean_root_inclusive: Option<Slot>,
        ancient_account_cleans: &AtomicU64,
        epoch_schedule: &EpochSchedule,
    ) -> (ReclaimResult, PubkeysRemovedFromAccountsIndex) {
        let pubkeys_removed_from_accounts_index = HashSet::default();
        if purges.is_empty() {
            return (
                ReclaimResult::default(),
                pubkeys_removed_from_accounts_index,
            );
        }
        // This number isn't carefully chosen; just guessed randomly such that
        // the hot loop will be the order of ~Xms.
        const INDEX_CLEAN_BULK_COUNT: usize = 4096;

        let one_epoch_old = self.get_oldest_non_ancient_slot(epoch_schedule);
        let pubkeys_removed_from_accounts_index = Mutex::new(pubkeys_removed_from_accounts_index);

        let mut clean_rooted = Measure::start("clean_old_root-ms");
        let reclaim_vecs = purges
            .par_chunks(INDEX_CLEAN_BULK_COUNT)
            .filter_map(|pubkeys: &[Pubkey]| {
                let mut reclaims = Vec::new();
                for pubkey in pubkeys {
                    let removed_from_index = self.accounts_index.clean_rooted_entries(
                        pubkey,
                        &mut reclaims,
                        max_clean_root_inclusive,
                    );
                    if removed_from_index {
                        pubkeys_removed_from_accounts_index
                            .lock()
                            .unwrap()
                            .insert(*pubkey);
                    }
                }

                (!reclaims.is_empty()).then(|| {
                    // figure out how many ancient accounts have been reclaimed
                    let old_reclaims = reclaims
                        .iter()
                        .filter_map(|(slot, _)| (slot < &one_epoch_old).then_some(1))
                        .sum();
                    ancient_account_cleans.fetch_add(old_reclaims, Ordering::Relaxed);
                    reclaims
                })
            })
            .collect::<Vec<_>>();
        clean_rooted.stop();
        let pubkeys_removed_from_accounts_index =
            pubkeys_removed_from_accounts_index.into_inner().unwrap();
        self.clean_accounts_stats
            .clean_old_root_us
            .fetch_add(clean_rooted.as_us(), Ordering::Relaxed);

        let mut measure = Measure::start("clean_old_root_reclaims");

        // Don't reset from clean, since the pubkeys in those stores may need to be unref'ed
        // and those stores may be used for background hashing.
        let reset_accounts = false;

        let mut reclaim_result = ReclaimResult::default();
        self.handle_reclaims(
            (!reclaim_vecs.is_empty()).then(|| reclaim_vecs.iter().flatten()),
            None,
            Some((&self.clean_accounts_stats.purge_stats, &mut reclaim_result)),
            reset_accounts,
            &pubkeys_removed_from_accounts_index,
        );
        measure.stop();
        debug!("{} {}", clean_rooted, measure);
        self.clean_accounts_stats
            .clean_old_root_reclaim_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
        (reclaim_result, pubkeys_removed_from_accounts_index)
    }

    fn do_reset_uncleaned_roots(&self, max_clean_root: Option<Slot>) {
        let mut measure = Measure::start("reset");
        self.accounts_index.reset_uncleaned_roots(max_clean_root);
        measure.stop();
        self.clean_accounts_stats
            .reset_uncleaned_roots_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
    }

    /// increment store_counts to non-zero for all stores that can not be deleted.
    /// a store cannot be deleted if:
    /// 1. one of the pubkeys in the store has account info to a store whose store count is not going to zero
    /// 2. a pubkey we were planning to remove is not removing all stores that contain the account
    fn calc_delete_dependencies(
        purges: &HashMap<Pubkey, (SlotList<AccountInfo>, RefCount)>,
        store_counts: &mut HashMap<Slot, (usize, HashSet<Pubkey>)>,
        min_slot: Option<Slot>,
    ) {
        // Another pass to check if there are some filtered accounts which
        // do not match the criteria of deleting all appendvecs which contain them
        // then increment their storage count.
        let mut already_counted = IntSet::default();
        for (pubkey, (account_infos, ref_count_from_storage)) in purges.iter() {
            let mut failed_slot = None;
            let all_stores_being_deleted =
                account_infos.len() as RefCount == *ref_count_from_storage;
            if all_stores_being_deleted {
                let mut delete = true;
                for (slot, _account_info) in account_infos {
                    if let Some(count) = store_counts.get(slot).map(|s| s.0) {
                        debug!(
                            "calc_delete_dependencies()
                            slot: {slot},
                            count len: {count}"
                        );
                        if count == 0 {
                            // this store CAN be removed
                            continue;
                        }
                    }
                    // One of the pubkeys in the store has account info to a store whose store count is not going to zero.
                    // If the store cannot be found, that also means store isn't being deleted.
                    failed_slot = Some(*slot);
                    delete = false;
                    break;
                }
                if delete {
                    // this pubkey can be deleted from all stores it is in
                    continue;
                }
            } else {
                // a pubkey we were planning to remove is not removing all stores that contain the account
                debug!(
                    "calc_delete_dependencies(),
                    pubkey: {},
                    account_infos: {:?},
                    account_infos_len: {},
                    ref_count_from_storage: {}",
                    pubkey,
                    account_infos,
                    account_infos.len(),
                    ref_count_from_storage,
                );
            }

            // increment store_counts to non-zero for all stores that can not be deleted.
            let mut pending_stores = IntSet::default();
            for (slot, _account_info) in account_infos {
                if !already_counted.contains(slot) {
                    pending_stores.insert(*slot);
                }
            }
            while !pending_stores.is_empty() {
                let slot = pending_stores.iter().next().cloned().unwrap();
                if Some(slot) == min_slot {
                    if let Some(failed_slot) = failed_slot.take() {
                        info!("calc_delete_dependencies, oldest slot is not able to be deleted because of {pubkey} in slot {failed_slot}");
                    } else {
                        info!("calc_delete_dependencies, oldest slot is not able to be deleted because of {pubkey}, account infos len: {}, ref count: {ref_count_from_storage}", account_infos.len());
                    }
                }

                pending_stores.remove(&slot);
                if !already_counted.insert(slot) {
                    continue;
                }
                // the point of all this code: remove the store count for all stores we cannot remove
                if let Some(store_count) = store_counts.remove(&slot) {
                    // all pubkeys in this store also cannot be removed from all stores they are in
                    let affected_pubkeys = &store_count.1;
                    for key in affected_pubkeys {
                        for (slot, _account_info) in &purges.get(key).unwrap().0 {
                            if !already_counted.contains(slot) {
                                pending_stores.insert(*slot);
                            }
                        }
                    }
                }
            }
        }
    }

    fn background_hasher(receiver: Receiver<CachedAccount>) {
        info!("Background account hasher has started");
        loop {
            let result = receiver.recv();
            match result {
                Ok(account) => {
                    // if we hold the only ref, then this account doesn't need to be hashed, we ignore this account and it will disappear
                    if Arc::strong_count(&account) > 1 {
                        // this will cause the hash to be calculated and store inside account if it needs to be calculated
                        let _ = (*account).hash();
                    };
                }
                Err(err) => {
                    info!("Background account hasher is stopping because: {err}");
                    break;
                }
            }
        }
        info!("Background account hasher has stopped");
    }

    fn start_background_hasher(&mut self) {
        let (sender, receiver) = unbounded();
        Builder::new()
            .name("solDbStoreHashr".to_string())
            .spawn(move || {
                Self::background_hasher(receiver);
            })
            .unwrap();
        self.sender_bg_hasher = Some(sender);
    }

    #[must_use]
    pub fn purge_keys_exact<'a, C: 'a>(
        &'a self,
        pubkey_to_slot_set: impl Iterator<Item = &'a (Pubkey, C)>,
    ) -> (Vec<(Slot, AccountInfo)>, PubkeysRemovedFromAccountsIndex)
    where
        C: Contains<'a, Slot>,
    {
        let mut reclaims = Vec::new();
        let mut dead_keys = Vec::new();

        let mut purge_exact_count = 0;
        let (_, purge_exact_us) = measure_us!(for (pubkey, slots_set) in pubkey_to_slot_set {
            purge_exact_count += 1;
            let is_empty = self
                .accounts_index
                .purge_exact(pubkey, slots_set, &mut reclaims);
            if is_empty {
                dead_keys.push(pubkey);
            }
        });

        let (pubkeys_removed_from_accounts_index, handle_dead_keys_us) = measure_us!(self
            .accounts_index
            .handle_dead_keys(&dead_keys, &self.account_indexes));

        self.stats
            .purge_exact_count
            .fetch_add(purge_exact_count, Ordering::Relaxed);
        self.stats
            .handle_dead_keys_us
            .fetch_add(handle_dead_keys_us, Ordering::Relaxed);
        self.stats
            .purge_exact_us
            .fetch_add(purge_exact_us, Ordering::Relaxed);
        (reclaims, pubkeys_removed_from_accounts_index)
    }

    fn max_clean_root(&self, proposed_clean_root: Option<Slot>) -> Option<Slot> {
        match (
            self.accounts_index.min_ongoing_scan_root(),
            proposed_clean_root,
        ) {
            (None, None) => None,
            (Some(min_scan_root), None) => Some(min_scan_root),
            (None, Some(proposed_clean_root)) => Some(proposed_clean_root),
            (Some(min_scan_root), Some(proposed_clean_root)) => {
                Some(std::cmp::min(min_scan_root, proposed_clean_root))
            }
        }
    }

    /// get the oldest slot that is within one epoch of the highest known root.
    /// The slot will have been offset by `self.ancient_append_vec_offset`
    fn get_oldest_non_ancient_slot(&self, epoch_schedule: &EpochSchedule) -> Slot {
        self.get_oldest_non_ancient_slot_from_slot(
            epoch_schedule,
            self.accounts_index.max_root_inclusive(),
        )
    }

    /// get the oldest slot that is within one epoch of `max_root_inclusive`.
    /// The slot will have been offset by `self.ancient_append_vec_offset`
    fn get_oldest_non_ancient_slot_from_slot(
        &self,
        epoch_schedule: &EpochSchedule,
        max_root_inclusive: Slot,
    ) -> Slot {
        let mut result = max_root_inclusive;
        if let Some(offset) = self.ancient_append_vec_offset {
            result = Self::apply_offset_to_slot(result, offset);
        }
        result = Self::apply_offset_to_slot(
            result,
            -((epoch_schedule.slots_per_epoch as i64).saturating_sub(1)),
        );
        result.min(max_root_inclusive)
    }

    /// Collect all the uncleaned slots, up to a max slot
    ///
    /// Search through the uncleaned Pubkeys and return all the slots, up to a maximum slot.
    fn collect_uncleaned_slots_up_to_slot(&self, max_slot_inclusive: Slot) -> Vec<Slot> {
        self.uncleaned_pubkeys
            .iter()
            .filter_map(|entry| {
                let slot = *entry.key();
                (slot <= max_slot_inclusive).then_some(slot)
            })
            .collect()
    }

    /// Remove `slots` from `uncleaned_pubkeys` and collect all pubkeys
    ///
    /// For each slot in the list of uncleaned slots, remove it from the `uncleaned_pubkeys` Map
    /// and collect all the pubkeys to return.
    fn remove_uncleaned_slots_and_collect_pubkeys(
        &self,
        uncleaned_slots: Vec<Slot>,
    ) -> Vec<Vec<Pubkey>> {
        uncleaned_slots
            .into_iter()
            .filter_map(|uncleaned_slot| {
                self.uncleaned_pubkeys
                    .remove(&uncleaned_slot)
                    .map(|(_removed_slot, removed_pubkeys)| removed_pubkeys)
            })
            .collect()
    }

    /// Remove uncleaned slots, up to a maximum slot, and return the collected pubkeys
    ///
    fn remove_uncleaned_slots_and_collect_pubkeys_up_to_slot(
        &self,
        max_slot_inclusive: Slot,
    ) -> Vec<Vec<Pubkey>> {
        let uncleaned_slots = self.collect_uncleaned_slots_up_to_slot(max_slot_inclusive);
        self.remove_uncleaned_slots_and_collect_pubkeys(uncleaned_slots)
    }

    /// Construct a vec of pubkeys for cleaning from:
    ///   uncleaned_pubkeys - the delta set of updated pubkeys in rooted slots from the last clean
    ///   dirty_stores - set of stores which had accounts removed or recently rooted
    /// returns the minimum slot we encountered
    fn construct_candidate_clean_keys(
        &self,
        max_clean_root_inclusive: Option<Slot>,
        is_startup: bool,
        last_full_snapshot_slot: Option<Slot>,
        timings: &mut CleanKeyTimings,
        epoch_schedule: &EpochSchedule,
    ) -> (Vec<Pubkey>, Option<Slot>) {
        let oldest_non_ancient_slot = self.get_oldest_non_ancient_slot(epoch_schedule);
        let mut dirty_store_processing_time = Measure::start("dirty_store_processing");
        let max_slot_inclusive =
            max_clean_root_inclusive.unwrap_or_else(|| self.accounts_index.max_root_inclusive());
        let mut dirty_stores = Vec::with_capacity(self.dirty_stores.len());
        // find the oldest dirty slot
        // we'll add logging if that append vec cannot be marked dead
        let mut min_dirty_slot = None::<u64>;
        self.dirty_stores.retain(|slot, store| {
            if *slot > max_slot_inclusive {
                true
            } else {
                min_dirty_slot = min_dirty_slot.map(|min| min.min(*slot)).or(Some(*slot));
                dirty_stores.push((*slot, store.clone()));
                false
            }
        });
        let dirty_stores_len = dirty_stores.len();
        let pubkeys = DashSet::new();
        let dirty_ancient_stores = AtomicUsize::default();
        let mut dirty_store_routine = || {
            let chunk_size = 1.max(dirty_stores_len.saturating_div(rayon::current_num_threads()));
            let oldest_dirty_slots: Vec<u64> = dirty_stores
                .par_chunks(chunk_size)
                .map(|dirty_store_chunk| {
                    let mut oldest_dirty_slot = max_slot_inclusive.saturating_add(1);
                    dirty_store_chunk.iter().for_each(|(slot, store)| {
                        if slot < &oldest_non_ancient_slot {
                            dirty_ancient_stores.fetch_add(1, Ordering::Relaxed);
                        }
                        oldest_dirty_slot = oldest_dirty_slot.min(*slot);
                        store.accounts.account_iter().for_each(|account| {
                            pubkeys.insert(*account.pubkey());
                        });
                    });
                    oldest_dirty_slot
                })
                .collect();
            timings.oldest_dirty_slot = *oldest_dirty_slots
                .iter()
                .min()
                .unwrap_or(&max_slot_inclusive.saturating_add(1));
        };

        if is_startup {
            // Free to consume all the cores during startup
            dirty_store_routine();
        } else {
            self.thread_pool_clean.install(|| {
                dirty_store_routine();
            });
        }
        trace!(
            "dirty_stores.len: {} pubkeys.len: {}",
            dirty_stores_len,
            pubkeys.len()
        );
        timings.dirty_pubkeys_count = pubkeys.len() as u64;
        dirty_store_processing_time.stop();
        timings.dirty_store_processing_us += dirty_store_processing_time.as_us();
        timings.dirty_ancient_stores = dirty_ancient_stores.load(Ordering::Relaxed);

        let mut collect_delta_keys = Measure::start("key_create");
        let delta_keys =
            self.remove_uncleaned_slots_and_collect_pubkeys_up_to_slot(max_slot_inclusive);
        collect_delta_keys.stop();
        timings.collect_delta_keys_us += collect_delta_keys.as_us();

        let mut delta_insert = Measure::start("delta_insert");
        self.thread_pool_clean.install(|| {
            delta_keys.par_iter().for_each(|keys| {
                for key in keys {
                    pubkeys.insert(*key);
                }
            });
        });
        delta_insert.stop();
        timings.delta_insert_us += delta_insert.as_us();

        timings.delta_key_count = pubkeys.len() as u64;

        let mut hashset_to_vec = Measure::start("flat_map");
        let mut pubkeys: Vec<Pubkey> = pubkeys.into_iter().collect();
        hashset_to_vec.stop();
        timings.hashset_to_vec_us += hashset_to_vec.as_us();

        // Check if we should purge any of the zero_lamport_accounts_to_purge_later, based on the
        // last_full_snapshot_slot.
        assert!(
            last_full_snapshot_slot.is_some() || self.zero_lamport_accounts_to_purge_after_full_snapshot.is_empty(),
            "if snapshots are disabled, then zero_lamport_accounts_to_purge_later should always be empty"
        );
        if let Some(last_full_snapshot_slot) = last_full_snapshot_slot {
            self.zero_lamport_accounts_to_purge_after_full_snapshot
                .retain(|(slot, pubkey)| {
                    let is_candidate_for_clean =
                        max_slot_inclusive >= *slot && last_full_snapshot_slot >= *slot;
                    if is_candidate_for_clean {
                        pubkeys.push(*pubkey);
                    }
                    !is_candidate_for_clean
                });
        }

        (pubkeys, min_dirty_slot)
    }

    /// Call clean_accounts() with the common parameters that tests/benches use.
    pub fn clean_accounts_for_tests(&self) {
        self.clean_accounts(None, false, None, &EpochSchedule::default())
    }

    /// called with cli argument to verify refcounts are correct on all accounts
    /// this is very slow
    fn exhaustively_verify_refcounts(&self, max_slot_inclusive: Option<Slot>) {
        let max_slot_inclusive =
            max_slot_inclusive.unwrap_or_else(|| self.accounts_index.max_root_inclusive());
        info!("exhaustively verifying refcounts as of slot: {max_slot_inclusive}");
        let pubkey_refcount = DashMap::<Pubkey, Vec<Slot>>::default();
        let slots = self.storage.all_slots();
        // populate
        slots.into_par_iter().for_each(|slot| {
            if slot > max_slot_inclusive {
                return;
            }
            if let Some(storage) = self.storage.get_slot_storage_entry(slot) {
                storage.all_accounts().iter().for_each(|account| {
                    let pk = account.pubkey();
                    match pubkey_refcount.entry(*pk) {
                        dashmap::mapref::entry::Entry::Occupied(mut occupied_entry) => {
                            if !occupied_entry.get().iter().any(|s| s == &slot) {
                                occupied_entry.get_mut().push(slot);
                            }
                        }
                        dashmap::mapref::entry::Entry::Vacant(vacant_entry) => {
                            vacant_entry.insert(vec![slot]);
                        }
                    }
                });
            }
        });
        let total = pubkey_refcount.len();
        let failed = AtomicBool::default();
        let threads = quarter_thread_count();
        let per_batch = total / threads;
        (0..=threads).into_par_iter().for_each(|attempt| {
                pubkey_refcount.iter().skip(attempt * per_batch).take(per_batch).for_each(|entry| {
                    if failed.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(idx) = self.accounts_index.get_account_read_entry(entry.key()) {
                        match (idx.ref_count() as usize).cmp(&entry.value().len()) {
                            std::cmp::Ordering::Greater => {
                            let list = idx.slot_list();
                            let too_new = list.iter().filter_map(|(slot, _)| (slot > &max_slot_inclusive).then_some(())).count();

                            if ((idx.ref_count() as usize) - too_new) > entry.value().len() {
                                failed.store(true, Ordering::Relaxed);
                                error!("exhaustively_verify_refcounts: {} refcount too large: {}, should be: {}, {:?}, {:?}, original: {:?}, too_new: {too_new}", entry.key(), idx.ref_count(), entry.value().len(), *entry.value(), list, idx.slot_list());
                            }
                        }
                        std::cmp::Ordering::Less => {
                            error!("exhaustively_verify_refcounts: {} refcount too small: {}, should be: {}, {:?}, {:?}", entry.key(), idx.ref_count(), entry.value().len(), *entry.value(), idx.slot_list());
                        }
                        _ => {}
                    }
                    }
                });
            });
        if failed.load(Ordering::Relaxed) {
            panic!("exhaustively_verify_refcounts failed");
        }
    }

    // Purge zero lamport accounts and older rooted account states as garbage
    // collection
    // Only remove those accounts where the entire rooted history of the account
    // can be purged because there are no live append vecs in the ancestors
    pub fn clean_accounts(
        &self,
        max_clean_root_inclusive: Option<Slot>,
        is_startup: bool,
        last_full_snapshot_slot: Option<Slot>,
        epoch_schedule: &EpochSchedule,
    ) {
        if self.exhaustively_verify_refcounts {
            self.exhaustively_verify_refcounts(max_clean_root_inclusive);
        }

        let _guard = self.active_stats.activate(ActiveStatItem::Clean);

        let ancient_account_cleans = AtomicU64::default();

        let mut measure_all = Measure::start("clean_accounts");
        let max_clean_root_inclusive = self.max_clean_root(max_clean_root_inclusive);

        self.report_store_stats();

        let mut key_timings = CleanKeyTimings::default();
        let (mut pubkeys, min_dirty_slot) = self.construct_candidate_clean_keys(
            max_clean_root_inclusive,
            is_startup,
            last_full_snapshot_slot,
            &mut key_timings,
            epoch_schedule,
        );

        let mut sort = Measure::start("sort");
        if is_startup {
            pubkeys.par_sort_unstable();
        } else {
            self.thread_pool_clean
                .install(|| pubkeys.par_sort_unstable());
        }
        sort.stop();

        let total_keys_count = pubkeys.len();
        let mut accounts_scan = Measure::start("accounts_scan");
        let uncleaned_roots = self.accounts_index.clone_uncleaned_roots();
        let found_not_zero_accum = AtomicU64::new(0);
        let not_found_on_fork_accum = AtomicU64::new(0);
        let missing_accum = AtomicU64::new(0);
        let useful_accum = AtomicU64::new(0);

        // parallel scan the index.
        let (mut purges_zero_lamports, purges_old_accounts) = {
            let do_clean_scan = || {
                pubkeys
                    .par_chunks(4096)
                    .map(|pubkeys: &[Pubkey]| {
                        let mut purges_zero_lamports = HashMap::new();
                        let mut purges_old_accounts = Vec::new();
                        let mut found_not_zero = 0;
                        let mut not_found_on_fork = 0;
                        let mut missing = 0;
                        let mut useful = 0;
                        self.accounts_index.scan(
                            pubkeys.iter(),
                            |pubkey, slots_refs, _entry| {
                                let mut useless = true;
                                if let Some((slot_list, ref_count)) = slots_refs {
                                    let index_in_slot_list = self.accounts_index.latest_slot(
                                        None,
                                        slot_list,
                                        max_clean_root_inclusive,
                                    );

                                    match index_in_slot_list {
                                        Some(index_in_slot_list) => {
                                            // found info relative to max_clean_root
                                            let (slot, account_info) =
                                                &slot_list[index_in_slot_list];
                                            if account_info.is_zero_lamport() {
                                                useless = false;
                                                purges_zero_lamports.insert(
                                                    *pubkey,
                                                    (
                                                        self.accounts_index.get_rooted_entries(
                                                            slot_list,
                                                            max_clean_root_inclusive,
                                                        ),
                                                        ref_count,
                                                    ),
                                                );
                                            } else {
                                                found_not_zero += 1;
                                            }
                                            if uncleaned_roots.contains(slot) {
                                                // Assertion enforced by `accounts_index.get()`, the latest slot
                                                // will not be greater than the given `max_clean_root`
                                                if let Some(max_clean_root_inclusive) =
                                                    max_clean_root_inclusive
                                                {
                                                    assert!(slot <= &max_clean_root_inclusive);
                                                }
                                                purges_old_accounts.push(*pubkey);
                                                useless = false;
                                            }
                                        }
                                        None => {
                                            // This pubkey is in the index but not in a root slot, so clean
                                            // it up by adding it to the to-be-purged list.
                                            //
                                            // Also, this pubkey must have been touched by some slot since
                                            // it was in the dirty list, so we assume that the slot it was
                                            // touched in must be unrooted.
                                            not_found_on_fork += 1;
                                            useless = false;
                                            purges_old_accounts.push(*pubkey);
                                        }
                                    }
                                } else {
                                    missing += 1;
                                }
                                if !useless {
                                    useful += 1;
                                }
                                if useless {
                                    AccountsIndexScanResult::OnlyKeepInMemoryIfDirty
                                } else {
                                    AccountsIndexScanResult::KeepInMemory
                                }
                            },
                            None,
                            false,
                        );
                        found_not_zero_accum.fetch_add(found_not_zero, Ordering::Relaxed);
                        not_found_on_fork_accum.fetch_add(not_found_on_fork, Ordering::Relaxed);
                        missing_accum.fetch_add(missing, Ordering::Relaxed);
                        useful_accum.fetch_add(useful, Ordering::Relaxed);
                        (purges_zero_lamports, purges_old_accounts)
                    })
                    .reduce(
                        || (HashMap::new(), Vec::new()),
                        |mut m1, m2| {
                            // Collapse down the hashmaps/vecs into one.
                            m1.0.extend(m2.0);
                            m1.1.extend(m2.1);
                            m1
                        },
                    )
            };
            if is_startup {
                do_clean_scan()
            } else {
                self.thread_pool_clean.install(do_clean_scan)
            }
        };
        accounts_scan.stop();

        let mut clean_old_rooted = Measure::start("clean_old_roots");
        let ((purged_account_slots, removed_accounts), mut pubkeys_removed_from_accounts_index) =
            self.clean_accounts_older_than_root(
                purges_old_accounts,
                max_clean_root_inclusive,
                &ancient_account_cleans,
                epoch_schedule,
            );

        self.do_reset_uncleaned_roots(max_clean_root_inclusive);
        clean_old_rooted.stop();

        let mut store_counts_time = Measure::start("store_counts");

        // Calculate store counts as if everything was purged
        // Then purge if we can
        let mut store_counts: HashMap<Slot, (usize, HashSet<Pubkey>)> = HashMap::new();
        for (key, (account_infos, ref_count)) in purges_zero_lamports.iter_mut() {
            if purged_account_slots.contains_key(key) {
                *ref_count = self.accounts_index.ref_count_from_storage(key);
            }
            account_infos.retain(|(slot, account_info)| {
                let was_slot_purged = purged_account_slots
                    .get(key)
                    .map(|slots_removed| slots_removed.contains(slot))
                    .unwrap_or(false);
                if was_slot_purged {
                    // No need to look up the slot storage below if the entire
                    // slot was purged
                    return false;
                }
                // Check if this update in `slot` to the account with `key` was reclaimed earlier by
                // `clean_accounts_older_than_root()`
                let was_reclaimed = removed_accounts
                    .get(slot)
                    .map(|store_removed| store_removed.contains(&account_info.offset()))
                    .unwrap_or(false);
                if was_reclaimed {
                    return false;
                }
                if let Some(store_count) = store_counts.get_mut(slot) {
                    store_count.0 -= 1;
                    store_count.1.insert(*key);
                } else {
                    let mut key_set = HashSet::new();
                    key_set.insert(*key);
                    assert!(
                        !account_info.is_cached(),
                        "The Accounts Cache must be flushed first for this account info. pubkey: {}, slot: {}",
                        *key,
                        *slot
                    );
                    let count = self
                        .storage
                        .get_account_storage_entry(*slot, account_info.store_id())
                        .map(|store| store.count())
                        .unwrap()
                        - 1;
                    debug!(
                        "store_counts, inserting slot: {}, store id: {}, count: {}",
                        slot, account_info.store_id(), count
                    );
                    store_counts.insert(*slot, (count, key_set));
                }
                true
            });
        }
        store_counts_time.stop();

        let mut calc_deps_time = Measure::start("calc_deps");
        Self::calc_delete_dependencies(&purges_zero_lamports, &mut store_counts, min_dirty_slot);
        calc_deps_time.stop();

        let mut purge_filter = Measure::start("purge_filter");
        self.filter_zero_lamport_clean_for_incremental_snapshots(
            max_clean_root_inclusive,
            last_full_snapshot_slot,
            &store_counts,
            &mut purges_zero_lamports,
        );
        purge_filter.stop();

        let mut reclaims_time = Measure::start("reclaims");
        // Recalculate reclaims with new purge set
        let pubkey_to_slot_set: Vec<_> = purges_zero_lamports
            .into_iter()
            .map(|(key, (slots_list, _ref_count))| {
                (
                    key,
                    slots_list
                        .into_iter()
                        .map(|(slot, _)| slot)
                        .collect::<HashSet<Slot>>(),
                )
            })
            .collect();

        let (reclaims, pubkeys_removed_from_accounts_index2) =
            self.purge_keys_exact(pubkey_to_slot_set.iter());
        pubkeys_removed_from_accounts_index.extend(pubkeys_removed_from_accounts_index2);

        // Don't reset from clean, since the pubkeys in those stores may need to be unref'ed
        // and those stores may be used for background hashing.
        let reset_accounts = false;
        let mut reclaim_result = ReclaimResult::default();
        self.handle_reclaims(
            (!reclaims.is_empty()).then(|| reclaims.iter()),
            None,
            Some((&self.clean_accounts_stats.purge_stats, &mut reclaim_result)),
            reset_accounts,
            &pubkeys_removed_from_accounts_index,
        );

        reclaims_time.stop();
        measure_all.stop();

        self.clean_accounts_stats.report();
        datapoint_info!(
            "clean_accounts",
            ("total_us", measure_all.as_us(), i64),
            (
                "collect_delta_keys_us",
                key_timings.collect_delta_keys_us,
                i64
            ),
            ("oldest_dirty_slot", key_timings.oldest_dirty_slot, i64),
            (
                "pubkeys_removed_from_accounts_index",
                pubkeys_removed_from_accounts_index.len(),
                i64
            ),
            (
                "dirty_ancient_stores",
                key_timings.dirty_ancient_stores,
                i64
            ),
            (
                "dirty_store_processing_us",
                key_timings.dirty_store_processing_us,
                i64
            ),
            ("accounts_scan", accounts_scan.as_us() as i64, i64),
            ("clean_old_rooted", clean_old_rooted.as_us() as i64, i64),
            ("store_counts", store_counts_time.as_us() as i64, i64),
            ("purge_filter", purge_filter.as_us() as i64, i64),
            ("calc_deps", calc_deps_time.as_us() as i64, i64),
            ("reclaims", reclaims_time.as_us() as i64, i64),
            ("delta_insert_us", key_timings.delta_insert_us, i64),
            ("delta_key_count", key_timings.delta_key_count, i64),
            ("dirty_pubkeys_count", key_timings.dirty_pubkeys_count, i64),
            ("sort_us", sort.as_us(), i64),
            ("useful_keys", useful_accum.load(Ordering::Relaxed), i64),
            ("total_keys_count", total_keys_count, i64),
            (
                "scan_found_not_zero",
                found_not_zero_accum.load(Ordering::Relaxed),
                i64
            ),
            (
                "scan_not_found_on_fork",
                not_found_on_fork_accum.load(Ordering::Relaxed),
                i64
            ),
            ("scan_missing", missing_accum.load(Ordering::Relaxed), i64),
            ("uncleaned_roots_len", uncleaned_roots.len(), i64),
            (
                "clean_old_root_us",
                self.clean_accounts_stats
                    .clean_old_root_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "clean_old_root_reclaim_us",
                self.clean_accounts_stats
                    .clean_old_root_reclaim_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "reset_uncleaned_roots_us",
                self.clean_accounts_stats
                    .reset_uncleaned_roots_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "remove_dead_accounts_remove_us",
                self.clean_accounts_stats
                    .remove_dead_accounts_remove_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "remove_dead_accounts_shrink_us",
                self.clean_accounts_stats
                    .remove_dead_accounts_shrink_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "clean_stored_dead_slots_us",
                self.clean_accounts_stats
                    .clean_stored_dead_slots_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "roots_added",
                self.accounts_index.roots_added.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "roots_removed",
                self.accounts_index.roots_removed.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "active_scans",
                self.accounts_index.active_scans.load(Ordering::Relaxed),
                i64
            ),
            (
                "max_distance_to_min_scan_slot",
                self.accounts_index
                    .max_distance_to_min_scan_slot
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "ancient_account_cleans",
                ancient_account_cleans.load(Ordering::Relaxed),
                i64
            ),
            ("next_store_id", self.next_id.load(Ordering::Relaxed), i64),
        );
    }

    /// Removes the accounts in the input `reclaims` from the tracked "count" of
    /// their corresponding  storage entries. Note this does not actually free
    /// the memory from the storage entries until all the storage entries for
    /// a given slot `S` are empty, at which point `process_dead_slots` will
    /// remove all the storage entries for `S`.
    ///
    /// # Arguments
    /// * `reclaims` - The accounts to remove from storage entries' "count". Note here
    ///    that we should not remove cache entries, only entries for accounts actually
    ///    stored in a storage entry.
    ///
    /// * `expected_single_dead_slot` - A correctness assertion. If this is equal to `Some(S)`,
    ///    then the function will check that the only slot being cleaned up in `reclaims`
    ///    is the slot == `S`. This is true for instance when `handle_reclaims` is called
    ///    from store or slot shrinking, as those should only touch the slot they are
    ///    currently storing to or shrinking.
    ///
    /// * `purge_stats_and_reclaim_result` - Option containing `purge_stats` and `reclaim_result`.
    ///    `purge_stats`. `purge_stats` are stats used to track performance of purging dead slots.
    ///    `reclaim_result` contains information about accounts that were removed from storage,
    ///    does not include accounts that were removed from the cache.
    ///    If `purge_stats_and_reclaim_result.is_none()`, this implies there can be no dead slots
    ///    that happen as a result of this call, and the function will check that no slots are
    ///    cleaned up/removed via `process_dead_slots`. For instance, on store, no slots should
    ///    be cleaned up, but during the background clean accounts purges accounts from old rooted
    ///    slots, so outdated slots may be removed.
    ///
    /// * `reset_accounts` - Reset the append_vec store when the store is dead (count==0)
    ///    From the clean and shrink paths it should be false since there may be an in-progress
    ///    hash operation and the stores may hold accounts that need to be unref'ed.
    /// * `pubkeys_removed_from_accounts_index` - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn handle_reclaims<'a, I>(
        &'a self,
        reclaims: Option<I>,
        expected_single_dead_slot: Option<Slot>,
        purge_stats_and_reclaim_result: Option<(&PurgeStats, &mut ReclaimResult)>,
        reset_accounts: bool,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) where
        I: Iterator<Item = &'a (Slot, AccountInfo)>,
    {
        if let Some(reclaims) = reclaims {
            let (purge_stats, purged_account_slots, reclaimed_offsets) = if let Some((
                purge_stats,
                (ref mut purged_account_slots, ref mut reclaimed_offsets),
            )) =
                purge_stats_and_reclaim_result
            {
                (
                    Some(purge_stats),
                    Some(purged_account_slots),
                    Some(reclaimed_offsets),
                )
            } else {
                (None, None, None)
            };

            let dead_slots = self.remove_dead_accounts(
                reclaims,
                expected_single_dead_slot,
                reclaimed_offsets,
                reset_accounts,
            );

            if let Some(purge_stats) = purge_stats {
                if let Some(expected_single_dead_slot) = expected_single_dead_slot {
                    assert!(dead_slots.len() <= 1);
                    if dead_slots.len() == 1 {
                        assert!(dead_slots.contains(&expected_single_dead_slot));
                    }
                }

                self.process_dead_slots(
                    &dead_slots,
                    purged_account_slots,
                    purge_stats,
                    pubkeys_removed_from_accounts_index,
                );
            } else {
                assert!(dead_slots.is_empty());
            }
        }
    }

    /// During clean, some zero-lamport accounts that are marked for purge should *not* actually
    /// get purged.  Filter out those accounts here by removing them from 'purges_zero_lamports'
    ///
    /// When using incremental snapshots, do not purge zero-lamport accounts if the slot is higher
    /// than the last full snapshot slot.  This is to protect against the following scenario:
    ///
    ///   ```text
    ///   A full snapshot is taken, including account 'alpha' with a non-zero balance.  In a later slot,
    ///   alpha's lamports go to zero.  Eventually, cleaning runs.  Without this change,
    ///   alpha would be cleaned up and removed completely. Finally, an incremental snapshot is taken.
    ///
    ///   Later, the incremental and full snapshots are used to rebuild the bank and accounts
    ///   database (e.x. if the node restarts).  The full snapshot _does_ contain alpha
    ///   and its balance is non-zero.  However, since alpha was cleaned up in a slot after the full
    ///   snapshot slot (due to having zero lamports), the incremental snapshot would not contain alpha.
    ///   Thus, the accounts database will contain the old, incorrect info for alpha with a non-zero
    ///   balance.  Very bad!
    ///   ```
    ///
    /// This filtering step can be skipped if there is no `last_full_snapshot_slot`, or if the
    /// `max_clean_root_inclusive` is less-than-or-equal-to the `last_full_snapshot_slot`.
    fn filter_zero_lamport_clean_for_incremental_snapshots(
        &self,
        max_clean_root_inclusive: Option<Slot>,
        last_full_snapshot_slot: Option<Slot>,
        store_counts: &HashMap<Slot, (usize, HashSet<Pubkey>)>,
        purges_zero_lamports: &mut HashMap<Pubkey, (SlotList<AccountInfo>, RefCount)>,
    ) {
        let should_filter_for_incremental_snapshots = max_clean_root_inclusive.unwrap_or(Slot::MAX)
            > last_full_snapshot_slot.unwrap_or(Slot::MAX);
        assert!(
            last_full_snapshot_slot.is_some() || !should_filter_for_incremental_snapshots,
            "if filtering for incremental snapshots, then snapshots should be enabled",
        );

        purges_zero_lamports.retain(|pubkey, (slot_account_infos, _ref_count)| {
            // Only keep purges_zero_lamports where the entire history of the account in the root set
            // can be purged. All AppendVecs for those updates are dead.
            for (slot, _account_info) in slot_account_infos.iter() {
                if let Some(store_count) = store_counts.get(slot) {
                    if store_count.0 != 0 {
                        // one store this pubkey is in is not being removed, so this pubkey cannot be removed at all
                        return false;
                    }
                } else {
                    // store is not being removed, so this pubkey cannot be removed at all
                    return false;
                }
            }

            // Exit early if not filtering more for incremental snapshots
            if !should_filter_for_incremental_snapshots {
                return true;
            }

            let slot_account_info_at_highest_slot = slot_account_infos
                .iter()
                .max_by_key(|(slot, _account_info)| slot);

            slot_account_info_at_highest_slot.map_or(true, |(slot, account_info)| {
                // Do *not* purge zero-lamport accounts if the slot is greater than the last full
                // snapshot slot.  Since we're `retain`ing the accounts-to-purge, I felt creating
                // the `cannot_purge` variable made this easier to understand.  Accounts that do
                // not get purged here are added to a list so they be considered for purging later
                // (i.e. after the next full snapshot).
                assert!(account_info.is_zero_lamport());
                let cannot_purge = *slot > last_full_snapshot_slot.unwrap();
                if cannot_purge {
                    self.zero_lamport_accounts_to_purge_after_full_snapshot
                        .insert((*slot, *pubkey));
                }
                !cannot_purge
            })
        });
    }

    // Must be kept private!, does sensitive cleanup that should only be called from
    // supported pipelines in AccountsDb
    /// pubkeys_removed_from_accounts_index - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn process_dead_slots(
        &self,
        dead_slots: &IntSet<Slot>,
        purged_account_slots: Option<&mut AccountSlots>,
        purge_stats: &PurgeStats,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        if dead_slots.is_empty() {
            return;
        }
        let mut clean_dead_slots = Measure::start("reclaims::clean_dead_slots");
        self.clean_stored_dead_slots(
            dead_slots,
            purged_account_slots,
            pubkeys_removed_from_accounts_index,
        );
        clean_dead_slots.stop();

        let mut purge_removed_slots = Measure::start("reclaims::purge_removed_slots");
        self.purge_dead_slots_from_storage(dead_slots.iter(), purge_stats);
        purge_removed_slots.stop();

        // If the slot is dead, remove the need to shrink the storages as
        // the storage entries will be purged.
        {
            let mut list = self.shrink_candidate_slots.lock().unwrap();
            for slot in dead_slots {
                list.remove(slot);
            }
        }

        debug!(
            "process_dead_slots({}): {} {} {:?}",
            dead_slots.len(),
            clean_dead_slots,
            purge_removed_slots,
            dead_slots,
        );
    }

    /// load the account index entry for the first `count` items in `accounts`
    /// store a reference to all alive accounts in `alive_accounts`
    /// unref and optionally store a reference to all pubkeys that are in the index, but dead in `unrefed_pubkeys`
    /// return sum of account size for all alive accounts
    fn load_accounts_index_for_shrink<'a, T: ShrinkCollectRefs<'a>>(
        &self,
        accounts: &'a [StoredAccountMeta<'a>],
        stats: &ShrinkStats,
        slot_to_shrink: Slot,
    ) -> LoadAccountsIndexForShrink<'a, T> {
        let count = accounts.len();
        let mut alive_accounts = T::with_capacity(count, slot_to_shrink);
        let mut unrefed_pubkeys = Vec::with_capacity(count);

        let mut alive = 0;
        let mut dead = 0;
        let mut index = 0;
        let mut all_are_zero_lamports = true;
        let mut index_entries_being_shrunk = Vec::with_capacity(accounts.len());
        self.accounts_index.scan(
            accounts.iter().map(|account| account.pubkey()),
            |pubkey, slots_refs, entry| {
                let mut result = AccountsIndexScanResult::OnlyKeepInMemoryIfDirty;
                if let Some((slot_list, ref_count)) = slots_refs {
                    let stored_account = &accounts[index];
                    let is_alive = slot_list.iter().any(|(slot, _acct_info)| {
                        // if the accounts index contains an entry at this slot, then the append vec we're asking about contains this item and thus, it is alive at this slot
                        *slot == slot_to_shrink
                    });
                    if !is_alive {
                        // This pubkey was found in the storage, but no longer exists in the index.
                        // It would have had a ref to the storage from the initial store, but it will
                        // not exist in the re-written slot. Unref it to keep the index consistent with
                        // rewriting the storage entries.
                        unrefed_pubkeys.push(pubkey);
                        result = AccountsIndexScanResult::Unref;
                        dead += 1;
                    } else {
                        // Hold onto the index entry arc so that it cannot be flushed.
                        // Since we are shrinking these entries, we need to disambiguate append_vec_ids during this period and those only exist in the in-memory accounts index.
                        index_entries_being_shrunk.push(Arc::clone(entry.unwrap()));
                        all_are_zero_lamports &= stored_account.lamports() == 0;
                        alive_accounts.add(ref_count, stored_account, slot_list);
                        alive += 1;
                    }
                }
                index += 1;
                result
            },
            None,
            true,
        );
        assert_eq!(index, std::cmp::min(accounts.len(), count));
        stats.alive_accounts.fetch_add(alive, Ordering::Relaxed);
        stats.dead_accounts.fetch_add(dead, Ordering::Relaxed);

        LoadAccountsIndexForShrink {
            alive_accounts,
            unrefed_pubkeys,
            all_are_zero_lamports,
            index_entries_being_shrunk,
        }
    }

    /// get all accounts in all the storages passed in
    /// for duplicate pubkeys, the account with the highest write_value is returned
    pub fn get_unique_accounts_from_storage<'a>(
        &self,
        store: &'a Arc<AccountStorageEntry>,
    ) -> GetUniqueAccountsResult<'a> {
        let mut stored_accounts: HashMap<Pubkey, StoredAccountMeta> = HashMap::new();
        let capacity = store.capacity();
        store.accounts.account_iter().for_each(|account| {
            stored_accounts.insert(*account.pubkey(), account);
        });

        // sort by pubkey to keep account index lookups close
        let mut stored_accounts = stored_accounts.drain().map(|(_k, v)| v).collect::<Vec<_>>();
        stored_accounts.sort_unstable_by(|a, b| a.pubkey().cmp(b.pubkey()));

        GetUniqueAccountsResult {
            stored_accounts,
            capacity,
        }
    }

    pub(crate) fn get_unique_accounts_from_storage_for_shrink<'a>(
        &self,
        store: &'a Arc<AccountStorageEntry>,
        stats: &ShrinkStats,
    ) -> GetUniqueAccountsResult<'a> {
        let (result, storage_read_elapsed_us) =
            measure_us!(self.get_unique_accounts_from_storage(store));
        stats
            .storage_read_elapsed
            .fetch_add(storage_read_elapsed_us, Ordering::Relaxed);
        result
    }

    /// shared code for shrinking normal slots and combining into ancient append vecs
    /// note 'unique_accounts' is passed by ref so we can return references to data within it, avoiding self-references
    pub(crate) fn shrink_collect<'a: 'b, 'b, T: ShrinkCollectRefs<'b>>(
        &self,
        store: &'a Arc<AccountStorageEntry>,
        unique_accounts: &'b GetUniqueAccountsResult<'b>,
        stats: &ShrinkStats,
    ) -> ShrinkCollect<'b, T> {
        let slot = store.slot();

        let GetUniqueAccountsResult {
            stored_accounts,
            capacity,
        } = unique_accounts;

        let mut index_read_elapsed = Measure::start("index_read_elapsed");

        let len = stored_accounts.len();
        let alive_accounts_collect = Mutex::new(T::with_capacity(len, slot));
        let unrefed_pubkeys_collect = Mutex::new(Vec::with_capacity(len));
        stats
            .accounts_loaded
            .fetch_add(len as u64, Ordering::Relaxed);
        let all_are_zero_lamports_collect = Mutex::new(true);
        let index_entries_being_shrunk_outer = Mutex::new(Vec::default());
        self.thread_pool_clean.install(|| {
            stored_accounts
                .par_chunks(SHRINK_COLLECT_CHUNK_SIZE)
                .for_each(|stored_accounts| {
                    let LoadAccountsIndexForShrink {
                        alive_accounts,
                        mut unrefed_pubkeys,
                        all_are_zero_lamports,
                        mut index_entries_being_shrunk,
                    } = self.load_accounts_index_for_shrink(stored_accounts, stats, slot);

                    // collect
                    alive_accounts_collect
                        .lock()
                        .unwrap()
                        .collect(alive_accounts);
                    unrefed_pubkeys_collect
                        .lock()
                        .unwrap()
                        .append(&mut unrefed_pubkeys);
                    index_entries_being_shrunk_outer
                        .lock()
                        .unwrap()
                        .append(&mut index_entries_being_shrunk);
                    if !all_are_zero_lamports {
                        *all_are_zero_lamports_collect.lock().unwrap() = false;
                    }
                });
        });

        let alive_accounts = alive_accounts_collect.into_inner().unwrap();
        let unrefed_pubkeys = unrefed_pubkeys_collect.into_inner().unwrap();

        index_read_elapsed.stop();
        stats
            .index_read_elapsed
            .fetch_add(index_read_elapsed.as_us(), Ordering::Relaxed);

        let alive_total_bytes = alive_accounts.alive_bytes();

        let aligned_total_bytes: u64 = Self::page_align(alive_total_bytes as u64);

        stats
            .accounts_removed
            .fetch_add(len - alive_accounts.len(), Ordering::Relaxed);
        stats.bytes_removed.fetch_add(
            capacity.saturating_sub(aligned_total_bytes),
            Ordering::Relaxed,
        );
        stats
            .bytes_written
            .fetch_add(aligned_total_bytes, Ordering::Relaxed);

        ShrinkCollect {
            slot,
            capacity: *capacity,
            unrefed_pubkeys,
            alive_accounts,
            alive_total_bytes,
            total_starting_accounts: len,
            all_are_zero_lamports: all_are_zero_lamports_collect.into_inner().unwrap(),
            _index_entries_being_shrunk: index_entries_being_shrunk_outer.into_inner().unwrap(),
        }
    }

    /// common code from shrink and combine_ancient_slots
    /// get rid of all original store_ids in the slot
    pub(crate) fn remove_old_stores_shrink<'a, T: ShrinkCollectRefs<'a>>(
        &self,
        shrink_collect: &ShrinkCollect<'a, T>,
        stats: &ShrinkStats,
        shrink_in_progress: Option<ShrinkInProgress>,
        shrink_can_be_active: bool,
    ) {
        let mut time = Measure::start("remove_old_stores_shrink");
        // Purge old, overwritten storage entries
        let dead_storages = self.mark_dirty_dead_stores(
            shrink_collect.slot,
            // If all accounts are zero lamports, then we want to mark the entire OLD append vec as dirty.
            // otherwise, we'll call 'add_uncleaned_pubkeys_after_shrink' just on the unref'd keys below.
            shrink_collect.all_are_zero_lamports,
            shrink_in_progress,
            shrink_can_be_active,
        );

        if !shrink_collect.all_are_zero_lamports {
            self.add_uncleaned_pubkeys_after_shrink(
                shrink_collect.slot,
                shrink_collect.unrefed_pubkeys.iter().cloned().cloned(),
            );
        }

        self.drop_or_recycle_stores(dead_storages, stats);
        time.stop();

        stats
            .remove_old_stores_shrink_us
            .fetch_add(time.as_us(), Ordering::Relaxed);
    }

    fn do_shrink_slot_store(&self, slot: Slot, store: &Arc<AccountStorageEntry>) {
        if self.accounts_cache.contains(slot) {
            // It is not correct to shrink a slot while it is in the write cache until flush is complete and the slot is removed from the write cache.
            // There can exist a window after a slot is made a root and before the write cache flushing for that slot begins and then completes.
            // There can also exist a window after a slot is being flushed from the write cache until the index is updated and the slot is removed from the write cache.
            // During the second window, once an append vec has been created for the slot, it could be possible to try to shrink that slot.
            // Shrink no-ops before this function if there is no store for the slot (notice this function requires 'store' to be passed).
            // So, if we enter this function but the slot is still in the write cache, reasonable behavior is to skip shrinking this slot.
            // Flush will ONLY write alive accounts to the append vec, which is what shrink does anyway.
            // Flush then adds the slot to 'uncleaned_roots', which causes clean to take a look at the slot.
            // Clean causes us to mark accounts as dead, which causes shrink to later take a look at the slot.
            // This could be an assert, but it could lead to intermittency in tests.
            // It is 'correct' to ignore calls to shrink when a slot is still in the write cache.
            return;
        }
        let unique_accounts =
            self.get_unique_accounts_from_storage_for_shrink(store, &self.shrink_stats);
        debug!("do_shrink_slot_store: slot: {}", slot);
        let shrink_collect =
            self.shrink_collect::<AliveAccounts<'_>>(store, &unique_accounts, &self.shrink_stats);

        // This shouldn't happen if alive_bytes/approx_stored_count are accurate
        if Self::should_not_shrink(
            shrink_collect.alive_total_bytes as u64,
            shrink_collect.capacity,
        ) {
            self.shrink_stats
                .skipped_shrink
                .fetch_add(1, Ordering::Relaxed);
            for pubkey in shrink_collect.unrefed_pubkeys {
                if let Some(locked_entry) = self.accounts_index.get_account_read_entry(pubkey) {
                    // pubkeys in `unrefed_pubkeys` were unref'd in `shrink_collect` above under the assumption that we would shrink everything.
                    // Since shrink is not occurring, we need to addref the pubkeys to get the system back to the prior state since the account still exists at this slot.
                    locked_entry.addref();
                }
            }
            return;
        }

        let total_accounts_after_shrink = shrink_collect.alive_accounts.len();
        debug!(
            "shrinking: slot: {}, accounts: ({} => {}) bytes: {} original: {}",
            slot,
            shrink_collect.total_starting_accounts,
            total_accounts_after_shrink,
            shrink_collect.alive_total_bytes,
            shrink_collect.capacity,
        );

        let mut stats_sub = ShrinkStatsSub::default();
        let mut rewrite_elapsed = Measure::start("rewrite_elapsed");
        if shrink_collect.alive_total_bytes > 0 {
            let (shrink_in_progress, time_us) = measure_us!(
                self.get_store_for_shrink(slot, shrink_collect.alive_total_bytes as u64)
            );
            stats_sub.create_and_insert_store_elapsed_us = time_us;

            // here, we're writing back alive_accounts. That should be an atomic operation
            // without use of rather wide locks in this whole function, because we're
            // mutating rooted slots; There should be no writers to them.
            stats_sub.store_accounts_timing = self.store_accounts_frozen(
                (slot, &shrink_collect.alive_accounts.alive_accounts()[..]),
                None::<Vec<AccountHash>>,
                shrink_in_progress.new_storage(),
                None,
                StoreReclaims::Ignore,
            );

            rewrite_elapsed.stop();
            stats_sub.rewrite_elapsed_us = rewrite_elapsed.as_us();

            // `store_accounts_frozen()` above may have purged accounts from some
            // other storage entries (the ones that were just overwritten by this
            // new storage entry). This means some of those stores might have caused
            // this slot to be read to `self.shrink_candidate_slots`, so delete
            // those here
            self.shrink_candidate_slots.lock().unwrap().remove(&slot);

            self.remove_old_stores_shrink(
                &shrink_collect,
                &self.shrink_stats,
                Some(shrink_in_progress),
                false,
            );
        }

        Self::update_shrink_stats(&self.shrink_stats, stats_sub, true);
        self.shrink_stats.report();
    }

    pub(crate) fn update_shrink_stats(
        shrink_stats: &ShrinkStats,
        stats_sub: ShrinkStatsSub,
        increment_count: bool,
    ) {
        if increment_count {
            shrink_stats
                .num_slots_shrunk
                .fetch_add(1, Ordering::Relaxed);
        }
        shrink_stats.create_and_insert_store_elapsed.fetch_add(
            stats_sub.create_and_insert_store_elapsed_us,
            Ordering::Relaxed,
        );
        shrink_stats.store_accounts_elapsed.fetch_add(
            stats_sub.store_accounts_timing.store_accounts_elapsed,
            Ordering::Relaxed,
        );
        shrink_stats.update_index_elapsed.fetch_add(
            stats_sub.store_accounts_timing.update_index_elapsed,
            Ordering::Relaxed,
        );
        shrink_stats.handle_reclaims_elapsed.fetch_add(
            stats_sub.store_accounts_timing.handle_reclaims_elapsed,
            Ordering::Relaxed,
        );
        shrink_stats
            .rewrite_elapsed
            .fetch_add(stats_sub.rewrite_elapsed_us, Ordering::Relaxed);
        shrink_stats
            .unpackable_slots_count
            .fetch_add(stats_sub.unpackable_slots_count as u64, Ordering::Relaxed);
        shrink_stats.newest_alive_packed_count.fetch_add(
            stats_sub.newest_alive_packed_count as u64,
            Ordering::Relaxed,
        );
    }

    /// get stores for 'slot'
    /// Drop 'shrink_in_progress', which will cause the old store to be removed from the storage map.
    /// For 'shrink_in_progress'.'old_storage' which is not retained, insert in 'dead_storages' and optionally 'dirty_stores'
    /// This is the end of the life cycle of `shrink_in_progress`.
    pub fn mark_dirty_dead_stores(
        &self,
        slot: Slot,
        add_dirty_stores: bool,
        shrink_in_progress: Option<ShrinkInProgress>,
        shrink_can_be_active: bool,
    ) -> Vec<Arc<AccountStorageEntry>> {
        let mut dead_storages = Vec::default();

        let mut not_retaining_store = |store: &Arc<AccountStorageEntry>| {
            if add_dirty_stores {
                self.dirty_stores.insert(slot, store.clone());
            }
            dead_storages.push(store.clone());
        };

        if let Some(shrink_in_progress) = shrink_in_progress {
            // shrink is in progress, so 1 new append vec to keep, 1 old one to throw away
            not_retaining_store(shrink_in_progress.old_storage());
            // dropping 'shrink_in_progress' removes the old append vec that was being shrunk from db's storage
        } else if let Some(store) = self.storage.remove(&slot, shrink_can_be_active) {
            // no shrink in progress, so all append vecs in this slot are dead
            not_retaining_store(&store);
        }

        dead_storages
    }

    pub fn drop_or_recycle_stores(
        &self,
        dead_storages: Vec<Arc<AccountStorageEntry>>,
        stats: &ShrinkStats,
    ) {
        let mut recycle_stores_write_elapsed = Measure::start("recycle_stores_write_time");
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        recycle_stores_write_elapsed.stop();

        let mut drop_storage_entries_elapsed = Measure::start("drop_storage_entries_elapsed");
        if recycle_stores.entry_count() < MAX_RECYCLE_STORES {
            recycle_stores.add_entries(dead_storages);
            drop(recycle_stores);
        } else {
            self.stats
                .dropped_stores
                .fetch_add(dead_storages.len() as u64, Ordering::Relaxed);
            drop(recycle_stores);
            drop(dead_storages);
        }
        drop_storage_entries_elapsed.stop();
        stats
            .drop_storage_entries_elapsed
            .fetch_add(drop_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        stats
            .recycle_stores_write_elapsed
            .fetch_add(recycle_stores_write_elapsed.as_us(), Ordering::Relaxed);
    }

    /// return a store that can contain 'aligned_total' bytes
    pub fn get_store_for_shrink(&self, slot: Slot, aligned_total: u64) -> ShrinkInProgress<'_> {
        let shrunken_store = self
            .try_recycle_store(slot, aligned_total, aligned_total + 1024)
            .unwrap_or_else(|| {
                let maybe_shrink_paths = self.shrink_paths.read().unwrap();
                let (shrink_paths, from) = maybe_shrink_paths
                    .as_ref()
                    .map(|paths| (paths, "shrink-w-path"))
                    .unwrap_or_else(|| (&self.paths, "shrink"));
                self.create_store(slot, aligned_total, from, shrink_paths)
            });
        self.storage.shrinking_in_progress(slot, shrunken_store)
    }

    // Reads all accounts in given slot's AppendVecs and filter only to alive,
    // then create a minimum AppendVec filled with the alive.
    fn shrink_slot_forced(&self, slot: Slot) {
        debug!("shrink_slot_forced: slot: {}", slot);

        if let Some(store) = self
            .storage
            .get_slot_storage_entry_shrinking_in_progress_ok(slot)
        {
            if !Self::is_shrinking_productive(slot, &store) {
                return;
            }
            self.do_shrink_slot_store(slot, &store)
        }
    }

    fn all_slots_in_storage(&self) -> Vec<Slot> {
        self.storage.all_slots()
    }

    /// Given the input `ShrinkCandidates`, this function sorts the stores by their alive ratio
    /// in increasing order with the most sparse entries in the front. It will then simulate the
    /// shrinking by working on the most sparse entries first and if the overall alive ratio is
    /// achieved, it will stop and return:
    /// first tuple element: the filtered-down candidates and
    /// second duple element: the candidates which
    /// are skipped in this round and might be eligible for the future shrink.
    fn select_candidates_by_total_usage(
        &self,
        shrink_slots: &ShrinkCandidates,
        shrink_ratio: f64,
        oldest_non_ancient_slot: Option<Slot>,
    ) -> (IntMap<Slot, Arc<AccountStorageEntry>>, ShrinkCandidates) {
        struct StoreUsageInfo {
            slot: Slot,
            alive_ratio: f64,
            store: Arc<AccountStorageEntry>,
        }
        let mut measure = Measure::start("select_top_sparse_storage_entries-ms");
        let mut store_usage: Vec<StoreUsageInfo> = Vec::with_capacity(shrink_slots.len());
        let mut total_alive_bytes: u64 = 0;
        let mut candidates_count: usize = 0;
        let mut total_bytes: u64 = 0;
        let mut total_candidate_stores: usize = 0;
        for slot in shrink_slots {
            if oldest_non_ancient_slot
                .map(|oldest_non_ancient_slot| slot < &oldest_non_ancient_slot)
                .unwrap_or_default()
            {
                // this slot will be 'shrunk' by ancient code
                continue;
            }
            let Some(store) = self.storage.get_slot_storage_entry(*slot) else {
                continue;
            };
            candidates_count += 1;
            total_alive_bytes += Self::page_align(store.alive_bytes() as u64);
            total_bytes += store.capacity();
            let alive_ratio =
                Self::page_align(store.alive_bytes() as u64) as f64 / store.capacity() as f64;
            store_usage.push(StoreUsageInfo {
                slot: *slot,
                alive_ratio,
                store: store.clone(),
            });
            total_candidate_stores += 1;
        }
        store_usage.sort_by(|a, b| {
            a.alive_ratio
                .partial_cmp(&b.alive_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Working from the beginning of store_usage which are the most sparse and see when we can stop
        // shrinking while still achieving the overall goals.
        let mut shrink_slots = IntMap::default();
        let mut shrink_slots_next_batch = ShrinkCandidates::default();
        for usage in &store_usage {
            let store = &usage.store;
            let alive_ratio = (total_alive_bytes as f64) / (total_bytes as f64);
            debug!("alive_ratio: {:?} store_id: {:?}, store_ratio: {:?} requirement: {:?}, total_bytes: {:?} total_alive_bytes: {:?}",
                alive_ratio, usage.store.append_vec_id(), usage.alive_ratio, shrink_ratio, total_bytes, total_alive_bytes);
            if alive_ratio > shrink_ratio {
                // we have reached our goal, stop
                debug!(
                    "Shrinking goal can be achieved at slot {:?}, total_alive_bytes: {:?} \
                    total_bytes: {:?}, alive_ratio: {:}, shrink_ratio: {:?}",
                    usage.slot, total_alive_bytes, total_bytes, alive_ratio, shrink_ratio
                );
                if usage.alive_ratio < shrink_ratio {
                    shrink_slots_next_batch.insert(usage.slot);
                } else {
                    break;
                }
            } else {
                let current_store_size = store.capacity();
                let after_shrink_size = Self::page_align(store.alive_bytes() as u64);
                let bytes_saved = current_store_size.saturating_sub(after_shrink_size);
                total_bytes -= bytes_saved;
                shrink_slots.insert(usage.slot, Arc::clone(store));
            }
        }
        measure.stop();
        inc_new_counter_debug!(
            "shrink_select_top_sparse_storage_entries-ms",
            measure.as_ms() as usize
        );
        inc_new_counter_debug!(
            "shrink_select_top_sparse_storage_entries-seeds",
            candidates_count
        );
        inc_new_counter_debug!(
            "shrink_total_preliminary_candidate_stores",
            total_candidate_stores
        );

        (shrink_slots, shrink_slots_next_batch)
    }

    fn get_roots_less_than(&self, slot: Slot) -> Vec<Slot> {
        self.accounts_index
            .roots_tracker
            .read()
            .unwrap()
            .alive_roots
            .get_all_less_than(slot)
    }

    /// return all slots that are more than one epoch old and thus could already be an ancient append vec
    /// or which could need to be combined into a new or existing ancient append vec
    /// offset is used to combine newer slots than we normally would. This is designed to be used for testing.
    fn get_sorted_potential_ancient_slots(&self, oldest_non_ancient_slot: Slot) -> Vec<Slot> {
        let mut ancient_slots = self.get_roots_less_than(oldest_non_ancient_slot);
        ancient_slots.sort_unstable();
        ancient_slots
    }

    /// get a sorted list of slots older than an epoch
    /// squash those slots into ancient append vecs
    pub fn shrink_ancient_slots(&self, epoch_schedule: &EpochSchedule) {
        if self.ancient_append_vec_offset.is_none() {
            return;
        }

        let oldest_non_ancient_slot = self.get_oldest_non_ancient_slot(epoch_schedule);
        let can_randomly_shrink = true;
        let sorted_slots = self.get_sorted_potential_ancient_slots(oldest_non_ancient_slot);
        if self.create_ancient_storage == CreateAncientStorage::Append {
            self.combine_ancient_slots(sorted_slots, can_randomly_shrink);
        } else {
            self.combine_ancient_slots_packed(sorted_slots, can_randomly_shrink);
        }
    }

    /// 'accounts' that exist in the current slot we are combining into a different ancient slot
    /// 'existing_ancient_pubkeys': pubkeys that exist currently in the ancient append vec slot
    /// returns the pubkeys that are in 'accounts' that are already in 'existing_ancient_pubkeys'
    /// Also updated 'existing_ancient_pubkeys' to include all pubkeys in 'accounts' since they will soon be written into the ancient slot.
    fn get_keys_to_unref_ancient<'a>(
        accounts: &'a [&StoredAccountMeta<'_>],
        existing_ancient_pubkeys: &mut HashSet<Pubkey>,
    ) -> HashSet<&'a Pubkey> {
        let mut unref = HashSet::<&Pubkey>::default();
        // for each key that we're about to add that already exists in this storage, we need to unref. The account was in a different storage.
        // Now it is being put into an ancient storage again, but it is already there, so maintain max of 1 ref per storage in the accounts index.
        // The slot that currently references the account is going away, so unref to maintain # slots that reference the pubkey = refcount.
        accounts.iter().for_each(|account| {
            let key = account.pubkey();
            if !existing_ancient_pubkeys.insert(*key) {
                // this key exists BOTH in 'accounts' and already in the ancient append vec, so we need to unref it
                unref.insert(key);
            }
        });
        unref
    }

    /// 'accounts' are about to be appended to an ancient append vec. That ancient append vec may already have some accounts.
    /// Unref each account in 'accounts' that already exists in 'existing_ancient_pubkeys'.
    /// As a side effect, on exit, 'existing_ancient_pubkeys' will now contain all pubkeys in 'accounts'.
    fn unref_accounts_already_in_storage(
        &self,
        accounts: &[&StoredAccountMeta<'_>],
        existing_ancient_pubkeys: &mut HashSet<Pubkey>,
    ) {
        let unref = Self::get_keys_to_unref_ancient(accounts, existing_ancient_pubkeys);

        self.unref_pubkeys(
            unref.iter().cloned(),
            unref.len(),
            &PubkeysRemovedFromAccountsIndex::default(),
        );
    }

    /// get the storage from 'slot' to squash
    /// or None if this slot should be skipped
    /// side effect could be updating 'current_ancient'
    fn get_storage_to_move_to_ancient_append_vec(
        &self,
        slot: Slot,
        current_ancient: &mut CurrentAncientAppendVec,
        can_randomly_shrink: bool,
    ) -> Option<Arc<AccountStorageEntry>> {
        self.storage
            .get_slot_storage_entry(slot)
            .and_then(|storage| {
                self.should_move_to_ancient_append_vec(
                    &storage,
                    current_ancient,
                    slot,
                    can_randomly_shrink,
                )
                .then_some(storage)
            })
    }

    /// return true if the accounts in this slot should be moved to an ancient append vec
    /// otherwise, return false and the caller can skip this slot
    /// side effect could be updating 'current_ancient'
    /// can_randomly_shrink: true if ancient append vecs that otherwise don't qualify to be shrunk can be randomly shrunk
    ///  this is convenient for a running system
    ///  this is not useful for testing
    fn should_move_to_ancient_append_vec(
        &self,
        storage: &Arc<AccountStorageEntry>,
        current_ancient: &mut CurrentAncientAppendVec,
        slot: Slot,
        can_randomly_shrink: bool,
    ) -> bool {
        let accounts = &storage.accounts;

        self.shrink_ancient_stats
            .slots_considered
            .fetch_add(1, Ordering::Relaxed);

        if is_ancient(accounts) {
            self.shrink_ancient_stats
                .ancient_scanned
                .fetch_add(1, Ordering::Relaxed);

            // randomly shrink ancient slots
            // this exercises the ancient shrink code more often
            let written_bytes = storage.written_bytes();
            let mut alive_ratio = 0;
            let is_candidate = if written_bytes > 0 {
                alive_ratio = (storage.alive_bytes() as u64) * 100 / written_bytes;
                alive_ratio < 90
            } else {
                false
            };
            if is_candidate || (can_randomly_shrink && thread_rng().gen_range(0..10000) == 0) {
                // we are a candidate for shrink, so either append us to the previous append vec
                // or recreate us as a new append vec and eliminate the dead accounts
                info!(
                    "ancient_append_vec: shrinking full ancient: {}, random: {}, alive_ratio: {}",
                    slot, !is_candidate, alive_ratio
                );
                if !is_candidate {
                    self.shrink_ancient_stats
                        .random_shrink
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.shrink_ancient_stats
                    .ancient_append_vecs_shrunk
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
            // this slot is ancient and can become the 'current' ancient for other slots to be squashed into
            *current_ancient = CurrentAncientAppendVec::new(slot, Arc::clone(storage));
            return false; // we're done with this slot - this slot IS the ancient append vec
        }

        // otherwise, yes, squash this slot into the current ancient append vec or create one at this slot
        true
    }

    /// Combine all account data from storages in 'sorted_slots' into ancient append vecs.
    /// This keeps us from accumulating append vecs for each slot older than an epoch.
    fn combine_ancient_slots(&self, sorted_slots: Vec<Slot>, can_randomly_shrink: bool) {
        if sorted_slots.is_empty() {
            return;
        }

        let mut total = Measure::start("combine_ancient_slots");
        let mut guard = None;

        // the ancient append vec currently being written to
        let mut current_ancient = CurrentAncientAppendVec::default();
        let mut dropped_roots = vec![];

        // we have to keep track of what pubkeys exist in the current ancient append vec so we can unref correctly
        let mut ancient_slot_pubkeys = AncientSlotPubkeys::default();

        let len = sorted_slots.len();
        for slot in sorted_slots {
            let Some(old_storage) = self.get_storage_to_move_to_ancient_append_vec(
                slot,
                &mut current_ancient,
                can_randomly_shrink,
            ) else {
                // nothing to squash for this slot
                continue;
            };

            if guard.is_none() {
                // we are now doing interesting work in squashing ancient
                guard = Some(self.active_stats.activate(ActiveStatItem::SquashAncient));
                info!(
                    "ancient_append_vec: combine_ancient_slots first slot: {}, num_roots: {}",
                    slot, len
                );
            }

            self.combine_one_store_into_ancient(
                slot,
                &old_storage,
                &mut current_ancient,
                &mut ancient_slot_pubkeys,
                &mut dropped_roots,
            );
        }

        self.handle_dropped_roots_for_ancient(dropped_roots.into_iter());

        total.stop();
        self.shrink_ancient_stats
            .total_us
            .fetch_add(total.as_us(), Ordering::Relaxed);

        // only log when we moved some accounts to ancient append vecs or we've exceeded 100ms
        // results will continue to accumulate otherwise
        if guard.is_some() || self.shrink_ancient_stats.total_us.load(Ordering::Relaxed) > 100_000 {
            self.shrink_ancient_stats.report();
        }
    }

    /// put entire alive contents of 'old_storage' into the current ancient append vec or a newly created ancient append vec
    fn combine_one_store_into_ancient(
        &self,
        slot: Slot,
        old_storage: &Arc<AccountStorageEntry>,
        current_ancient: &mut CurrentAncientAppendVec,
        ancient_slot_pubkeys: &mut AncientSlotPubkeys,
        dropped_roots: &mut Vec<Slot>,
    ) {
        let unique_accounts = self.get_unique_accounts_from_storage_for_shrink(
            old_storage,
            &self.shrink_ancient_stats.shrink_stats,
        );
        let shrink_collect = self.shrink_collect::<AliveAccounts<'_>>(
            old_storage,
            &unique_accounts,
            &self.shrink_ancient_stats.shrink_stats,
        );

        // could follow what shrink does more closely
        if shrink_collect.total_starting_accounts == 0 || shrink_collect.alive_total_bytes == 0 {
            return; // skipping slot with no useful accounts to write
        }

        let mut stats_sub = ShrinkStatsSub::default();
        let mut bytes_remaining_to_write = shrink_collect.alive_total_bytes;
        let (mut shrink_in_progress, create_and_insert_store_elapsed_us) = measure_us!(
            current_ancient.create_if_necessary(slot, self, shrink_collect.alive_total_bytes)
        );
        stats_sub.create_and_insert_store_elapsed_us = create_and_insert_store_elapsed_us;
        let available_bytes = current_ancient.append_vec().accounts.remaining_bytes();
        // split accounts in 'slot' into:
        // 'Primary', which can fit in 'current_ancient'
        // 'Overflow', which will have to go into a new ancient append vec at 'slot'
        let to_store = AccountsToStore::new(
            available_bytes,
            shrink_collect.alive_accounts.alive_accounts(),
            shrink_collect.alive_total_bytes,
            slot,
        );

        ancient_slot_pubkeys.maybe_unref_accounts_already_in_ancient(
            slot,
            self,
            current_ancient,
            &to_store,
        );

        let mut rewrite_elapsed = Measure::start("rewrite_elapsed");
        // write what we can to the current ancient storage
        let (store_accounts_timing, bytes_written) =
            current_ancient.store_ancient_accounts(self, &to_store, StorageSelector::Primary);
        stats_sub.store_accounts_timing = store_accounts_timing;
        bytes_remaining_to_write = bytes_remaining_to_write.saturating_sub(bytes_written as usize);

        // handle accounts from 'slot' which did not fit into the current ancient append vec
        if to_store.has_overflow() {
            // We need a new ancient append vec at this slot.
            // Assert: it cannot be the case that we already had an ancient append vec at this slot and
            // yet that ancient append vec does not have room for the accounts stored at this slot currently
            assert_ne!(slot, current_ancient.slot());

            // Now we create an ancient append vec at `slot` to store the overflows.
            let (shrink_in_progress_overflow, time_us) = measure_us!(current_ancient
                .create_ancient_append_vec(
                    slot,
                    self,
                    to_store.get_bytes(StorageSelector::Overflow)
                ));
            stats_sub.create_and_insert_store_elapsed_us += time_us;
            // We cannot possibly be shrinking the original slot that created an ancient append vec
            // AND not have enough room in the ancient append vec at that slot
            // to hold all the contents of that slot.
            // We need this new 'shrink_in_progress' to be used in 'remove_old_stores_shrink' below.
            // All non-overflow accounts were put in a prior slot's ancient append vec. All overflow accounts
            // are essentially being shrunk into a new ancient append vec in 'slot'.
            assert!(shrink_in_progress.is_none());
            shrink_in_progress = Some(shrink_in_progress_overflow);

            // write the overflow accounts to the next ancient storage
            let (store_accounts_timing, bytes_written) =
                current_ancient.store_ancient_accounts(self, &to_store, StorageSelector::Overflow);
            bytes_remaining_to_write =
                bytes_remaining_to_write.saturating_sub(bytes_written as usize);

            stats_sub
                .store_accounts_timing
                .accumulate(&store_accounts_timing);
        }
        assert_eq!(bytes_remaining_to_write, 0);
        rewrite_elapsed.stop();
        stats_sub.rewrite_elapsed_us = rewrite_elapsed.as_us();

        if slot != current_ancient.slot() {
            // all append vecs in this slot have been combined into an ancient append vec
            dropped_roots.push(slot);
        }

        self.remove_old_stores_shrink(
            &shrink_collect,
            &self.shrink_ancient_stats.shrink_stats,
            shrink_in_progress,
            false,
        );

        // we should not try to shrink any of the stores from this slot anymore. All shrinking for this slot is now handled by ancient append vec code.
        self.shrink_candidate_slots.lock().unwrap().remove(&slot);

        Self::update_shrink_stats(&self.shrink_ancient_stats.shrink_stats, stats_sub, true);
    }

    /// each slot in 'dropped_roots' has been combined into an ancient append vec.
    /// We are done with the slot now forever.
    pub(crate) fn handle_dropped_roots_for_ancient(
        &self,
        dropped_roots: impl Iterator<Item = Slot>,
    ) {
        let mut accounts_delta_hashes = self.accounts_delta_hashes.lock().unwrap();
        let mut bank_hash_stats = self.bank_hash_stats.lock().unwrap();

        dropped_roots.for_each(|slot| {
            self.accounts_index.clean_dead_slot(slot);
            accounts_delta_hashes.remove(&slot);
            bank_hash_stats.remove(&slot);
            // the storage has been removed from this slot and recycled or dropped
            assert!(self.storage.remove(&slot, false).is_none());
            debug_assert!(
                !self
                    .accounts_index
                    .roots_tracker
                    .read()
                    .unwrap()
                    .alive_roots
                    .contains(&slot),
                "slot: {slot}"
            );
        });
    }

    /// add all 'pubkeys' into the set of pubkeys that are 'uncleaned', associated with 'slot'
    /// clean will visit these pubkeys next time it runs
    fn add_uncleaned_pubkeys_after_shrink(
        &self,
        slot: Slot,
        pubkeys: impl Iterator<Item = Pubkey>,
    ) {
        /*
        This is only called during 'shrink'-type operations.
        Original accounts were separated into 'accounts' and 'unrefed_pubkeys'.
        These sets correspond to 'alive' and 'dead'.
        'alive' means this account in this slot is in the accounts index.
        'dead' means this account in this slot is NOT in the accounts index.
        If dead, nobody will care if this version of this account is not written into the newly shrunk append vec for this slot.
        For all dead accounts, they were already unrefed and are now absent in the new append vec.
        This means that another version of this pubkey could possibly now be cleaned since this one is now gone.
        For example, a zero lamport account in a later slot can be removed if we just removed the only non-zero lamport account for that pubkey in this slot.
        So, for all unrefed accounts, send them to clean to be revisited next time clean runs.
        If an account is alive, then its status has not changed. It was previously alive in this slot. It is still alive in this slot.
        Clean doesn't care about alive accounts that remain alive.
        Except... A slightly different case is if ALL the alive accounts in this slot are zero lamport accounts, then it is possible that
        this slot can be marked dead. So, if all alive accounts are zero lamports, we send the entire OLD/pre-shrunk append vec
        to clean so that all the pubkeys are visited.
        It is a performance optimization to not send the ENTIRE old/pre-shrunk append vec to clean in the normal case.
        */

        let mut uncleaned_pubkeys = self.uncleaned_pubkeys.entry(slot).or_default();
        uncleaned_pubkeys.extend(pubkeys);
    }

    pub fn shrink_candidate_slots(&self, epoch_schedule: &EpochSchedule) -> usize {
        let oldest_non_ancient_slot = self.get_oldest_non_ancient_slot(epoch_schedule);

        let shrink_candidates_slots =
            std::mem::take(&mut *self.shrink_candidate_slots.lock().unwrap());

        let (shrink_slots, shrink_slots_next_batch) = {
            if let AccountShrinkThreshold::TotalSpace { shrink_ratio } = self.shrink_ratio {
                let (shrink_slots, shrink_slots_next_batch) = self
                    .select_candidates_by_total_usage(
                        &shrink_candidates_slots,
                        shrink_ratio,
                        self.ancient_append_vec_offset
                            .map(|_| oldest_non_ancient_slot),
                    );
                (shrink_slots, Some(shrink_slots_next_batch))
            } else {
                (
                    // lookup storage for each slot
                    shrink_candidates_slots
                        .into_iter()
                        .filter_map(|slot| {
                            self.storage
                                .get_slot_storage_entry(slot)
                                .map(|storage| (slot, storage))
                        })
                        .collect(),
                    None,
                )
            }
        };

        if shrink_slots.is_empty()
            && shrink_slots_next_batch
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true)
        {
            return 0;
        }

        let _guard = self.active_stats.activate(ActiveStatItem::Shrink);

        let mut measure_shrink_all_candidates = Measure::start("shrink_all_candidate_slots-ms");
        let num_candidates = shrink_slots.len();
        let shrink_candidates_count = shrink_slots.len();
        self.thread_pool_clean.install(|| {
            shrink_slots
                .into_par_iter()
                .for_each(|(slot, slot_shrink_candidate)| {
                    let mut measure = Measure::start("shrink_candidate_slots-ms");
                    self.do_shrink_slot_store(slot, &slot_shrink_candidate);
                    measure.stop();
                    inc_new_counter_info!("shrink_candidate_slots-ms", measure.as_ms() as usize);
                });
        });
        measure_shrink_all_candidates.stop();
        inc_new_counter_info!(
            "shrink_all_candidate_slots-ms",
            measure_shrink_all_candidates.as_ms() as usize
        );
        inc_new_counter_info!("shrink_all_candidate_slots-count", shrink_candidates_count);
        let mut pended_counts: usize = 0;
        if let Some(shrink_slots_next_batch) = shrink_slots_next_batch {
            let mut shrink_slots = self.shrink_candidate_slots.lock().unwrap();
            pended_counts += shrink_slots_next_batch.len();
            for slot in shrink_slots_next_batch {
                shrink_slots.insert(slot);
            }
        }
        inc_new_counter_info!("shrink_pended_stores-count", pended_counts);

        num_candidates
    }

    pub fn shrink_all_slots(
        &self,
        is_startup: bool,
        last_full_snapshot_slot: Option<Slot>,
        epoch_schedule: &EpochSchedule,
    ) {
        let _guard = self.active_stats.activate(ActiveStatItem::Shrink);
        const DIRTY_STORES_CLEANING_THRESHOLD: usize = 10_000;
        const OUTER_CHUNK_SIZE: usize = 2000;
        if is_startup {
            let slots = self.all_slots_in_storage();
            let threads = num_cpus::get();
            let inner_chunk_size = std::cmp::max(OUTER_CHUNK_SIZE / threads, 1);
            slots.chunks(OUTER_CHUNK_SIZE).for_each(|chunk| {
                chunk.par_chunks(inner_chunk_size).for_each(|slots| {
                    for slot in slots {
                        self.shrink_slot_forced(*slot);
                    }
                });
                if self.dirty_stores.len() > DIRTY_STORES_CLEANING_THRESHOLD {
                    self.clean_accounts(None, is_startup, last_full_snapshot_slot, epoch_schedule);
                }
            });
        } else {
            for slot in self.all_slots_in_storage() {
                self.shrink_slot_forced(slot);
                if self.dirty_stores.len() > DIRTY_STORES_CLEANING_THRESHOLD {
                    self.clean_accounts(None, is_startup, last_full_snapshot_slot, epoch_schedule);
                }
            }
        }
    }

    pub fn scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        mut scan_func: F,
        config: &ScanConfig,
    ) -> ScanResult<()>
    where
        F: FnMut(Option<(&Pubkey, AccountSharedData, Slot)>),
    {
        // This can error out if the slots being scanned over are aborted
        self.accounts_index.scan_accounts(
            ancestors,
            bank_id,
            |pubkey, (account_info, slot)| {
                let account_slot = self
                    .get_account_accessor(slot, pubkey, &account_info.storage_location())
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot));
                scan_func(account_slot)
            },
            config,
        )?;

        Ok(())
    }

    pub fn unchecked_scan_accounts<F>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        mut scan_func: F,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, LoadedAccount, Slot),
    {
        self.accounts_index.unchecked_scan_accounts(
            metric_name,
            ancestors,
            |pubkey, (account_info, slot)| {
                if let Some(loaded_account) = self
                    .get_account_accessor(slot, pubkey, &account_info.storage_location())
                    .get_loaded_account()
                {
                    scan_func(pubkey, loaded_account, slot);
                }
            },
            config,
        );
    }

    /// Only guaranteed to be safe when called from rent collection
    pub fn range_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        range: R,
        config: &ScanConfig,
        mut scan_func: F,
    ) where
        F: FnMut(Option<(&Pubkey, AccountSharedData, Slot)>),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        self.accounts_index.range_scan_accounts(
            metric_name,
            ancestors,
            range,
            config,
            |pubkey, (account_info, slot)| {
                // unlike other scan fns, this is called from Bank::collect_rent_eagerly(),
                // which is on-consensus processing in the banking/replaying stage.
                // This requires infallible and consistent account loading.
                // So, we unwrap Option<LoadedAccount> from get_loaded_account() here.
                // This is safe because this closure is invoked with the account_info,
                // while we lock the index entry at AccountsIndex::do_scan_accounts() ultimately,
                // meaning no other subsystems can invalidate the account_info before making their
                // changes to the index entry.
                // For details, see the comment in retry_to_get_account_accessor()
                if let Some(account_slot) = self
                    .get_account_accessor(slot, pubkey, &account_info.storage_location())
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot))
                {
                    scan_func(Some(account_slot))
                }
            },
        );
    }

    pub fn index_scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        index_key: IndexKey,
        mut scan_func: F,
        config: &ScanConfig,
    ) -> ScanResult<bool>
    where
        F: FnMut(Option<(&Pubkey, AccountSharedData, Slot)>),
    {
        let key = match &index_key {
            IndexKey::ProgramId(key) => key,
            IndexKey::SplTokenMint(key) => key,
            IndexKey::SplTokenOwner(key) => key,
        };
        if !self.account_indexes.include_key(key) {
            // the requested key was not indexed in the secondary index, so do a normal scan
            let used_index = false;
            self.scan_accounts(ancestors, bank_id, scan_func, config)?;
            return Ok(used_index);
        }

        self.accounts_index.index_scan_accounts(
            ancestors,
            bank_id,
            index_key,
            |pubkey, (account_info, slot)| {
                let account_slot = self
                    .get_account_accessor(slot, pubkey, &account_info.storage_location())
                    .get_loaded_account()
                    .map(|loaded_account| (pubkey, loaded_account.take_account(), slot));
                scan_func(account_slot)
            },
            config,
        )?;
        let used_index = true;
        Ok(used_index)
    }

    /// Scan a specific slot through all the account storage
    pub fn scan_account_storage<R, B>(
        &self,
        slot: Slot,
        cache_map_func: impl Fn(LoadedAccount) -> Option<R> + Sync,
        storage_scan_func: impl Fn(&B, LoadedAccount) + Sync,
    ) -> ScanStorageResult<R, B>
    where
        R: Send,
        B: Send + Default + Sync,
    {
        if let Some(slot_cache) = self.accounts_cache.slot_cache(slot) {
            // If we see the slot in the cache, then all the account information
            // is in this cached slot
            if slot_cache.len() > SCAN_SLOT_PAR_ITER_THRESHOLD {
                ScanStorageResult::Cached(self.thread_pool.install(|| {
                    slot_cache
                        .par_iter()
                        .filter_map(|cached_account| {
                            cache_map_func(LoadedAccount::Cached(Cow::Borrowed(
                                cached_account.value(),
                            )))
                        })
                        .collect()
                }))
            } else {
                ScanStorageResult::Cached(
                    slot_cache
                        .iter()
                        .filter_map(|cached_account| {
                            cache_map_func(LoadedAccount::Cached(Cow::Borrowed(
                                cached_account.value(),
                            )))
                        })
                        .collect(),
                )
            }
        } else {
            let retval = B::default();
            // If the slot is not in the cache, then all the account information must have
            // been flushed. This is guaranteed because we only remove the rooted slot from
            // the cache *after* we've finished flushing in `flush_slot_cache`.
            // Regarding `shrinking_in_progress_ok`:
            // This fn could be running in the foreground, so shrinking could be running in the background, independently.
            // Even if shrinking is running, there will be 0-1 active storages to scan here at any point.
            // When a concurrent shrink completes, the active storage at this slot will
            // be replaced with an equivalent storage with only alive accounts in it.
            // A shrink on this slot could have completed anytime before the call here, a shrink could currently be in progress,
            // or the shrink could complete immediately or anytime after this call. This has always been true.
            // So, whether we get a never-shrunk, an about-to-be shrunk, or a will-be-shrunk-in-future storage here to scan,
            // all are correct and possible in a normally running system.
            if let Some(storage) = self
                .storage
                .get_slot_storage_entry_shrinking_in_progress_ok(slot)
            {
                storage
                    .accounts
                    .account_iter()
                    .for_each(|account| storage_scan_func(&retval, LoadedAccount::Stored(account)));
            }

            ScanStorageResult::Stored(retval)
        }
    }

    /// Insert a default bank hash stats for `slot`
    ///
    /// This fn is called when creating a new bank from parent.
    pub fn insert_default_bank_hash_stats(&self, slot: Slot, parent_slot: Slot) {
        let mut bank_hash_stats = self.bank_hash_stats.lock().unwrap();
        if bank_hash_stats.get(&slot).is_some() {
            error!("set_hash: already exists; multiple forks with shared slot {slot} as child (parent: {parent_slot})!?");
            return;
        }
        bank_hash_stats.insert(slot, BankHashStats::default());
    }

    pub fn load(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        self.do_load(ancestors, pubkey, None, load_hint, LoadZeroLamports::None)
    }

    /// Return Ok(index_of_matching_owner) if the account owner at `offset` is one of the pubkeys in `owners`.
    /// Return Err(MatchAccountOwnerError::NoMatch) if the account has 0 lamports or the owner is not one of
    /// the pubkeys in `owners`.
    /// Return Err(MatchAccountOwnerError::UnableToLoad) if the account could not be accessed.
    pub fn account_matches_owners(
        &self,
        ancestors: &Ancestors,
        account: &Pubkey,
        owners: &[Pubkey],
    ) -> Result<usize, MatchAccountOwnerError> {
        let (slot, storage_location, _maybe_account_accesor) = self
            .read_index_for_accessor_or_load_slow(ancestors, account, None, false)
            .ok_or(MatchAccountOwnerError::UnableToLoad)?;

        if !storage_location.is_cached() {
            let result = self.read_only_accounts_cache.load(*account, slot);
            if let Some(account) = result {
                return if account.is_zero_lamport() {
                    Err(MatchAccountOwnerError::NoMatch)
                } else {
                    owners
                        .iter()
                        .position(|entry| account.owner() == entry)
                        .ok_or(MatchAccountOwnerError::NoMatch)
                };
            }
        }

        let (account_accessor, _slot) = self
            .retry_to_get_account_accessor(
                slot,
                storage_location,
                ancestors,
                account,
                None,
                LoadHint::Unspecified,
            )
            .ok_or(MatchAccountOwnerError::UnableToLoad)?;
        account_accessor.account_matches_owners(owners)
    }

    /// load the account with `pubkey` into the read only accounts cache.
    /// The goal is to make subsequent loads (which caller expects to occur) to find the account quickly.
    pub fn load_account_into_read_cache(&self, ancestors: &Ancestors, pubkey: &Pubkey) {
        self.do_load_with_populate_read_cache(
            ancestors,
            pubkey,
            None,
            LoadHint::Unspecified,
            true,
            // no return from this function, so irrelevant
            LoadZeroLamports::None,
        );
    }

    /// note this returns None for accounts with zero lamports
    pub fn load_with_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load(ancestors, pubkey, LoadHint::FixedMaxRoot)
    }

    fn read_index_for_accessor_or_load_slow<'a>(
        &'a self,
        ancestors: &Ancestors,
        pubkey: &'a Pubkey,
        max_root: Option<Slot>,
        clone_in_lock: bool,
    ) -> Option<(Slot, StorageLocation, Option<LoadedAccountAccessor<'a>>)> {
        let (lock, index) = match self.accounts_index.get(pubkey, Some(ancestors), max_root) {
            AccountIndexGetResult::Found(lock, index) => (lock, index),
            // we bail out pretty early for missing.
            AccountIndexGetResult::NotFound => {
                return None;
            }
        };

        let slot_list = lock.slot_list();
        let (slot, info) = slot_list[index];
        let storage_location = info.storage_location();
        let some_from_slow_path = if clone_in_lock {
            // the fast path must have failed.... so take the slower approach
            // of copying potentially large Account::data inside the lock.

            // calling check_and_get_loaded_account is safe as long as we're guaranteed to hold
            // the lock during the time and there should be no purge thanks to alive ancestors
            // held by our caller.
            Some(self.get_account_accessor(slot, pubkey, &storage_location))
        } else {
            None
        };

        Some((slot, storage_location, some_from_slow_path))
        // `lock` is dropped here rather pretty quickly with clone_in_lock = false,
        // so the entry could be raced for mutation by other subsystems,
        // before we actually provision an account data for caller's use from now on.
        // This is traded for less contention and resultant performance, introducing fair amount of
        // delicate handling in retry_to_get_account_accessor() below ;)
        // you're warned!
    }

    fn retry_to_get_account_accessor<'a>(
        &'a self,
        mut slot: Slot,
        mut storage_location: StorageLocation,
        ancestors: &'a Ancestors,
        pubkey: &'a Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
    ) -> Option<(LoadedAccountAccessor<'a>, Slot)> {
        // Happy drawing time! :)
        //
        // Reader                               | Accessed data source for cached/stored
        // -------------------------------------+----------------------------------
        // R1 read_index_for_accessor_or_load_slow()| cached/stored: index
        //          |                           |
        //        <(store_id, offset, ..)>      |
        //          V                           |
        // R2 retry_to_get_account_accessor()/  | cached: map of caches & entry for (slot, pubkey)
        //        get_account_accessor()        | stored: map of stores
        //          |                           |
        //        <Accessor>                    |
        //          V                           |
        // R3 check_and_get_loaded_account()/   | cached: N/A (note: basically noop unwrap)
        //        get_loaded_account()          | stored: store's entry for slot
        //          |                           |
        //        <LoadedAccount>               |
        //          V                           |
        // R4 take_account()                    | cached/stored: entry of cache/storage for (slot, pubkey)
        //          |                           |
        //        <AccountSharedData>           |
        //          V                           |
        //    Account!!                         V
        //
        // Flusher                              | Accessed data source for cached/stored
        // -------------------------------------+----------------------------------
        // F1 flush_slot_cache()                | N/A
        //          |                           |
        //          V                           |
        // F2 store_accounts_frozen()/          | map of stores (creates new entry)
        //        write_accounts_to_storage()   |
        //          |                           |
        //          V                           |
        // F3 store_accounts_frozen()/          | index
        //        update_index()                | (replaces existing store_id, offset in caches)
        //          |                           |
        //          V                           |
        // F4 accounts_cache.remove_slot()      | map of caches (removes old entry)
        //                                      V
        //
        // Remarks for flusher: So, for any reading operations, it's a race condition where F4 happens
        // between R1 and R2. In that case, retrying from R1 is safu because F3 should have
        // been occurred.
        //
        // Shrinker                             | Accessed data source for stored
        // -------------------------------------+----------------------------------
        // S1 do_shrink_slot_store()            | N/A
        //          |                           |
        //          V                           |
        // S2 store_accounts_frozen()/          | map of stores (creates new entry)
        //        write_accounts_to_storage()   |
        //          |                           |
        //          V                           |
        // S3 store_accounts_frozen()/          | index
        //        update_index()                | (replaces existing store_id, offset in stores)
        //          |                           |
        //          V                           |
        // S4 do_shrink_slot_store()/           | map of stores (removes old entry)
        //        dead_storages
        //
        // Remarks for shrinker: So, for any reading operations, it's a race condition
        // where S4 happens between R1 and R2. In that case, retrying from R1 is safu because S3 should have
        // been occurred, and S3 atomically replaced the index accordingly.
        //
        // Cleaner                              | Accessed data source for stored
        // -------------------------------------+----------------------------------
        // C1 clean_accounts()                  | N/A
        //          |                           |
        //          V                           |
        // C2 clean_accounts()/                 | index
        //        purge_keys_exact()            | (removes existing store_id, offset for stores)
        //          |                           |
        //          V                           |
        // C3 clean_accounts()/                 | map of stores (removes old entry)
        //        handle_reclaims()             |
        //
        // Remarks for cleaner: So, for any reading operations, it's a race condition
        // where C3 happens between R1 and R2. In that case, retrying from R1 is safu.
        // In that case, None would be returned while bailing out at R1.
        //
        // Purger                                 | Accessed data source for cached/stored
        // ---------------------------------------+----------------------------------
        // P1 purge_slot()                        | N/A
        //          |                             |
        //          V                             |
        // P2 purge_slots_from_cache_and_store()  | map of caches/stores (removes old entry)
        //          |                             |
        //          V                             |
        // P3 purge_slots_from_cache_and_store()/ | index
        //       purge_slot_cache()/              |
        //          purge_slot_cache_pubkeys()    | (removes existing store_id, offset for cache)
        //       purge_slot_storage()/            |
        //          purge_keys_exact()            | (removes accounts index entries)
        //          handle_reclaims()             | (removes storage entries)
        //      OR                                |
        //    clean_accounts()/                   |
        //        clean_accounts_older_than_root()| (removes existing store_id, offset for stores)
        //                                        V
        //
        // Remarks for purger: So, for any reading operations, it's a race condition
        // where P2 happens between R1 and R2. In that case, retrying from R1 is safu.
        // In that case, we may bail at index read retry when P3 hasn't been run

        #[cfg(test)]
        {
            // Give some time for cache flushing to occur here for unit tests
            sleep(Duration::from_millis(self.load_delay));
        }

        // Failsafe for potential race conditions with other subsystems
        let mut num_acceptable_failed_iterations = 0;
        loop {
            let account_accessor = self.get_account_accessor(slot, pubkey, &storage_location);
            match account_accessor {
                LoadedAccountAccessor::Cached(Some(_)) | LoadedAccountAccessor::Stored(Some(_)) => {
                    // Great! There was no race, just return :) This is the most usual situation
                    return Some((account_accessor, slot));
                }
                LoadedAccountAccessor::Cached(None) => {
                    num_acceptable_failed_iterations += 1;
                    // Cache was flushed in between checking the index and retrieving from the cache,
                    // so retry. This works because in accounts cache flush, an account is written to
                    // storage *before* it is removed from the cache
                    match load_hint {
                        LoadHint::FixedMaxRoot => {
                            // it's impossible for this to fail for transaction loads from
                            // replaying/banking more than once.
                            // This is because:
                            // 1) For a slot `X` that's being replayed, there is only one
                            // latest ancestor containing the latest update for the account, and this
                            // ancestor can only be flushed once.
                            // 2) The root cannot move while replaying, so the index cannot continually
                            // find more up to date entries than the current `slot`
                            assert!(num_acceptable_failed_iterations <= 1);
                        }
                        LoadHint::Unspecified => {
                            // Because newer root can be added to the index (= not fixed),
                            // multiple flush race conditions can be observed under very rare
                            // condition, at least theoretically
                        }
                    }
                }
                LoadedAccountAccessor::Stored(None) => {
                    match load_hint {
                        LoadHint::FixedMaxRoot => {
                            // When running replay on the validator, or banking stage on the leader,
                            // it should be very rare that the storage entry doesn't exist if the
                            // entry in the accounts index is the latest version of this account.
                            //
                            // There are only a few places where the storage entry may not exist
                            // after reading the index:
                            // 1) Shrink has removed the old storage entry and rewritten to
                            // a newer storage entry
                            // 2) The `pubkey` asked for in this function is a zero-lamport account,
                            // and the storage entry holding this account qualified for zero-lamport clean.
                            //
                            // In both these cases, it should be safe to retry and recheck the accounts
                            // index indefinitely, without incrementing num_acceptable_failed_iterations.
                            // That's because if the root is fixed, there should be a bounded number
                            // of pending cleans/shrinks (depends how far behind the AccountsBackgroundService
                            // is), termination to the desired condition is guaranteed.
                            //
                            // Also note that in both cases, if we do find the storage entry,
                            // we can guarantee that the storage entry is safe to read from because
                            // we grabbed a reference to the storage entry while it was still in the
                            // storage map. This means even if the storage entry is removed from the storage
                            // map after we grabbed the storage entry, the recycler should not reset the
                            // storage entry until we drop the reference to the storage entry.
                            //
                            // eh, no code in this arm? yes!
                        }
                        LoadHint::Unspecified => {
                            // RPC get_account() may have fetched an old root from the index that was
                            // either:
                            // 1) Cleaned up by clean_accounts(), so the accounts index has been updated
                            // and the storage entries have been removed.
                            // 2) Dropped by purge_slots() because the slot was on a minor fork, which
                            // removes the slots' storage entries but doesn't purge from the accounts index
                            // (account index cleanup is left to clean for stored slots). Note that
                            // this generally is impossible to occur in the wild because the RPC
                            // should hold the slot's bank, preventing it from being purged() to
                            // begin with.
                            num_acceptable_failed_iterations += 1;
                        }
                    }
                }
            }
            #[cfg(not(test))]
            let load_limit = ABSURD_CONSECUTIVE_FAILED_ITERATIONS;

            #[cfg(test)]
            let load_limit = self.load_limit.load(Ordering::Relaxed);

            let fallback_to_slow_path = if num_acceptable_failed_iterations >= load_limit {
                // The latest version of the account existed in the index, but could not be
                // fetched from storage. This means a race occurred between this function and clean
                // accounts/purge_slots
                let message = format!(
                    "do_load() failed to get key: {pubkey} from storage, latest attempt was for \
                     slot: {slot}, storage_location: {storage_location:?}, load_hint: {load_hint:?}",
                );
                datapoint_warn!("accounts_db-do_load_warn", ("warn", message, String));
                true
            } else {
                false
            };

            // Because reading from the cache/storage failed, retry from the index read
            let (new_slot, new_storage_location, maybe_account_accessor) = self
                .read_index_for_accessor_or_load_slow(
                    ancestors,
                    pubkey,
                    max_root,
                    fallback_to_slow_path,
                )?;
            // Notice the subtle `?` at previous line, we bail out pretty early if missing.

            if new_slot == slot && new_storage_location.is_store_id_equal(&storage_location) {
                inc_new_counter_info!("retry_to_get_account_accessor-panic", 1);
                let message = format!(
                    "Bad index entry detected ({}, {}, {:?}, {:?}, {:?}, {:?})",
                    pubkey,
                    slot,
                    storage_location,
                    load_hint,
                    new_storage_location,
                    self.accounts_index.get_account_read_entry(pubkey)
                );
                // Considering that we've failed to get accessor above and further that
                // the index still returned the same (slot, store_id) tuple, offset must be same
                // too.
                assert!(
                    new_storage_location.is_offset_equal(&storage_location),
                    "{message}"
                );

                // If the entry was missing from the cache, that means it must have been flushed,
                // and the accounts index is always updated before cache flush, so store_id must
                // not indicate being cached at this point.
                assert!(!new_storage_location.is_cached(), "{message}");

                // If this is not a cache entry, then this was a minor fork slot
                // that had its storage entries cleaned up by purge_slots() but hasn't been
                // cleaned yet. That means this must be rpc access and not replay/banking at the
                // very least. Note that purge shouldn't occur even for RPC as caller must hold all
                // of ancestor slots..
                assert_eq!(load_hint, LoadHint::Unspecified, "{message}");

                // Everything being assert!()-ed, let's panic!() here as it's an error condition
                // after all....
                // That reasoning is based on the fact all of code-path reaching this fn
                // retry_to_get_account_accessor() must outlive the Arc<Bank> (and its all
                // ancestors) over this fn invocation, guaranteeing the prevention of being purged,
                // first of all.
                // For details, see the comment in AccountIndex::do_checked_scan_accounts(),
                // which is referring back here.
                panic!("{message}");
            } else if fallback_to_slow_path {
                // the above bad-index-entry check must had been checked first to retain the same
                // behavior
                return Some((
                    maybe_account_accessor.expect("must be some if clone_in_lock=true"),
                    new_slot,
                ));
            }

            slot = new_slot;
            storage_location = new_storage_location;
        }
    }

    fn do_load(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
        load_zero_lamports: LoadZeroLamports,
    ) -> Option<(AccountSharedData, Slot)> {
        self.do_load_with_populate_read_cache(
            ancestors,
            pubkey,
            max_root,
            load_hint,
            false,
            load_zero_lamports,
        )
    }

    /// remove all entries from the read only accounts cache
    /// useful for benches/tests
    pub fn flush_read_only_cache_for_tests(&self) {
        self.read_only_accounts_cache.reset_for_tests();
    }

    /// if 'load_into_read_cache_only', then return value is meaningless.
    ///   The goal is to get the account into the read-only cache.
    fn do_load_with_populate_read_cache(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
        load_into_read_cache_only: bool,
        load_zero_lamports: LoadZeroLamports,
    ) -> Option<(AccountSharedData, Slot)> {
        #[cfg(not(test))]
        assert!(max_root.is_none());

        let (slot, storage_location, _maybe_account_accesor) =
            self.read_index_for_accessor_or_load_slow(ancestors, pubkey, max_root, false)?;
        // Notice the subtle `?` at previous line, we bail out pretty early if missing.

        let in_write_cache = storage_location.is_cached();
        if !load_into_read_cache_only {
            if !in_write_cache {
                let result = self.read_only_accounts_cache.load(*pubkey, slot);
                if let Some(account) = result {
                    if matches!(load_zero_lamports, LoadZeroLamports::None)
                        && account.is_zero_lamport()
                    {
                        return None;
                    }
                    return Some((account, slot));
                }
            }
        } else {
            // goal is to load into read cache
            if in_write_cache {
                // no reason to load in read cache. already in write cache
                return None;
            }
            if self.read_only_accounts_cache.in_cache(pubkey, slot) {
                // already in read cache
                return None;
            }
        }

        let (mut account_accessor, slot) = self.retry_to_get_account_accessor(
            slot,
            storage_location,
            ancestors,
            pubkey,
            max_root,
            load_hint,
        )?;
        let loaded_account = account_accessor.check_and_get_loaded_account();
        let is_cached = loaded_account.is_cached();
        let account = loaded_account.take_account();
        if matches!(load_zero_lamports, LoadZeroLamports::None) && account.is_zero_lamport() {
            return None;
        }

        if !is_cached {
            /*
            We show this store into the read-only cache for account 'A' and future loads of 'A' from the read-only cache are
            safe/reflect 'A''s latest state on this fork.
            This safety holds if during replay of slot 'S', we show we only read 'A' from the write cache,
            not the read-only cache, after it's been updated in replay of slot 'S'.
            Assume for contradiction this is not true, and we read 'A' from the read-only cache *after* it had been updated in 'S'.
            This means an entry '(S, A)' was added to the read-only cache after 'A' had been updated in 'S'.
            Now when '(S, A)' was being added to the read-only cache, it must have been true that  'is_cache == false',
            which means '(S', A)' does not exist in the write cache yet.
            However, by the assumption for contradiction above ,  'A' has already been updated in 'S' which means '(S, A)'
            must exist in the write cache, which is a contradiction.
            */
            self.read_only_accounts_cache
                .store(*pubkey, slot, account.clone());
        }
        Some((account, slot))
    }

    pub fn load_account_hash(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        max_root: Option<Slot>,
        load_hint: LoadHint,
    ) -> Option<AccountHash> {
        let (slot, storage_location, _maybe_account_accesor) =
            self.read_index_for_accessor_or_load_slow(ancestors, pubkey, max_root, false)?;
        // Notice the subtle `?` at previous line, we bail out pretty early if missing.

        let (mut account_accessor, _) = self.retry_to_get_account_accessor(
            slot,
            storage_location,
            ancestors,
            pubkey,
            max_root,
            load_hint,
        )?;
        let loaded_account = account_accessor.check_and_get_loaded_account();
        Some(loaded_account.loaded_hash())
    }

    fn get_account_accessor<'a>(
        &'a self,
        slot: Slot,
        pubkey: &'a Pubkey,
        storage_location: &StorageLocation,
    ) -> LoadedAccountAccessor<'a> {
        match storage_location {
            StorageLocation::Cached => {
                let maybe_cached_account = self.accounts_cache.load(slot, pubkey).map(Cow::Owned);
                LoadedAccountAccessor::Cached(maybe_cached_account)
            }
            StorageLocation::AppendVec(store_id, offset) => {
                let maybe_storage_entry = self
                    .storage
                    .get_account_storage_entry(slot, *store_id)
                    .map(|account_storage_entry| (account_storage_entry, *offset));
                LoadedAccountAccessor::Stored(maybe_storage_entry)
            }
        }
    }

    fn try_recycle_and_insert_store(
        &self,
        slot: Slot,
        min_size: u64,
        max_size: u64,
    ) -> Option<Arc<AccountStorageEntry>> {
        let store = self.try_recycle_store(slot, min_size, max_size)?;
        self.insert_store(slot, store.clone());
        Some(store)
    }

    fn try_recycle_store(
        &self,
        slot: Slot,
        min_size: u64,
        max_size: u64,
    ) -> Option<Arc<AccountStorageEntry>> {
        let mut max = 0;
        let mut min = std::u64::MAX;
        let mut avail = 0;
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        for (i, (_recycled_time, store)) in recycle_stores.iter().enumerate() {
            if Arc::strong_count(store) == 1 {
                max = std::cmp::max(store.accounts.capacity(), max);
                min = std::cmp::min(store.accounts.capacity(), min);
                avail += 1;

                if store.accounts.is_recyclable()
                    && store.accounts.capacity() >= min_size
                    && store.accounts.capacity() < max_size
                {
                    let ret = recycle_stores.remove_entry(i);
                    drop(recycle_stores);
                    let old_id = ret.append_vec_id();
                    ret.recycle(slot, self.next_id());
                    // This info shows the appendvec change history.  It helps debugging
                    // the appendvec data corrupution issues related to recycling.
                    debug!(
                        "recycling store: old slot {}, old_id: {}, new slot {}, new id{}, path {:?} ",
                        slot,
                        old_id,
                        ret.slot(),
                        ret.append_vec_id(),
                        ret.get_path(),
                    );
                    self.stats
                        .recycle_store_count
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(ret);
                }
            }
        }
        debug!(
            "no recycle stores max: {} min: {} len: {} looking: {}, {} avail: {}",
            max,
            min,
            recycle_stores.entry_count(),
            min_size,
            max_size,
            avail,
        );
        None
    }

    fn find_storage_candidate(&self, slot: Slot, size: usize) -> Arc<AccountStorageEntry> {
        let mut get_slot_stores = Measure::start("get_slot_stores");
        let store = self.storage.get_slot_storage_entry(slot);
        get_slot_stores.stop();
        self.stats
            .store_get_slot_store
            .fetch_add(get_slot_stores.as_us(), Ordering::Relaxed);
        let mut find_existing = Measure::start("find_existing");
        if let Some(store) = store {
            if store.try_available() {
                let ret = store.clone();
                drop(store);
                find_existing.stop();
                self.stats
                    .store_find_existing
                    .fetch_add(find_existing.as_us(), Ordering::Relaxed);
                return ret;
            }
        }
        find_existing.stop();
        self.stats
            .store_find_existing
            .fetch_add(find_existing.as_us(), Ordering::Relaxed);

        let store = if let Some(store) = self.try_recycle_store(slot, size as u64, std::u64::MAX) {
            store
        } else {
            self.create_store(slot, self.file_size, "store", &self.paths)
        };

        // try_available is like taking a lock on the store,
        // preventing other threads from using it.
        // It must succeed here and happen before insert,
        // otherwise another thread could also grab it from the index.
        assert!(store.try_available());
        self.insert_store(slot, store.clone());
        store
    }

    pub fn page_align(size: u64) -> u64 {
        (size + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)
    }

    fn has_space_available(&self, slot: Slot, size: u64) -> bool {
        let store = self.storage.get_slot_storage_entry(slot).unwrap();
        if store.status() == AccountStorageStatus::Available
            && store.accounts.remaining_bytes() >= size
        {
            return true;
        }
        false
    }

    fn create_store(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
        paths: &[PathBuf],
    ) -> Arc<AccountStorageEntry> {
        self.stats
            .create_store_count
            .fetch_add(1, Ordering::Relaxed);
        let path_index = thread_rng().gen_range(0..paths.len());
        let store = Arc::new(self.new_storage_entry(slot, Path::new(&paths[path_index]), size));

        debug!(
            "creating store: {} slot: {} len: {} size: {} from: {} path: {:?}",
            store.append_vec_id(),
            slot,
            store.accounts.len(),
            store.accounts.capacity(),
            from,
            store.accounts.get_path()
        );

        store
    }

    fn create_and_insert_store(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
    ) -> Arc<AccountStorageEntry> {
        self.create_and_insert_store_with_paths(slot, size, from, &self.paths)
    }

    fn create_and_insert_store_with_paths(
        &self,
        slot: Slot,
        size: u64,
        from: &str,
        paths: &[PathBuf],
    ) -> Arc<AccountStorageEntry> {
        let store = self.create_store(slot, size, from, paths);
        let store_for_index = store.clone();

        self.insert_store(slot, store_for_index);
        store
    }

    fn insert_store(&self, slot: Slot, store: Arc<AccountStorageEntry>) {
        self.storage.insert(slot, store)
    }

    pub fn enable_bank_drop_callback(&self) {
        self.is_bank_drop_callback_enabled
            .store(true, Ordering::Release);
    }

    /// This should only be called after the `Bank::drop()` runs in bank.rs, See BANK_DROP_SAFETY
    /// comment below for more explanation.
    ///   * `is_serialized_with_abs` - indicates whehter this call runs sequentially with all other
    ///        accounts_db relevant calls, such as shrinking, purging etc., in account background
    ///        service.
    pub fn purge_slot(&self, slot: Slot, bank_id: BankId, is_serialized_with_abs: bool) {
        if self.is_bank_drop_callback_enabled.load(Ordering::Acquire) && !is_serialized_with_abs {
            panic!(
                "bad drop callpath detected; Bank::drop() must run serially with other logic in
                ABS like clean_accounts()"
            )
        }

        // BANK_DROP_SAFETY: Because this function only runs once the bank is dropped,
        // we know that there are no longer any ongoing scans on this bank, because scans require
        // and hold a reference to the bank at the tip of the fork they're scanning. Hence it's
        // safe to remove this bank_id from the `removed_bank_ids` list at this point.
        if self
            .accounts_index
            .removed_bank_ids
            .lock()
            .unwrap()
            .remove(&bank_id)
        {
            // If this slot was already cleaned up, no need to do any further cleans
            return;
        }

        self.purge_slots(std::iter::once(&slot));
    }

    fn recycle_slot_stores(
        &self,
        total_removed_storage_entries: usize,
        slot_stores: &[Arc<AccountStorageEntry>],
    ) -> u64 {
        let mut recycle_stores_write_elapsed = Measure::start("recycle_stores_write_elapsed");
        let mut recycle_stores = self.recycle_stores.write().unwrap();
        recycle_stores_write_elapsed.stop();

        for (recycled_count, store) in slot_stores.iter().enumerate() {
            if recycle_stores.entry_count() > MAX_RECYCLE_STORES {
                let dropped_count = total_removed_storage_entries - recycled_count;
                self.stats
                    .dropped_stores
                    .fetch_add(dropped_count as u64, Ordering::Relaxed);
                return recycle_stores_write_elapsed.as_us();
            }
            recycle_stores.add_entry(Arc::clone(store));
        }
        recycle_stores_write_elapsed.as_us()
    }

    /// Purges every slot in `removed_slots` from both the cache and storage. This includes
    /// entries in the accounts index, cache entries, and any backing storage entries.
    pub fn purge_slots_from_cache_and_store<'a>(
        &self,
        removed_slots: impl Iterator<Item = &'a Slot> + Clone,
        purge_stats: &PurgeStats,
        log_accounts: bool,
    ) {
        let mut remove_cache_elapsed_across_slots = 0;
        let mut num_cached_slots_removed = 0;
        let mut total_removed_cached_bytes = 0;
        if log_accounts {
            if let Some(min) = removed_slots.clone().min() {
                info!(
                    "purge_slots_from_cache_and_store: {:?}",
                    self.get_pubkey_hash_for_slot(*min).0
                );
            }
        }
        for remove_slot in removed_slots {
            // This function is only currently safe with respect to `flush_slot_cache()` because
            // both functions run serially in AccountsBackgroundService.
            let mut remove_cache_elapsed = Measure::start("remove_cache_elapsed");
            // Note: we cannot remove this slot from the slot cache until we've removed its
            // entries from the accounts index first. This is because `scan_accounts()` relies on
            // holding the index lock, finding the index entry, and then looking up the entry
            // in the cache. If it fails to find that entry, it will panic in `get_loaded_account()`
            if let Some(slot_cache) = self.accounts_cache.slot_cache(*remove_slot) {
                // If the slot is still in the cache, remove the backing storages for
                // the slot and from the Accounts Index
                num_cached_slots_removed += 1;
                total_removed_cached_bytes += slot_cache.total_bytes();
                self.purge_slot_cache(*remove_slot, slot_cache);
                remove_cache_elapsed.stop();
                remove_cache_elapsed_across_slots += remove_cache_elapsed.as_us();
                // Nobody else should have removed the slot cache entry yet
                assert!(self.accounts_cache.remove_slot(*remove_slot).is_some());
            } else {
                self.purge_slot_storage(*remove_slot, purge_stats);
            }
            // It should not be possible that a slot is neither in the cache or storage. Even in
            // a slot with all ticks, `Bank::new_from_parent()` immediately stores some sysvars
            // on bank creation.
        }

        purge_stats
            .remove_cache_elapsed
            .fetch_add(remove_cache_elapsed_across_slots, Ordering::Relaxed);
        purge_stats
            .num_cached_slots_removed
            .fetch_add(num_cached_slots_removed, Ordering::Relaxed);
        purge_stats
            .total_removed_cached_bytes
            .fetch_add(total_removed_cached_bytes, Ordering::Relaxed);
    }

    /// Purge the backing storage entries for the given slot, does not purge from
    /// the cache!
    fn purge_dead_slots_from_storage<'a>(
        &'a self,
        removed_slots: impl Iterator<Item = &'a Slot> + Clone,
        purge_stats: &PurgeStats,
    ) {
        // Check all slots `removed_slots` are no longer "relevant" roots.
        // Note that the slots here could have been rooted slots, but if they're passed here
        // for removal it means:
        // 1) All updates in that old root have been outdated by updates in newer roots
        // 2) Those slots/roots should have already been purged from the accounts index root
        // tracking metadata via `accounts_index.clean_dead_slot()`.
        let mut safety_checks_elapsed = Measure::start("safety_checks_elapsed");
        assert!(self
            .accounts_index
            .get_rooted_from_list(removed_slots.clone())
            .is_empty());
        safety_checks_elapsed.stop();
        purge_stats
            .safety_checks_elapsed
            .fetch_add(safety_checks_elapsed.as_us(), Ordering::Relaxed);

        let mut total_removed_storage_entries = 0;
        let mut total_removed_stored_bytes = 0;
        let mut all_removed_slot_storages = vec![];

        let mut remove_storage_entries_elapsed = Measure::start("remove_storage_entries_elapsed");
        for remove_slot in removed_slots {
            // Remove the storage entries and collect some metrics
            if let Some(store) = self.storage.remove(remove_slot, false) {
                {
                    total_removed_storage_entries += 1;
                    total_removed_stored_bytes += store.accounts.capacity();
                }
                all_removed_slot_storages.push(store);
            }
        }
        remove_storage_entries_elapsed.stop();
        let num_stored_slots_removed = all_removed_slot_storages.len();

        let recycle_stores_write_elapsed =
            self.recycle_slot_stores(total_removed_storage_entries, &all_removed_slot_storages);

        let mut drop_storage_entries_elapsed = Measure::start("drop_storage_entries_elapsed");
        // Backing mmaps for removed storages entries explicitly dropped here outside
        // of any locks
        drop(all_removed_slot_storages);
        drop_storage_entries_elapsed.stop();
        purge_stats
            .remove_storage_entries_elapsed
            .fetch_add(remove_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        purge_stats
            .drop_storage_entries_elapsed
            .fetch_add(drop_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        purge_stats
            .num_stored_slots_removed
            .fetch_add(num_stored_slots_removed, Ordering::Relaxed);
        purge_stats
            .total_removed_storage_entries
            .fetch_add(total_removed_storage_entries, Ordering::Relaxed);
        purge_stats
            .total_removed_stored_bytes
            .fetch_add(total_removed_stored_bytes, Ordering::Relaxed);
        purge_stats
            .recycle_stores_write_elapsed
            .fetch_add(recycle_stores_write_elapsed, Ordering::Relaxed);
    }

    fn purge_slot_cache(&self, purged_slot: Slot, slot_cache: SlotCache) {
        let mut purged_slot_pubkeys: HashSet<(Slot, Pubkey)> = HashSet::new();
        let pubkey_to_slot_set: Vec<(Pubkey, Slot)> = slot_cache
            .iter()
            .map(|account| {
                purged_slot_pubkeys.insert((purged_slot, *account.key()));
                (*account.key(), purged_slot)
            })
            .collect();
        self.purge_slot_cache_pubkeys(
            purged_slot,
            purged_slot_pubkeys,
            pubkey_to_slot_set,
            true,
            &HashSet::default(),
        );
    }

    fn purge_slot_cache_pubkeys(
        &self,
        purged_slot: Slot,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        pubkey_to_slot_set: Vec<(Pubkey, Slot)>,
        is_dead: bool,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        // Slot purged from cache should not exist in the backing store
        assert!(self
            .storage
            .get_slot_storage_entry_shrinking_in_progress_ok(purged_slot)
            .is_none());
        let num_purged_keys = pubkey_to_slot_set.len();
        let (reclaims, _) = self.purge_keys_exact(pubkey_to_slot_set.iter());
        assert_eq!(reclaims.len(), num_purged_keys);
        if is_dead {
            self.remove_dead_slots_metadata(
                std::iter::once(&purged_slot),
                purged_slot_pubkeys,
                None,
                pubkeys_removed_from_accounts_index,
            );
        }
    }

    fn purge_slot_storage(&self, remove_slot: Slot, purge_stats: &PurgeStats) {
        // Because AccountsBackgroundService synchronously flushes from the accounts cache
        // and handles all Bank::drop() (the cleanup function that leads to this
        // function call), then we don't need to worry above an overlapping cache flush
        // with this function call. This means, if we get into this case, we can be
        // confident that the entire state for this slot has been flushed to the storage
        // already.
        let mut scan_storages_elasped = Measure::start("scan_storages_elasped");
        type ScanResult = ScanStorageResult<Pubkey, Arc<Mutex<HashSet<(Pubkey, Slot)>>>>;
        let scan_result: ScanResult = self.scan_account_storage(
            remove_slot,
            |loaded_account: LoadedAccount| Some(*loaded_account.pubkey()),
            |accum: &Arc<Mutex<HashSet<(Pubkey, Slot)>>>, loaded_account: LoadedAccount| {
                accum
                    .lock()
                    .unwrap()
                    .insert((*loaded_account.pubkey(), remove_slot));
            },
        );
        scan_storages_elasped.stop();
        purge_stats
            .scan_storages_elapsed
            .fetch_add(scan_storages_elasped.as_us(), Ordering::Relaxed);

        let mut purge_accounts_index_elapsed = Measure::start("purge_accounts_index_elapsed");
        let (reclaims, pubkeys_removed_from_accounts_index) = match scan_result {
            ScanStorageResult::Cached(_) => {
                panic!("Should not see cached keys in this `else` branch, since we checked this slot did not exist in the cache above");
            }
            ScanStorageResult::Stored(stored_keys) => {
                // Purge this slot from the accounts index
                self.purge_keys_exact(stored_keys.lock().unwrap().iter())
            }
        };
        purge_accounts_index_elapsed.stop();
        purge_stats
            .purge_accounts_index_elapsed
            .fetch_add(purge_accounts_index_elapsed.as_us(), Ordering::Relaxed);

        // `handle_reclaims()` should remove all the account index entries and
        // storage entries
        let mut handle_reclaims_elapsed = Measure::start("handle_reclaims_elapsed");
        // Slot should be dead after removing all its account entries
        let expected_dead_slot = Some(remove_slot);
        self.handle_reclaims(
            (!reclaims.is_empty()).then(|| reclaims.iter()),
            expected_dead_slot,
            Some((purge_stats, &mut ReclaimResult::default())),
            false,
            &pubkeys_removed_from_accounts_index,
        );
        handle_reclaims_elapsed.stop();
        purge_stats
            .handle_reclaims_elapsed
            .fetch_add(handle_reclaims_elapsed.as_us(), Ordering::Relaxed);
        // After handling the reclaimed entries, this slot's
        // storage entries should be purged from self.storage
        assert!(
            self.storage.get_slot_storage_entry(remove_slot).is_none(),
            "slot {remove_slot} is not none"
        );
    }

    #[allow(clippy::needless_collect)]
    fn purge_slots<'a>(&self, slots: impl Iterator<Item = &'a Slot> + Clone) {
        // `add_root()` should be called first
        let mut safety_checks_elapsed = Measure::start("safety_checks_elapsed");
        let non_roots = slots
            // Only safe to check when there are duplicate versions of a slot
            // because ReplayStage will not make new roots before dumping the
            // duplicate slots first. Thus we will not be in a case where we
            // root slot `S`, then try to dump some other version of slot `S`, the
            // dumping has to finish first
            //
            // Also note roots are never removed via `remove_unrooted_slot()`, so
            // it's safe to filter them out here as they won't need deletion from
            // self.accounts_index.removed_bank_ids in `purge_slots_from_cache_and_store()`.
            .filter(|slot| !self.accounts_index.is_alive_root(**slot));
        safety_checks_elapsed.stop();
        self.external_purge_slots_stats
            .safety_checks_elapsed
            .fetch_add(safety_checks_elapsed.as_us(), Ordering::Relaxed);
        self.purge_slots_from_cache_and_store(non_roots, &self.external_purge_slots_stats, false);
        self.external_purge_slots_stats
            .report("external_purge_slots_stats", Some(1000));
    }

    pub fn remove_unrooted_slots(&self, remove_slots: &[(Slot, BankId)]) {
        let rooted_slots = self
            .accounts_index
            .get_rooted_from_list(remove_slots.iter().map(|(slot, _)| slot));
        assert!(
            rooted_slots.is_empty(),
            "Trying to remove accounts for rooted slots {rooted_slots:?}"
        );

        let RemoveUnrootedSlotsSynchronization {
            slots_under_contention,
            signal,
        } = &self.remove_unrooted_slots_synchronization;

        {
            // Slots that are currently being flushed by flush_slot_cache()

            let mut currently_contended_slots = slots_under_contention.lock().unwrap();

            // Slots that are currently being flushed by flush_slot_cache() AND
            // we want to remove in this function
            let mut remaining_contended_flush_slots: Vec<Slot> = remove_slots
                .iter()
                .filter_map(|(remove_slot, _)| {
                    // Reserve the slots that we want to purge that aren't currently
                    // being flushed to prevent cache from flushing those slots in
                    // the future.
                    //
                    // Note that the single replay thread has to remove a specific slot `N`
                    // before another version of the same slot can be replayed. This means
                    // multiple threads should not call `remove_unrooted_slots()` simultaneously
                    // with the same slot.
                    let is_being_flushed = !currently_contended_slots.insert(*remove_slot);
                    // If the cache is currently flushing this slot, add it to the list
                    is_being_flushed.then_some(remove_slot)
                })
                .cloned()
                .collect();

            // Wait for cache flushes to finish
            loop {
                if !remaining_contended_flush_slots.is_empty() {
                    // Wait for the signal that the cache has finished flushing a slot
                    //
                    // Don't wait if the remaining_contended_flush_slots is empty, otherwise
                    // we may never get a signal since there's no cache flush thread to
                    // do the signaling
                    currently_contended_slots = signal.wait(currently_contended_slots).unwrap();
                } else {
                    // There are no slots being flushed to wait on, so it's safe to continue
                    // to purging the slots we want to purge!
                    break;
                }

                // For each slot the cache flush has finished, mark that we're about to start
                // purging these slots by reserving it in `currently_contended_slots`.
                remaining_contended_flush_slots.retain(|flush_slot| {
                    // returns true if slot was already in set. This means slot is being flushed
                    !currently_contended_slots.insert(*flush_slot)
                });
            }
        }

        // Mark down these slots are about to be purged so that new attempts to scan these
        // banks fail, and any ongoing scans over these slots will detect that they should abort
        // their results
        {
            let mut locked_removed_bank_ids = self.accounts_index.removed_bank_ids.lock().unwrap();
            for (_slot, remove_bank_id) in remove_slots.iter() {
                locked_removed_bank_ids.insert(*remove_bank_id);
            }
        }

        let remove_unrooted_purge_stats = PurgeStats::default();
        self.purge_slots_from_cache_and_store(
            remove_slots.iter().map(|(slot, _)| slot),
            &remove_unrooted_purge_stats,
            true,
        );
        remove_unrooted_purge_stats.report("remove_unrooted_slots_purge_slots_stats", None);

        let mut currently_contended_slots = slots_under_contention.lock().unwrap();
        for (remove_slot, _) in remove_slots {
            assert!(currently_contended_slots.remove(remove_slot));
        }
    }

    pub fn hash_account<T: ReadableAccount>(account: &T, pubkey: &Pubkey) -> AccountHash {
        Self::hash_account_data(
            account.lamports(),
            account.owner(),
            account.executable(),
            account.rent_epoch(),
            account.data(),
            pubkey,
        )
    }

    fn hash_account_data(
        lamports: u64,
        owner: &Pubkey,
        executable: bool,
        rent_epoch: Epoch,
        data: &[u8],
        pubkey: &Pubkey,
    ) -> AccountHash {
        if lamports == 0 {
            return AccountHash(Hash::default());
        }
        let mut hasher = blake3::Hasher::new();

        // allocate 128 bytes buffer on the stack
        const BUF_SIZE: usize = 128;
        const TOTAL_FIELD_SIZE: usize = 8 /* lamports */ + 8 /* slot */ + 8 /* rent_epoch */ + 1 /* exec_flag */ + 32 /* owner_key */ + 32 /* pubkey */;
        const DATA_SIZE_CAN_FIT: usize = BUF_SIZE - TOTAL_FIELD_SIZE;

        let mut buffer = SmallVec::<[u8; BUF_SIZE]>::new();

        // collect lamports, slot, rent_epoch into buffer to hash
        buffer.extend_from_slice(&lamports.to_le_bytes());

        buffer.extend_from_slice(&rent_epoch.to_le_bytes());

        if data.len() > DATA_SIZE_CAN_FIT {
            // For larger accounts whose data can't fit into the buffer, update the hash now.
            hasher.update(&buffer);
            buffer.clear();

            // hash account's data
            hasher.update(data);
        } else {
            // For small accounts whose data can fit into the buffer, append it to the buffer.
            buffer.extend_from_slice(data);
        }

        // collect exec_flag, owner, pubkey into buffer to hash
        if executable {
            buffer.push(1_u8);
        } else {
            buffer.push(0_u8);
        }
        buffer.extend_from_slice(owner.as_ref());
        buffer.extend_from_slice(pubkey.as_ref());
        hasher.update(&buffer);

        AccountHash(Hash::new_from_array(hasher.finalize().into()))
    }

    fn bulk_assign_write_version(&self, count: usize) -> StoredMetaWriteVersion {
        self.write_version
            .fetch_add(count as StoredMetaWriteVersion, Ordering::AcqRel)
    }

    fn write_accounts_to_storage<
        'a,
        'b,
        T: ReadableAccount + Sync,
        U: StorableAccounts<'a, T>,
        V: Borrow<AccountHash>,
    >(
        &self,
        slot: Slot,
        storage: &AccountStorageEntry,
        accounts_and_meta_to_store: &StorableAccountsWithHashesAndWriteVersions<'a, 'b, T, U, V>,
    ) -> Vec<AccountInfo> {
        let mut infos: Vec<AccountInfo> = Vec::with_capacity(accounts_and_meta_to_store.len());
        let mut total_append_accounts_us = 0;
        while infos.len() < accounts_and_meta_to_store.len() {
            let mut append_accounts = Measure::start("append_accounts");
            let rvs = storage
                .accounts
                .append_accounts(accounts_and_meta_to_store, infos.len());
            append_accounts.stop();
            total_append_accounts_us += append_accounts.as_us();
            if rvs.is_none() {
                storage.set_status(AccountStorageStatus::Full);

                // See if an account overflows the append vecs in the slot.
                let account = accounts_and_meta_to_store.account(infos.len());
                let data_len = account
                    .map(|account| account.data().len())
                    .unwrap_or_default();
                let data_len = (data_len + STORE_META_OVERHEAD) as u64;
                if !self.has_space_available(slot, data_len) {
                    info!(
                        "write_accounts_to_storage, no space: {}, {}, {}, {}, {}",
                        storage.accounts.capacity(),
                        storage.accounts.remaining_bytes(),
                        data_len,
                        infos.len(),
                        accounts_and_meta_to_store.len()
                    );
                    let special_store_size = std::cmp::max(data_len * 2, self.file_size);
                    if self
                        .try_recycle_and_insert_store(slot, special_store_size, std::u64::MAX)
                        .is_none()
                    {
                        self.create_and_insert_store(slot, special_store_size, "large create");
                    }
                }
                continue;
            }

            let store_id = storage.append_vec_id();
            for (i, stored_account_info) in rvs.unwrap().into_iter().enumerate() {
                storage.add_account(stored_account_info.size);

                infos.push(AccountInfo::new(
                    StorageLocation::AppendVec(store_id, stored_account_info.offset),
                    accounts_and_meta_to_store
                        .account(i)
                        .map(|account| account.lamports())
                        .unwrap_or_default(),
                ));
            }
            // restore the state to available
            storage.set_status(AccountStorageStatus::Available);
        }

        self.stats
            .store_append_accounts
            .fetch_add(total_append_accounts_us, Ordering::Relaxed);

        infos
    }

    pub fn mark_slot_frozen(&self, slot: Slot) {
        if let Some(slot_cache) = self.accounts_cache.slot_cache(slot) {
            slot_cache.mark_slot_frozen();
            slot_cache.report_slot_store_metrics();
        }
        self.accounts_cache.report_size();
    }

    pub fn expire_old_recycle_stores(&self) {
        let mut recycle_stores_write_elapsed = Measure::start("recycle_stores_write_time");
        let recycle_stores = self.recycle_stores.write().unwrap().expire_old_entries();
        recycle_stores_write_elapsed.stop();

        let mut drop_storage_entries_elapsed = Measure::start("drop_storage_entries_elapsed");
        drop(recycle_stores);
        drop_storage_entries_elapsed.stop();

        self.clean_accounts_stats
            .purge_stats
            .drop_storage_entries_elapsed
            .fetch_add(drop_storage_entries_elapsed.as_us(), Ordering::Relaxed);
        self.clean_accounts_stats
            .purge_stats
            .recycle_stores_write_elapsed
            .fetch_add(recycle_stores_write_elapsed.as_us(), Ordering::Relaxed);
    }

    // These functions/fields are only usable from a dev context (i.e. tests and benches)
    #[cfg(feature = "dev-context-only-utils")]
    pub fn flush_accounts_cache_slot_for_tests(&self, slot: Slot) {
        self.flush_slot_cache(slot);
    }

    /// true if write cache is too big
    fn should_aggressively_flush_cache(&self) -> bool {
        self.write_cache_limit_bytes
            .unwrap_or(WRITE_CACHE_LIMIT_BYTES_DEFAULT)
            < self.accounts_cache.size()
    }

    // `force_flush` flushes all the cached roots `<= requested_flush_root`. It also then
    // flushes:
    // 1) excess remaining roots or unrooted slots while 'should_aggressively_flush_cache' is true
    pub fn flush_accounts_cache(&self, force_flush: bool, requested_flush_root: Option<Slot>) {
        #[cfg(not(test))]
        assert!(requested_flush_root.is_some());

        if !force_flush && !self.should_aggressively_flush_cache() {
            return;
        }

        // Flush only the roots <= requested_flush_root, so that snapshotting has all
        // the relevant roots in storage.
        let mut flush_roots_elapsed = Measure::start("flush_roots_elapsed");
        let mut account_bytes_saved = 0;
        let mut num_accounts_saved = 0;

        let _guard = self.active_stats.activate(ActiveStatItem::Flush);

        // Note even if force_flush is false, we will still flush all roots <= the
        // given `requested_flush_root`, even if some of the later roots cannot be used for
        // cleaning due to an ongoing scan
        let (total_new_cleaned_roots, num_cleaned_roots_flushed) = self
            .flush_rooted_accounts_cache(
                requested_flush_root,
                Some((&mut account_bytes_saved, &mut num_accounts_saved)),
            );
        flush_roots_elapsed.stop();

        // Note we don't purge unrooted slots here because there may be ongoing scans/references
        // for those slot, let the Bank::drop() implementation do cleanup instead on dead
        // banks

        // If 'should_aggressively_flush_cache', then flush the excess ones to storage
        let (total_new_excess_roots, num_excess_roots_flushed) =
            if self.should_aggressively_flush_cache() {
                // Start by flushing the roots
                //
                // Cannot do any cleaning on roots past `requested_flush_root` because future
                // snapshots may need updates from those later slots, hence we pass `None`
                // for `should_clean`.
                self.flush_rooted_accounts_cache(None, None)
            } else {
                (0, 0)
            };

        let mut excess_slot_count = 0;
        let mut unflushable_unrooted_slot_count = 0;
        let max_flushed_root = self.accounts_cache.fetch_max_flush_root();
        if self.should_aggressively_flush_cache() {
            let old_slots = self.accounts_cache.cached_frozen_slots();
            excess_slot_count = old_slots.len();
            let mut flush_stats = FlushStats::default();
            old_slots.into_iter().for_each(|old_slot| {
                // Don't flush slots that are known to be unrooted
                if old_slot > max_flushed_root {
                    if self.should_aggressively_flush_cache() {
                        if let Some(stats) = self.flush_slot_cache(old_slot) {
                            flush_stats.num_flushed += stats.num_flushed;
                            flush_stats.num_purged += stats.num_purged;
                            flush_stats.total_size += stats.total_size;
                        }
                    }
                } else {
                    unflushable_unrooted_slot_count += 1;
                }
            });
            datapoint_info!(
                "accounts_db-flush_accounts_cache_aggressively",
                ("num_flushed", flush_stats.num_flushed, i64),
                ("num_purged", flush_stats.num_purged, i64),
                ("total_flush_size", flush_stats.total_size, i64),
                ("total_cache_size", self.accounts_cache.size(), i64),
                ("total_frozen_slots", excess_slot_count, i64),
                ("total_slots", self.accounts_cache.num_slots(), i64),
            );
        }

        datapoint_info!(
            "accounts_db-flush_accounts_cache",
            ("total_new_cleaned_roots", total_new_cleaned_roots, i64),
            ("num_cleaned_roots_flushed", num_cleaned_roots_flushed, i64),
            ("total_new_excess_roots", total_new_excess_roots, i64),
            ("num_excess_roots_flushed", num_excess_roots_flushed, i64),
            ("excess_slot_count", excess_slot_count, i64),
            (
                "unflushable_unrooted_slot_count",
                unflushable_unrooted_slot_count,
                i64
            ),
            (
                "flush_roots_elapsed",
                flush_roots_elapsed.as_us() as i64,
                i64
            ),
            ("account_bytes_saved", account_bytes_saved, i64),
            ("num_accounts_saved", num_accounts_saved, i64),
        );
    }

    fn flush_rooted_accounts_cache(
        &self,
        requested_flush_root: Option<Slot>,
        should_clean: Option<(&mut usize, &mut usize)>,
    ) -> (usize, usize) {
        let max_clean_root = should_clean.as_ref().and_then(|_| {
            // If there is a long running scan going on, this could prevent any cleaning
            // based on updates from slots > `max_clean_root`.
            self.max_clean_root(requested_flush_root)
        });

        let mut written_accounts = HashSet::new();

        // If `should_clean` is None, then`should_flush_f` is also None, which will cause
        // `flush_slot_cache` to flush all accounts to storage without cleaning any accounts.
        let mut should_flush_f = should_clean.map(|(account_bytes_saved, num_accounts_saved)| {
            move |&pubkey: &Pubkey, account: &AccountSharedData| {
                // if not in hashset, then not flushed previously, so flush it
                let should_flush = written_accounts.insert(pubkey);
                if !should_flush {
                    *account_bytes_saved += account.data().len();
                    *num_accounts_saved += 1;
                    // If a later root already wrote this account, no point
                    // in flushing it
                }
                should_flush
            }
        });

        // Always flush up to `requested_flush_root`, which is necessary for things like snapshotting.
        let cached_roots: BTreeSet<Slot> = self.accounts_cache.clear_roots(requested_flush_root);

        // Iterate from highest to lowest so that we don't need to flush earlier
        // outdated updates in earlier roots
        let mut num_roots_flushed = 0;
        for &root in cached_roots.iter().rev() {
            if self
                .flush_slot_cache_with_clean(root, should_flush_f.as_mut(), max_clean_root)
                .is_some()
            {
                num_roots_flushed += 1;
            }

            // Regardless of whether this slot was *just* flushed from the cache by the above
            // `flush_slot_cache()`, we should update the `max_flush_root`.
            // This is because some rooted slots may be flushed to storage *before* they are marked as root.
            // This can occur for instance when
            //  the cache is overwhelmed, we flushed some yet to be rooted frozen slots
            // These slots may then *later* be marked as root, so we still need to handle updating the
            // `max_flush_root` in the accounts cache.
            self.accounts_cache.set_max_flush_root(root);
        }

        // Only add to the uncleaned roots set *after* we've flushed the previous roots,
        // so that clean will actually be able to clean the slots.
        let num_new_roots = cached_roots.len();
        self.accounts_index.add_uncleaned_roots(cached_roots);
        (num_new_roots, num_roots_flushed)
    }

    fn do_flush_slot_cache(
        &self,
        slot: Slot,
        slot_cache: &SlotCache,
        mut should_flush_f: Option<&mut impl FnMut(&Pubkey, &AccountSharedData) -> bool>,
        max_clean_root: Option<Slot>,
    ) -> FlushStats {
        let mut num_purged = 0;
        let mut total_size = 0;
        let mut num_flushed = 0;
        let iter_items: Vec<_> = slot_cache.iter().collect();
        let mut purged_slot_pubkeys: HashSet<(Slot, Pubkey)> = HashSet::new();
        let mut pubkey_to_slot_set: Vec<(Pubkey, Slot)> = vec![];
        if should_flush_f.is_some() {
            if let Some(max_clean_root) = max_clean_root {
                if slot > max_clean_root {
                    // Only if the root is greater than the `max_clean_root` do we
                    // have to prevent cleaning, otherwise, just default to `should_flush_f`
                    // for any slots <= `max_clean_root`
                    should_flush_f = None;
                }
            }
        }

        let (accounts, hashes): (Vec<(&Pubkey, &AccountSharedData)>, Vec<AccountHash>) = iter_items
            .iter()
            .filter_map(|iter_item| {
                let key = iter_item.key();
                let account = &iter_item.value().account;
                let should_flush = should_flush_f
                    .as_mut()
                    .map(|should_flush_f| should_flush_f(key, account))
                    .unwrap_or(true);
                if should_flush {
                    let hash = iter_item.value().hash();
                    total_size += aligned_stored_size(account.data().len()) as u64;
                    num_flushed += 1;
                    Some(((key, account), hash))
                } else {
                    // If we don't flush, we have to remove the entry from the
                    // index, since it's equivalent to purging
                    purged_slot_pubkeys.insert((slot, *key));
                    pubkey_to_slot_set.push((*key, slot));
                    num_purged += 1;
                    None
                }
            })
            .unzip();

        let is_dead_slot = accounts.is_empty();
        // Remove the account index entries from earlier roots that are outdated by later roots.
        // Safe because queries to the index will be reading updates from later roots.
        self.purge_slot_cache_pubkeys(
            slot,
            purged_slot_pubkeys,
            pubkey_to_slot_set,
            is_dead_slot,
            &HashSet::default(),
        );

        if !is_dead_slot {
            // This ensures that all updates are written to an AppendVec, before any
            // updates to the index happen, so anybody that sees a real entry in the index,
            // will be able to find the account in storage
            let flushed_store = self.create_and_insert_store(slot, total_size, "flush_slot_cache");
            self.store_accounts_frozen(
                (slot, &accounts[..]),
                Some(hashes),
                &flushed_store,
                None,
                StoreReclaims::Default,
            );

            // If the above sizing function is correct, just one AppendVec is enough to hold
            // all the data for the slot
            assert!(self.storage.get_slot_storage_entry(slot).is_some());
        }

        // Remove this slot from the cache, which will to AccountsDb's new readers should look like an
        // atomic switch from the cache to storage.
        // There is some racy condition for existing readers who just has read exactly while
        // flushing. That case is handled by retry_to_get_account_accessor()
        assert!(self.accounts_cache.remove_slot(slot).is_some());
        FlushStats {
            num_flushed,
            num_purged,
            total_size,
        }
    }

    /// flush all accounts in this slot
    fn flush_slot_cache(&self, slot: Slot) -> Option<FlushStats> {
        self.flush_slot_cache_with_clean(slot, None::<&mut fn(&_, &_) -> bool>, None)
    }

    /// 1.13 and some 1.14 could produce legal snapshots with more than 1 append vec per slot.
    /// This is now illegal at runtime in the validator.
    /// However, there is a clear path to be able to support this.
    /// So, combine all accounts from 'slot_stores' into a new storage and return it.
    /// This runs prior to the storages being put in AccountsDb.storage
    pub fn combine_multiple_slots_into_one_at_startup(
        path: &Path,
        id: AppendVecId,
        slot: Slot,
        slot_stores: &HashMap<AppendVecId, Arc<AccountStorageEntry>>,
    ) -> Arc<AccountStorageEntry> {
        let size = slot_stores.values().map(|storage| storage.capacity()).sum();
        let storage = AccountStorageEntry::new(path, slot, id, size);

        // get unique accounts, most recent version by write_version
        let mut accum = HashMap::<Pubkey, StoredAccountMeta<'_>>::default();
        slot_stores.iter().for_each(|(_id, store)| {
            store.accounts.account_iter().for_each(|loaded_account| {
                match accum.entry(*loaded_account.pubkey()) {
                    hash_map::Entry::Occupied(mut occupied_entry) => {
                        if loaded_account.write_version() > occupied_entry.get().write_version() {
                            occupied_entry.insert(loaded_account);
                        }
                    }
                    hash_map::Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(loaded_account);
                    }
                }
            });
        });

        // store all unique accounts into new storage
        let accounts = accum.values().collect::<Vec<_>>();
        let to_store = (slot, &accounts[..]);
        let storable =
            StorableAccountsWithHashesAndWriteVersions::<'_, '_, _, _, &AccountHash>::new(
                &to_store,
            );
        storage.accounts.append_accounts(&storable, 0);

        Arc::new(storage)
    }

    /// `should_flush_f` is an optional closure that determines whether a given
    /// account should be flushed. Passing `None` will by default flush all
    /// accounts
    fn flush_slot_cache_with_clean(
        &self,
        slot: Slot,
        should_flush_f: Option<&mut impl FnMut(&Pubkey, &AccountSharedData) -> bool>,
        max_clean_root: Option<Slot>,
    ) -> Option<FlushStats> {
        if self
            .remove_unrooted_slots_synchronization
            .slots_under_contention
            .lock()
            .unwrap()
            .insert(slot)
        {
            // We have not seen this slot, flush it.
            let flush_stats = self.accounts_cache.slot_cache(slot).map(|slot_cache| {
                #[cfg(test)]
                {
                    // Give some time for cache flushing to occur here for unit tests
                    sleep(Duration::from_millis(self.load_delay));
                }
                // Since we added the slot to `slots_under_contention` AND this slot
                // still exists in the cache, we know the slot cannot be removed
                // by any other threads past this point. We are now responsible for
                // flushing this slot.
                self.do_flush_slot_cache(slot, &slot_cache, should_flush_f, max_clean_root)
            });

            // Nobody else should have been purging this slot, so should not have been removed
            // from `self.remove_unrooted_slots_synchronization`.
            assert!(self
                .remove_unrooted_slots_synchronization
                .slots_under_contention
                .lock()
                .unwrap()
                .remove(&slot));

            // Signal to any threads blocked on `remove_unrooted_slots(slot)` that we have finished
            // flushing
            self.remove_unrooted_slots_synchronization
                .signal
                .notify_all();
            flush_stats
        } else {
            // We have already seen this slot. It is already under flushing. Skip.
            None
        }
    }

    fn write_accounts_to_cache<'a, 'b, T: ReadableAccount + Sync, P>(
        &self,
        slot: Slot,
        accounts_and_meta_to_store: &impl StorableAccounts<'b, T>,
        txn_iter: Box<dyn std::iter::Iterator<Item = &Option<&SanitizedTransaction>> + 'a>,
        mut write_version_producer: P,
    ) -> Vec<AccountInfo>
    where
        P: Iterator<Item = u64>,
    {
        txn_iter
            .enumerate()
            .map(|(i, txn)| {
                let account = accounts_and_meta_to_store
                    .account_default_if_zero_lamport(i)
                    .map(|account| account.to_account_shared_data())
                    .unwrap_or_default();
                let account_info = AccountInfo::new(StorageLocation::Cached, account.lamports());

                self.notify_account_at_accounts_update(
                    slot,
                    &account,
                    txn,
                    accounts_and_meta_to_store.pubkey(i),
                    &mut write_version_producer,
                );

                let cached_account =
                    self.accounts_cache
                        .store(slot, accounts_and_meta_to_store.pubkey(i), account);
                // hash this account in the bg
                match &self.sender_bg_hasher {
                    Some(ref sender) => {
                        let _ = sender.send(cached_account);
                    }
                    None => (),
                };
                account_info
            })
            .collect()
    }

    fn store_accounts_to<
        'a: 'c,
        'b,
        'c,
        P: Iterator<Item = u64>,
        T: ReadableAccount + Sync + ZeroLamport + 'b,
    >(
        &self,
        accounts: &'c impl StorableAccounts<'b, T>,
        hashes: Option<Vec<impl Borrow<AccountHash>>>,
        mut write_version_producer: P,
        store_to: &StoreTo,
        transactions: Option<&[Option<&'a SanitizedTransaction>]>,
    ) -> Vec<AccountInfo> {
        let mut calc_stored_meta_time = Measure::start("calc_stored_meta");
        let slot = accounts.target_slot();
        (0..accounts.len()).for_each(|index| {
            let pubkey = accounts.pubkey(index);
            self.read_only_accounts_cache.remove(*pubkey, slot);
        });
        calc_stored_meta_time.stop();
        self.stats
            .calc_stored_meta
            .fetch_add(calc_stored_meta_time.as_us(), Ordering::Relaxed);

        match store_to {
            StoreTo::Cache => {
                let txn_iter: Box<dyn std::iter::Iterator<Item = &Option<&SanitizedTransaction>>> =
                    match transactions {
                        Some(transactions) => {
                            assert_eq!(transactions.len(), accounts.len());
                            Box::new(transactions.iter())
                        }
                        None => Box::new(std::iter::repeat(&None).take(accounts.len())),
                    };

                self.write_accounts_to_cache(slot, accounts, txn_iter, write_version_producer)
            }
            StoreTo::Storage(storage) => {
                if accounts.has_hash_and_write_version() {
                    self.write_accounts_to_storage(
                        slot,
                        storage,
                        &StorableAccountsWithHashesAndWriteVersions::<'_, '_, _, _, &AccountHash>::new(
                            accounts,
                        ),
                    )
                } else {
                    let write_versions = (0..accounts.len())
                        .map(|_| write_version_producer.next().unwrap())
                        .collect::<Vec<_>>();
                    match hashes {
                        Some(hashes) => self.write_accounts_to_storage(
                            slot,
                            storage,
                            &StorableAccountsWithHashesAndWriteVersions::new_with_hashes_and_write_versions(
                                accounts,
                                hashes,
                                write_versions,
                            ),
                        ),
                        None => {
                            // hash any accounts where we were lazy in calculating the hash
                            let mut hash_time = Measure::start("hash_accounts");
                            let len = accounts.len();
                            let mut hashes = Vec::with_capacity(len);
                            for index in 0..accounts.len() {
                                let (pubkey, account) = (accounts.pubkey(index), accounts.account(index));
                                let hash = Self::hash_account(
                                    account,
                                    pubkey,
                                );
                                hashes.push(hash);
                            }
                            hash_time.stop();
                            self.stats
                                .store_hash_accounts
                                .fetch_add(hash_time.as_us(), Ordering::Relaxed);

                            self.write_accounts_to_storage(
                                    slot,
                                    storage,
                                    &StorableAccountsWithHashesAndWriteVersions::new_with_hashes_and_write_versions(accounts, hashes, write_versions),
                                )
                        }
                    }
                }
            }
        }
    }

    fn report_store_stats(&self) {
        let mut total_count = 0;
        let mut newest_slot = 0;
        let mut oldest_slot = std::u64::MAX;
        let mut total_bytes = 0;
        let mut total_alive_bytes = 0;
        for (slot, store) in self.storage.iter() {
            total_count += 1;
            newest_slot = std::cmp::max(newest_slot, slot);

            oldest_slot = std::cmp::min(oldest_slot, slot);

            total_alive_bytes += Self::page_align(store.alive_bytes() as u64);
            total_bytes += store.capacity();
        }
        info!(
            "total_stores: {total_count}, newest_slot: {newest_slot}, oldest_slot: {oldest_slot}"
        );

        let total_alive_ratio = if total_bytes > 0 {
            total_alive_bytes as f64 / total_bytes as f64
        } else {
            0.
        };

        datapoint_info!(
            "accounts_db-stores",
            ("total_count", total_count, i64),
            (
                "recycle_count",
                self.recycle_stores.read().unwrap().entry_count() as u64,
                i64
            ),
            ("total_bytes", total_bytes, i64),
            ("total_alive_bytes", total_alive_bytes, i64),
            ("total_alive_ratio", total_alive_ratio, f64),
        );
        datapoint_info!(
            "accounts_db-perf-stats",
            (
                "delta_hash_num",
                self.stats.delta_hash_num.swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "delta_hash_scan_us",
                self.stats
                    .delta_hash_scan_time_total_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "delta_hash_accumulate_us",
                self.stats
                    .delta_hash_accumulate_time_total_us
                    .swap(0, Ordering::Relaxed),
                i64
            ),
            (
                "skipped_rewrites_num",
                self.stats.skipped_rewrites_num.swap(0, Ordering::Relaxed),
                i64
            ),
        );
    }

    pub fn checked_iterative_sum_for_capitalization(total_cap: u64, new_cap: u64) -> u64 {
        let new_total = total_cap as u128 + new_cap as u128;
        AccountsHasher::checked_cast_for_capitalization(new_total)
    }

    pub fn checked_sum_for_capitalization<T: Iterator<Item = u64>>(balances: T) -> u64 {
        AccountsHasher::checked_cast_for_capitalization(balances.map(|b| b as u128).sum::<u128>())
    }

    pub fn calculate_accounts_hash_from_index(
        &self,
        max_slot: Slot,
        config: &CalcAccountsHashConfig<'_>,
    ) -> Result<(AccountsHash, u64), AccountsHashVerificationError> {
        let mut collect = Measure::start("collect");
        let keys: Vec<_> = self
            .accounts_index
            .account_maps
            .iter()
            .flat_map(|map| {
                let mut keys = map.keys();
                keys.sort_unstable(); // hashmap is not ordered, but bins are relative to each other
                keys
            })
            .collect();
        collect.stop();

        let mut scan = Measure::start("scan");
        let mismatch_found = AtomicU64::new(0);
        // Pick a chunk size big enough to allow us to produce output vectors that are smaller than the overall size.
        // We'll also accumulate the lamports within each chunk and fewer chunks results in less contention to accumulate the sum.
        let chunks = crate::accounts_hash::MERKLE_FANOUT.pow(4);
        let total_lamports = Mutex::<u64>::new(0);

        let get_hashes = || {
            keys.par_chunks(chunks)
                .map(|pubkeys| {
                    let mut sum = 0u128;
                    let result: Vec<Hash> = pubkeys
                        .iter()
                        .filter_map(|pubkey| {
                            if let AccountIndexGetResult::Found(lock, index) =
                                self.accounts_index.get(pubkey, config.ancestors, Some(max_slot))
                            {
                                let (slot, account_info) = &lock.slot_list()[index];
                                if !account_info.is_zero_lamport() {
                                    // Because we're keeping the `lock' here, there is no need
                                    // to use retry_to_get_account_accessor()
                                    // In other words, flusher/shrinker/cleaner is blocked to
                                    // cause any Accessor(None) situation.
                                    // Anyway this race condition concern is currently a moot
                                    // point because calculate_accounts_hash() should not
                                    // currently race with clean/shrink because the full hash
                                    // is synchronous with clean/shrink in
                                    // AccountsBackgroundService
                                    self.get_account_accessor(
                                        *slot,
                                        pubkey,
                                        &account_info.storage_location(),
                                    )
                                    .get_loaded_account()
                                    .and_then(
                                        |loaded_account| {
                                            let mut loaded_hash = loaded_account.loaded_hash();
                                            let balance = loaded_account.lamports();
                                            let hash_is_missing = loaded_hash == AccountHash(Hash::default());
                                            if config.check_hash || hash_is_missing {
                                                let computed_hash =
                                                    loaded_account.compute_hash(pubkey);
                                                if hash_is_missing {
                                                    loaded_hash = computed_hash;
                                                }
                                                else if config.check_hash && computed_hash != loaded_hash {
                                                    info!("hash mismatch found: computed: {}, loaded: {}, pubkey: {}", computed_hash.0, loaded_hash.0, pubkey);
                                                    mismatch_found
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    return None;
                                                }
                                            }

                                            sum += balance as u128;
                                            Some(loaded_hash.0)
                                        },
                                    )
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect();
                    let mut total = total_lamports.lock().unwrap();
                    *total =
                        AccountsHasher::checked_cast_for_capitalization(*total as u128 + sum);
                    result
                }).collect()
        };

        let hashes: Vec<Vec<Hash>> = if config.check_hash {
            get_hashes()
        } else {
            self.thread_pool_clean.install(get_hashes)
        };
        if mismatch_found.load(Ordering::Relaxed) > 0 {
            warn!(
                "{} mismatched account hash(es) found",
                mismatch_found.load(Ordering::Relaxed)
            );
            return Err(AccountsHashVerificationError::MismatchedAccountsHash);
        }

        scan.stop();
        let total_lamports = *total_lamports.lock().unwrap();

        let mut hash_time = Measure::start("hash");
        let (accumulated_hash, hash_total) = AccountsHasher::calculate_hash(hashes);
        hash_time.stop();
        datapoint_info!(
            "calculate_accounts_hash_from_index",
            ("accounts_scan", scan.as_us(), i64),
            ("hash", hash_time.as_us(), i64),
            ("hash_total", hash_total, i64),
            ("collect", collect.as_us(), i64),
        );

        let accounts_hash = AccountsHash(accumulated_hash);
        Ok((accounts_hash, total_lamports))
    }

    /// This is only valid to call from tests.
    /// run the accounts hash calculation and store the results
    pub fn update_accounts_hash_for_tests(
        &self,
        slot: Slot,
        ancestors: &Ancestors,
        debug_verify: bool,
        is_startup: bool,
    ) -> (AccountsHash, u64) {
        self.update_accounts_hash_with_verify(
            CalcAccountsHashDataSource::IndexForTests,
            debug_verify,
            slot,
            ancestors,
            None,
            &EpochSchedule::default(),
            &RentCollector::default(),
            is_startup,
        )
    }

    /// iterate over a single storage, calling scanner on each item
    fn scan_single_account_storage<S>(storage: &Arc<AccountStorageEntry>, scanner: &mut S)
    where
        S: AppendVecScan,
    {
        storage.accounts.account_iter().for_each(|account| {
            if scanner.filter(account.pubkey()) {
                scanner.found_account(&LoadedAccount::Stored(account))
            }
        });
    }

    fn update_old_slot_stats(&self, stats: &HashStats, storage: Option<&Arc<AccountStorageEntry>>) {
        if let Some(storage) = storage {
            stats.roots_older_than_epoch.fetch_add(1, Ordering::Relaxed);
            let num_accounts = storage.count();
            let sizes = storage.capacity();
            stats
                .append_vec_sizes_older_than_epoch
                .fetch_add(sizes as usize, Ordering::Relaxed);
            stats
                .accounts_in_roots_older_than_epoch
                .fetch_add(num_accounts, Ordering::Relaxed);
        }
    }

    /// return slot + offset, where offset can be +/-
    fn apply_offset_to_slot(slot: Slot, offset: i64) -> Slot {
        if offset > 0 {
            slot.saturating_add(offset as u64)
        } else {
            slot.saturating_sub(offset.unsigned_abs())
        }
    }

    /// `oldest_non_ancient_slot` is only applicable when `Append` is used for ancient append vec packing.
    /// If `Pack` is used for ancient append vec packing, return None.
    /// Otherwise, return a slot 'max_slot_inclusive' - (slots_per_epoch - `self.ancient_append_vec_offset`)
    /// If ancient append vecs are not enabled, return 0.
    fn get_oldest_non_ancient_slot_for_hash_calc_scan(
        &self,
        max_slot_inclusive: Slot,
        config: &CalcAccountsHashConfig<'_>,
    ) -> Option<Slot> {
        if self.create_ancient_storage == CreateAncientStorage::Pack {
            // oldest_non_ancient_slot is only applicable when ancient storages are created with `Append`. When ancient storages are created with `Pack`, ancient storages
            // can be created in between non-ancient storages. Return None, because oldest_non_ancient_slot is not applicable here.
            None
        } else if self.ancient_append_vec_offset.is_some() {
            // For performance, this is required when ancient appendvecs are enabled
            Some(
                self.get_oldest_non_ancient_slot_from_slot(
                    config.epoch_schedule,
                    max_slot_inclusive,
                ),
            )
        } else {
            // This causes the entire range to be chunked together, treating older append vecs just like new ones.
            // This performs well if there are many old append vecs that haven't been cleaned yet.
            // 0 will have the effect of causing ALL older append vecs to be chunked together, just like every other append vec.
            Some(0)
        }
    }

    /// hash info about 'storage' into 'hasher'
    /// return true iff storage is valid for loading from cache
    fn hash_storage_info(
        hasher: &mut impl StdHasher,
        storage: Option<&Arc<AccountStorageEntry>>,
        slot: Slot,
    ) -> bool {
        if let Some(append_vec) = storage {
            // hash info about this storage
            append_vec.written_bytes().hash(hasher);
            let storage_file = append_vec.accounts.get_path();
            slot.hash(hasher);
            storage_file.hash(hasher);
            let amod = std::fs::metadata(storage_file);
            if amod.is_err() {
                return false;
            }
            let amod = amod.unwrap().modified();
            if amod.is_err() {
                return false;
            }
            let amod = amod
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            amod.hash(hasher);
        }
        // if we made it here, we have hashed info and we should try to load from the cache
        true
    }

    /// Scan through all the account storage in parallel.
    /// Returns a Vec of opened files.
    /// Each file has serialized hash info, sorted by pubkey and then slot, from scanning the append vecs.
    ///   A single pubkey could be in multiple entries. The pubkey found in the latest entry is the one to use.
    fn scan_account_storage_no_bank<S>(
        &self,
        cache_hash_data: &CacheHashData,
        config: &CalcAccountsHashConfig<'_>,
        snapshot_storages: &SortedStorages,
        scanner: S,
        bin_range: &Range<usize>,
        stats: &mut HashStats,
    ) -> Vec<CacheHashDataFileReference>
    where
        S: AppendVecScan,
    {
        let oldest_non_ancient_slot = self.get_oldest_non_ancient_slot_for_hash_calc_scan(
            snapshot_storages.max_slot_inclusive(),
            config,
        );
        let splitter = SplitAncientStorages::new(oldest_non_ancient_slot, snapshot_storages);

        let slots_per_epoch = config
            .rent_collector
            .epoch_schedule
            .get_slots_in_epoch(config.rent_collector.epoch);
        let one_epoch_old = snapshot_storages
            .range()
            .end
            .saturating_sub(slots_per_epoch);

        stats.scan_chunks = splitter.chunk_count;

        let cache_files = (0..splitter.chunk_count)
            .into_par_iter()
            .filter_map(|chunk| {
                let range_this_chunk = splitter.get_slot_range(chunk)?;

                let mut load_from_cache = true;
                let mut hasher = hash_map::DefaultHasher::new();
                bin_range.start.hash(&mut hasher);
                bin_range.end.hash(&mut hasher);
                let is_first_scan_pass = bin_range.start == 0;

                // calculate hash representing all storages in this chunk
                let mut empty = true;
                for (slot, storage) in snapshot_storages.iter_range(&range_this_chunk) {
                    empty = false;
                    if is_first_scan_pass && slot < one_epoch_old {
                        self.update_old_slot_stats(stats, storage);
                    }
                    if !Self::hash_storage_info(&mut hasher, storage, slot) {
                        load_from_cache = false;
                        break;
                    }
                }
                if empty {
                    return None;
                }
                // we have a hash value for the storages in this chunk
                // so, build a file name:
                let hash = hasher.finish();
                let file_name = format!(
                    "{}.{}.{}.{}.{:016x}",
                    range_this_chunk.start,
                    range_this_chunk.end,
                    bin_range.start,
                    bin_range.end,
                    hash
                );
                if load_from_cache {
                    if let Ok(mapped_file) =
                        cache_hash_data.get_file_reference_to_map_later(&file_name)
                    {
                        return Some(ScanAccountStorageResult::CacheFileAlreadyExists(
                            mapped_file,
                        ));
                    }
                }

                // fall through and load normally - we failed to load from a cache file but there are storages present
                Some(ScanAccountStorageResult::CacheFileNeedsToBeCreated((
                    file_name,
                    range_this_chunk,
                )))
            })
            .collect::<Vec<_>>();

        // deletes the old files that will not be used before creating new ones
        cache_hash_data.delete_old_cache_files();

        cache_files
            .into_par_iter()
            .map(|chunk| {
                match chunk {
                    ScanAccountStorageResult::CacheFileAlreadyExists(file) => Some(file),
                    ScanAccountStorageResult::CacheFileNeedsToBeCreated((
                        file_name,
                        range_this_chunk,
                    )) => {
                        let mut scanner = scanner.clone();
                        let mut init_accum = true;
                        // load from cache failed, so create the cache file for this chunk
                        for (slot, storage) in snapshot_storages.iter_range(&range_this_chunk) {
                            let ancient =
                                oldest_non_ancient_slot.is_some_and(|oldest_non_ancient_slot| {
                                    slot < oldest_non_ancient_slot
                                });

                            let (_, scan_us) = measure_us!(if let Some(storage) = storage {
                                if init_accum {
                                    let range = bin_range.end - bin_range.start;
                                    scanner.init_accum(range);
                                    init_accum = false;
                                }
                                scanner.set_slot(slot);

                                Self::scan_single_account_storage(storage, &mut scanner);
                            });
                            if ancient {
                                stats
                                    .sum_ancient_scans_us
                                    .fetch_add(scan_us, Ordering::Relaxed);
                                stats.count_ancient_scans.fetch_add(1, Ordering::Relaxed);
                                stats
                                    .longest_ancient_scan_us
                                    .fetch_max(scan_us, Ordering::Relaxed);
                            }
                        }
                        (!init_accum)
                            .then(|| {
                                let r = scanner.scanning_complete();
                                assert!(!file_name.is_empty());
                                (!r.is_empty() && r.iter().any(|b| !b.is_empty())).then(|| {
                                    // error if we can't write this
                                    cache_hash_data.save(&file_name, &r).unwrap();
                                    cache_hash_data
                                        .get_file_reference_to_map_later(&file_name)
                                        .unwrap()
                                })
                            })
                            .flatten()
                    }
                }
            })
            .filter_map(|x| x)
            .collect()
    }

    /// storages are sorted by slot and have range info.
    /// add all stores older than slots_per_epoch to dirty_stores so clean visits these slots
    fn mark_old_slots_as_dirty(
        &self,
        storages: &SortedStorages,
        slots_per_epoch: Slot,
        stats: &mut crate::accounts_hash::HashStats,
    ) {
        // Nothing to do if ancient append vecs are enabled.
        // Ancient slots will be visited by the ancient append vec code and dealt with correctly.
        // we expect these ancient append vecs to be old and keeping accounts
        // We can expect the normal processes will keep them cleaned.
        // If we included them here then ALL accounts in ALL ancient append vecs will be visited by clean each time.
        if self.ancient_append_vec_offset.is_some() {
            return;
        }

        let mut mark_time = Measure::start("mark_time");
        let mut num_dirty_slots: usize = 0;
        let max = storages.max_slot_inclusive();
        let acceptable_straggler_slot_count = 100; // do nothing special for these old stores which will likely get cleaned up shortly
        let sub = slots_per_epoch + acceptable_straggler_slot_count;
        let in_epoch_range_start = max.saturating_sub(sub);
        for (slot, storage) in storages.iter_range(&(..in_epoch_range_start)) {
            if let Some(storage) = storage {
                self.dirty_stores.insert(slot, storage.clone());
                num_dirty_slots += 1;
            }
        }
        mark_time.stop();
        stats.mark_time_us = mark_time.as_us();
        stats.num_dirty_slots = num_dirty_slots;
    }

    pub fn calculate_accounts_hash(
        &self,
        data_source: CalcAccountsHashDataSource,
        slot: Slot,
        config: &CalcAccountsHashConfig<'_>,
    ) -> Result<(AccountsHash, u64), AccountsHashVerificationError> {
        match data_source {
            CalcAccountsHashDataSource::Storages => {
                if self.accounts_cache.contains_any_slots(slot) {
                    // this indicates a race condition
                    inc_new_counter_info!("accounts_hash_items_in_write_cache", 1);
                }

                let mut collect_time = Measure::start("collect");
                let (combined_maps, slots) = self.get_snapshot_storages(..=slot);
                collect_time.stop();

                let mut sort_time = Measure::start("sort_storages");
                let min_root = self.accounts_index.min_alive_root();
                let storages = SortedStorages::new_with_slots(
                    combined_maps.iter().zip(slots),
                    min_root,
                    Some(slot),
                );
                sort_time.stop();

                let mut timings = HashStats {
                    collect_snapshots_us: collect_time.as_us(),
                    storage_sort_us: sort_time.as_us(),
                    ..HashStats::default()
                };
                timings.calc_storage_size_quartiles(&combined_maps);

                self.calculate_accounts_hash_from_storages(config, &storages, timings)
            }
            CalcAccountsHashDataSource::IndexForTests => {
                self.calculate_accounts_hash_from_index(slot, config)
            }
        }
    }

    fn calculate_accounts_hash_with_verify(
        &self,
        data_source: CalcAccountsHashDataSource,
        debug_verify: bool,
        slot: Slot,
        config: CalcAccountsHashConfig<'_>,
        expected_capitalization: Option<u64>,
    ) -> Result<(AccountsHash, u64), AccountsHashVerificationError> {
        let (accounts_hash, total_lamports) =
            self.calculate_accounts_hash(data_source, slot, &config)?;
        if debug_verify {
            // calculate the other way (store or non-store) and verify results match.
            let data_source_other = match data_source {
                CalcAccountsHashDataSource::IndexForTests => CalcAccountsHashDataSource::Storages,
                CalcAccountsHashDataSource::Storages => CalcAccountsHashDataSource::IndexForTests,
            };
            let (accounts_hash_other, total_lamports_other) =
                self.calculate_accounts_hash(data_source_other, slot, &config)?;

            let success = accounts_hash == accounts_hash_other
                && total_lamports == total_lamports_other
                && total_lamports == expected_capitalization.unwrap_or(total_lamports);
            assert!(success, "calculate_accounts_hash_with_verify mismatch. hashes: {}, {}; lamports: {}, {}; expected lamports: {:?}, data source: {:?}, slot: {}", accounts_hash.0, accounts_hash_other.0, total_lamports, total_lamports_other, expected_capitalization, data_source, slot);
        }
        Ok((accounts_hash, total_lamports))
    }

    /// run the accounts hash calculation and store the results
    #[allow(clippy::too_many_arguments)]
    pub fn update_accounts_hash_with_verify(
        &self,
        data_source: CalcAccountsHashDataSource,
        debug_verify: bool,
        slot: Slot,
        ancestors: &Ancestors,
        expected_capitalization: Option<u64>,
        epoch_schedule: &EpochSchedule,
        rent_collector: &RentCollector,
        is_startup: bool,
    ) -> (AccountsHash, u64) {
        let check_hash = false;
        let (accounts_hash, total_lamports) = self
            .calculate_accounts_hash_with_verify(
                data_source,
                debug_verify,
                slot,
                CalcAccountsHashConfig {
                    use_bg_thread_pool: !is_startup,
                    check_hash,
                    ancestors: Some(ancestors),
                    epoch_schedule,
                    rent_collector,
                    store_detailed_debug_info_on_failure: false,
                },
                expected_capitalization,
            )
            .unwrap(); // unwrap here will never fail since check_hash = false
        self.set_accounts_hash(slot, (accounts_hash, total_lamports));
        (accounts_hash, total_lamports)
    }

    /// Calculate the full accounts hash for `storages` and save the results at `slot`
    pub fn update_accounts_hash(
        &self,
        config: &CalcAccountsHashConfig<'_>,
        storages: &SortedStorages<'_>,
        slot: Slot,
        stats: HashStats,
    ) -> Result<(AccountsHash, /*capitalization*/ u64), AccountsHashVerificationError> {
        let accounts_hash = self.calculate_accounts_hash_from_storages(config, storages, stats)?;
        let old_accounts_hash = self.set_accounts_hash(slot, accounts_hash);
        if let Some(old_accounts_hash) = old_accounts_hash {
            warn!("Accounts hash was already set for slot {slot}! old: {old_accounts_hash:?}, new: {accounts_hash:?}");
        }
        Ok(accounts_hash)
    }

    /// Calculate the incremental accounts hash for `storages` and save the results at `slot`
    pub fn update_incremental_accounts_hash(
        &self,
        config: &CalcAccountsHashConfig<'_>,
        storages: &SortedStorages<'_>,
        slot: Slot,
        stats: HashStats,
    ) -> Result<(IncrementalAccountsHash, /*capitalization*/ u64), AccountsHashVerificationError>
    {
        let incremental_accounts_hash =
            self.calculate_incremental_accounts_hash(config, storages, stats)?;
        let old_incremental_accounts_hash =
            self.set_incremental_accounts_hash(slot, incremental_accounts_hash);
        if let Some(old_incremental_accounts_hash) = old_incremental_accounts_hash {
            warn!("Incremental accounts hash was already set for slot {slot}! old: {old_incremental_accounts_hash:?}, new: {incremental_accounts_hash:?}");
        }
        Ok(incremental_accounts_hash)
    }

    /// Set the accounts hash for `slot`
    ///
    /// returns the previous accounts hash for `slot`
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn set_accounts_hash(
        &self,
        slot: Slot,
        accounts_hash: (AccountsHash, /*capitalization*/ u64),
    ) -> Option<(AccountsHash, /*capitalization*/ u64)> {
        self.accounts_hashes
            .lock()
            .unwrap()
            .insert(slot, accounts_hash)
    }

    /// After deserializing a snapshot, set the accounts hash for the new AccountsDb
    pub fn set_accounts_hash_from_snapshot(
        &mut self,
        slot: Slot,
        accounts_hash: SerdeAccountsHash,
        capitalization: u64,
    ) -> Option<(AccountsHash, /*capitalization*/ u64)> {
        self.set_accounts_hash(slot, (accounts_hash.into(), capitalization))
    }

    /// Get the accounts hash for `slot`
    pub fn get_accounts_hash(&self, slot: Slot) -> Option<(AccountsHash, /*capitalization*/ u64)> {
        self.accounts_hashes.lock().unwrap().get(&slot).cloned()
    }

    /// Set the incremental accounts hash for `slot`
    ///
    /// returns the previous incremental accounts hash for `slot`
    pub fn set_incremental_accounts_hash(
        &self,
        slot: Slot,
        incremental_accounts_hash: (IncrementalAccountsHash, /*capitalization*/ u64),
    ) -> Option<(IncrementalAccountsHash, /*capitalization*/ u64)> {
        self.incremental_accounts_hashes
            .lock()
            .unwrap()
            .insert(slot, incremental_accounts_hash)
    }

    /// After deserializing a snapshot, set the incremental accounts hash for the new AccountsDb
    pub fn set_incremental_accounts_hash_from_snapshot(
        &mut self,
        slot: Slot,
        incremental_accounts_hash: SerdeIncrementalAccountsHash,
        capitalization: u64,
    ) -> Option<(IncrementalAccountsHash, /*capitalization*/ u64)> {
        self.set_incremental_accounts_hash(slot, (incremental_accounts_hash.into(), capitalization))
    }

    /// Get the incremental accounts hash for `slot`
    pub fn get_incremental_accounts_hash(
        &self,
        slot: Slot,
    ) -> Option<(IncrementalAccountsHash, /*capitalization*/ u64)> {
        self.incremental_accounts_hashes
            .lock()
            .unwrap()
            .get(&slot)
            .cloned()
    }

    /// Purge accounts hashes that are older than `last_full_snapshot_slot`
    ///
    /// Should only be called by AccountsHashVerifier, since it consumes the accounts hashes and
    /// knows which ones are still needed.
    pub fn purge_old_accounts_hashes(&self, last_full_snapshot_slot: Slot) {
        self.accounts_hashes
            .lock()
            .unwrap()
            .retain(|&slot, _| slot >= last_full_snapshot_slot);
        self.incremental_accounts_hashes
            .lock()
            .unwrap()
            .retain(|&slot, _| slot >= last_full_snapshot_slot);
    }

    /// scan 'storages', return a vec of 'CacheHashDataFileReference', one per pass
    fn scan_snapshot_stores_with_cache(
        &self,
        cache_hash_data: &CacheHashData,
        storages: &SortedStorages,
        stats: &mut crate::accounts_hash::HashStats,
        bins: usize,
        bin_range: &Range<usize>,
        config: &CalcAccountsHashConfig<'_>,
    ) -> Result<Vec<CacheHashDataFileReference>, AccountsHashVerificationError> {
        assert!(bin_range.start < bins);
        assert!(bin_range.end <= bins);
        assert!(bin_range.start < bin_range.end);
        let _guard = self.active_stats.activate(ActiveStatItem::HashScan);

        let bin_calculator = PubkeyBinCalculator24::new(bins);
        let mut time = Measure::start("scan all accounts");
        stats.num_snapshot_storage = storages.storage_count();
        stats.num_slots = storages.slot_count();
        let mismatch_found = Arc::new(AtomicU64::new(0));
        let range = bin_range.end - bin_range.start;
        let sort_time = Arc::new(AtomicU64::new(0));

        let scanner = ScanState {
            current_slot: Slot::default(),
            accum: BinnedHashData::default(),
            bin_calculator: &bin_calculator,
            config,
            mismatch_found: mismatch_found.clone(),
            range,
            bin_range,
            sort_time: sort_time.clone(),
            pubkey_to_bin_index: 0,
        };

        let result = self.scan_account_storage_no_bank(
            cache_hash_data,
            config,
            storages,
            scanner,
            bin_range,
            stats,
        );

        stats.sort_time_total_us += sort_time.load(Ordering::Relaxed);

        if config.check_hash && mismatch_found.load(Ordering::Relaxed) > 0 {
            warn!(
                "{} mismatched account hash(es) found",
                mismatch_found.load(Ordering::Relaxed)
            );
            return Err(AccountsHashVerificationError::MismatchedAccountsHash);
        }

        time.stop();
        stats.scan_time_total_us += time.as_us();

        Ok(result)
    }

    fn sort_slot_storage_scan(accum: &mut BinnedHashData) -> u64 {
        let (_, sort_time) = measure_us!(accum.iter_mut().for_each(|items| {
            // sort_by vs unstable because slot and write_version are already in order
            items.sort_by(AccountsHasher::compare_two_hash_entries);
        }));
        sort_time
    }

    /// normal code path returns the common cache path
    /// when called after a failure has been detected, redirect the cache storage to a separate folder for debugging later
    fn get_cache_hash_data(
        accounts_hash_cache_path: PathBuf,
        config: &CalcAccountsHashConfig<'_>,
        kind: CalcAccountsHashKind,
        slot: Slot,
    ) -> CacheHashData {
        let accounts_hash_cache_path = if !config.store_detailed_debug_info_on_failure {
            accounts_hash_cache_path
        } else {
            // this path executes when we are failing with a hash mismatch
            let failed_dir = accounts_hash_cache_path
                .join("failed_calculate_accounts_hash_cache")
                .join(slot.to_string());
            _ = std::fs::remove_dir_all(&failed_dir);
            failed_dir
        };
        CacheHashData::new(accounts_hash_cache_path, kind == CalcAccountsHashKind::Full)
    }

    // modeled after calculate_accounts_delta_hash
    // intended to be faster than calculate_accounts_hash
    pub fn calculate_accounts_hash_from_storages(
        &self,
        config: &CalcAccountsHashConfig<'_>,
        storages: &SortedStorages<'_>,
        stats: HashStats,
    ) -> Result<(AccountsHash, u64), AccountsHashVerificationError> {
        let (accounts_hash, capitalization) = self._calculate_accounts_hash_from_storages(
            config,
            storages,
            stats,
            CalcAccountsHashKind::Full,
        )?;
        let AccountsHashKind::Full(accounts_hash) = accounts_hash else {
            panic!("calculate_accounts_hash_from_storages must return a FullAccountsHash");
        };
        Ok((accounts_hash, capitalization))
    }

    /// Calculate the incremental accounts hash
    ///
    /// This calculation is intended to be used by incremental snapshots, and thus differs from a
    /// "full" accounts hash in a few ways:
    /// - Zero-lamport accounts are *included* in the hash because zero-lamport accounts are also
    ///   included in the incremental snapshot.  This ensures reconstructing the AccountsDb is
    ///   still correct when using this incremental accounts hash.
    /// - `storages` must be the same as the ones going into the incremental snapshot.
    pub fn calculate_incremental_accounts_hash(
        &self,
        config: &CalcAccountsHashConfig<'_>,
        storages: &SortedStorages<'_>,
        stats: HashStats,
    ) -> Result<(IncrementalAccountsHash, /* capitalization */ u64), AccountsHashVerificationError>
    {
        let (accounts_hash, capitalization) = self._calculate_accounts_hash_from_storages(
            config,
            storages,
            stats,
            CalcAccountsHashKind::Incremental,
        )?;
        let AccountsHashKind::Incremental(incremental_accounts_hash) = accounts_hash else {
            panic!("calculate_incremental_accounts_hash must return an IncrementalAccountsHash");
        };
        Ok((incremental_accounts_hash, capitalization))
    }

    fn _calculate_accounts_hash_from_storages(
        &self,
        config: &CalcAccountsHashConfig<'_>,
        storages: &SortedStorages<'_>,
        mut stats: HashStats,
        kind: CalcAccountsHashKind,
    ) -> Result<(AccountsHashKind, u64), AccountsHashVerificationError> {
        let total_time = Measure::start("");
        let _guard = self.active_stats.activate(ActiveStatItem::Hash);
        stats.oldest_root = storages.range().start;

        self.mark_old_slots_as_dirty(storages, config.epoch_schedule.slots_per_epoch, &mut stats);

        let slot = storages.max_slot_inclusive();
        let use_bg_thread_pool = config.use_bg_thread_pool;
        let accounts_hash_cache_path = self.accounts_hash_cache_path.clone();
        let transient_accounts_hash_cache_dir = TempDir::new_in(&accounts_hash_cache_path)
            .expect("create transient accounts hash cache dir");
        let transient_accounts_hash_cache_path =
            transient_accounts_hash_cache_dir.path().to_path_buf();
        let scan_and_hash = || {
            let (cache_hash_data, cache_hash_data_us) = measure_us!(Self::get_cache_hash_data(
                accounts_hash_cache_path,
                config,
                kind,
                slot
            ));
            stats.cache_hash_data_us += cache_hash_data_us;

            let bounds = Range {
                start: 0,
                end: PUBKEY_BINS_FOR_CALCULATING_HASHES,
            };

            let accounts_hasher = AccountsHasher {
                zero_lamport_accounts: kind.zero_lamport_accounts(),
                dir_for_temp_cache_files: transient_accounts_hash_cache_path,
                active_stats: &self.active_stats,
            };

            // get raw data by scanning
            let cache_hash_data_file_references = self.scan_snapshot_stores_with_cache(
                &cache_hash_data,
                storages,
                &mut stats,
                PUBKEY_BINS_FOR_CALCULATING_HASHES,
                &bounds,
                config,
            )?;

            let cache_hash_data_files = cache_hash_data_file_references
                .iter()
                .map(|d| d.map())
                .collect::<Vec<_>>();

            if let Some(err) = cache_hash_data_files
                .iter()
                .filter_map(|r| r.as_ref().err())
                .next()
            {
                panic!("failed generating accounts hash files: {:?}", err);
            }

            // convert mmapped cache files into slices of data
            let cache_hash_intermediates = cache_hash_data_files
                .iter()
                .map(|d| d.as_ref().unwrap().get_cache_hash_data())
                .collect::<Vec<_>>();

            // turn raw data into merkle tree hashes and sum of lamports
            let (accounts_hash, capitalization) =
                accounts_hasher.rest_of_hash_calculation(&cache_hash_intermediates, &mut stats);
            let accounts_hash = match kind {
                CalcAccountsHashKind::Full => AccountsHashKind::Full(AccountsHash(accounts_hash)),
                CalcAccountsHashKind::Incremental => {
                    AccountsHashKind::Incremental(IncrementalAccountsHash(accounts_hash))
                }
            };
            info!("calculate_accounts_hash_from_storages: slot: {slot}, {accounts_hash:?}, capitalization: {capitalization}");
            Ok((accounts_hash, capitalization))
        };

        let result = if use_bg_thread_pool {
            self.thread_pool_clean.install(scan_and_hash)
        } else {
            scan_and_hash()
        };
        stats.total_us = total_time.end_as_us();
        stats.log();
        result
    }

    /// Verify accounts hash at startup (or tests)
    ///
    /// Calculate accounts hash(es) and compare them to the values set at startup.
    /// If `base` is `None`, only calculates the full accounts hash for `[0, slot]`.
    /// If `base` is `Some`, calculate the full accounts hash for `[0, base slot]`
    /// and then calculate the incremental accounts hash for `(base slot, slot]`.
    pub fn verify_accounts_hash_and_lamports(
        &self,
        slot: Slot,
        total_lamports: u64,
        base: Option<(Slot, /*capitalization*/ u64)>,
        config: VerifyAccountsHashAndLamportsConfig,
    ) -> Result<(), AccountsHashVerificationError> {
        let calc_config = CalcAccountsHashConfig {
            use_bg_thread_pool: config.use_bg_thread_pool,
            check_hash: false,
            ancestors: Some(config.ancestors),
            epoch_schedule: config.epoch_schedule,
            rent_collector: config.rent_collector,
            store_detailed_debug_info_on_failure: config.store_detailed_debug_info,
        };
        let hash_mismatch_is_error = !config.ignore_mismatch;

        if let Some((base_slot, base_capitalization)) = base {
            self.verify_accounts_hash_and_lamports(base_slot, base_capitalization, None, config)?;
            let (storages, slots) =
                self.get_snapshot_storages(base_slot.checked_add(1).unwrap()..=slot);
            let sorted_storages =
                SortedStorages::new_with_slots(storages.iter().zip(slots), None, None);
            let calculated_incremental_accounts_hash = self.calculate_incremental_accounts_hash(
                &calc_config,
                &sorted_storages,
                HashStats::default(),
            )?;
            let found_incremental_accounts_hash = self
                .get_incremental_accounts_hash(slot)
                .ok_or(AccountsHashVerificationError::MissingAccountsHash)?;
            if calculated_incremental_accounts_hash != found_incremental_accounts_hash {
                warn!(
                    "mismatched incremental accounts hash for slot {slot}: \
                    {calculated_incremental_accounts_hash:?} (calculated) != {found_incremental_accounts_hash:?} (expected)"
                );
                if hash_mismatch_is_error {
                    return Err(AccountsHashVerificationError::MismatchedAccountsHash);
                }
            }
        } else {
            let (calculated_accounts_hash, calculated_lamports) = self
                .calculate_accounts_hash_with_verify(
                    CalcAccountsHashDataSource::Storages,
                    config.test_hash_calculation,
                    slot,
                    calc_config,
                    None,
                )?;

            if calculated_lamports != total_lamports {
                warn!(
                    "Mismatched total lamports: {} calculated: {}",
                    total_lamports, calculated_lamports
                );
                return Err(AccountsHashVerificationError::MismatchedTotalLamports(
                    calculated_lamports,
                    total_lamports,
                ));
            }

            let (found_accounts_hash, _) = self
                .get_accounts_hash(slot)
                .ok_or(AccountsHashVerificationError::MissingAccountsHash)?;
            if calculated_accounts_hash != found_accounts_hash {
                warn!(
                    "Mismatched accounts hash for slot {slot}: \
                    {calculated_accounts_hash:?} (calculated) != {found_accounts_hash:?} (expected)"
                );
                if hash_mismatch_is_error {
                    return Err(AccountsHashVerificationError::MismatchedAccountsHash);
                }
            }
        }

        Ok(())
    }

    /// helper to return
    /// 1. pubkey, hash pairs for the slot
    /// 2. us spent scanning
    /// 3. Measure started when we began accumulating
    pub fn get_pubkey_hash_for_slot(
        &self,
        slot: Slot,
    ) -> (Vec<(Pubkey, AccountHash)>, u64, Measure) {
        let mut scan = Measure::start("scan");
        let scan_result: ScanStorageResult<(Pubkey, AccountHash), DashMap<Pubkey, AccountHash>> =
            self.scan_account_storage(
                slot,
                |loaded_account: LoadedAccount| {
                    // Cache only has one version per key, don't need to worry about versioning
                    Some((*loaded_account.pubkey(), loaded_account.loaded_hash()))
                },
                |accum: &DashMap<Pubkey, AccountHash>, loaded_account: LoadedAccount| {
                    let loaded_hash = loaded_account.loaded_hash();
                    accum.insert(*loaded_account.pubkey(), loaded_hash);
                },
            );
        scan.stop();

        let accumulate = Measure::start("accumulate");
        let hashes: Vec<_> = match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result.into_iter().collect(),
        };

        (hashes, scan.as_us(), accumulate)
    }

    /// Return all of the accounts for a given slot
    pub fn get_pubkey_hash_account_for_slot(&self, slot: Slot) -> Vec<PubkeyHashAccount> {
        type ScanResult =
            ScanStorageResult<PubkeyHashAccount, DashMap<Pubkey, (AccountHash, AccountSharedData)>>;
        let scan_result: ScanResult = self.scan_account_storage(
            slot,
            |loaded_account: LoadedAccount| {
                // Cache only has one version per key, don't need to worry about versioning
                Some(PubkeyHashAccount {
                    pubkey: *loaded_account.pubkey(),
                    hash: loaded_account.loaded_hash(),
                    account: loaded_account.take_account(),
                })
            },
            |accum: &DashMap<Pubkey, (AccountHash, AccountSharedData)>,
             loaded_account: LoadedAccount| {
                // Storage may have duplicates so only keep the latest version for each key
                accum.insert(
                    *loaded_account.pubkey(),
                    (loaded_account.loaded_hash(), loaded_account.take_account()),
                );
            },
        );

        match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result
                .into_iter()
                .map(|(pubkey, (hash, account))| PubkeyHashAccount {
                    pubkey,
                    hash,
                    account,
                })
                .collect(),
        }
    }

    /// Wrapper function to calculate accounts delta hash for `slot` (only used for testing and benchmarking.)
    ///
    /// As part of calculating the accounts delta hash, get a list of accounts modified this slot
    /// (aka dirty pubkeys) and add them to `self.uncleaned_pubkeys` for future cleaning.
    pub fn calculate_accounts_delta_hash(&self, slot: Slot) -> AccountsDeltaHash {
        self.calculate_accounts_delta_hash_internal(slot, None, HashMap::default())
    }

    /// Calculate accounts delta hash for `slot`
    ///
    /// As part of calculating the accounts delta hash, get a list of accounts modified this slot
    /// (aka dirty pubkeys) and add them to `self.uncleaned_pubkeys` for future cleaning.
    pub fn calculate_accounts_delta_hash_internal(
        &self,
        slot: Slot,
        ignore: Option<Pubkey>,
        mut skipped_rewrites: HashMap<Pubkey, AccountHash>,
    ) -> AccountsDeltaHash {
        let (mut hashes, scan_us, mut accumulate) = self.get_pubkey_hash_for_slot(slot);
        let dirty_keys = hashes.iter().map(|(pubkey, _hash)| *pubkey).collect();

        hashes.iter().for_each(|(k, _h)| {
            skipped_rewrites.remove(k);
        });

        let num_skipped_rewrites = skipped_rewrites.len();
        hashes.extend(skipped_rewrites);

        info!("skipped rewrite hashes {} {}", slot, num_skipped_rewrites);

        if let Some(ignore) = ignore {
            hashes.retain(|k| k.0 != ignore);
        }

        let accounts_delta_hash =
            AccountsDeltaHash(AccountsHasher::accumulate_account_hashes(hashes));
        accumulate.stop();
        let mut uncleaned_time = Measure::start("uncleaned_index");
        self.uncleaned_pubkeys.insert(slot, dirty_keys);
        uncleaned_time.stop();

        self.set_accounts_delta_hash(slot, accounts_delta_hash);

        self.stats
            .store_uncleaned_update
            .fetch_add(uncleaned_time.as_us(), Ordering::Relaxed);
        self.stats
            .delta_hash_scan_time_total_us
            .fetch_add(scan_us, Ordering::Relaxed);
        self.stats
            .delta_hash_accumulate_time_total_us
            .fetch_add(accumulate.as_us(), Ordering::Relaxed);
        self.stats.delta_hash_num.fetch_add(1, Ordering::Relaxed);
        self.stats
            .skipped_rewrites_num
            .fetch_add(num_skipped_rewrites, Ordering::Relaxed);

        accounts_delta_hash
    }

    /// Set the accounts delta hash for `slot` in the `accounts_delta_hashes` map
    ///
    /// returns the previous accounts delta hash for `slot`
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn set_accounts_delta_hash(
        &self,
        slot: Slot,
        accounts_delta_hash: AccountsDeltaHash,
    ) -> Option<AccountsDeltaHash> {
        self.accounts_delta_hashes
            .lock()
            .unwrap()
            .insert(slot, accounts_delta_hash)
    }

    /// After deserializing a snapshot, set the accounts delta hash for the new AccountsDb
    pub fn set_accounts_delta_hash_from_snapshot(
        &mut self,
        slot: Slot,
        accounts_delta_hash: SerdeAccountsDeltaHash,
    ) -> Option<AccountsDeltaHash> {
        self.set_accounts_delta_hash(slot, accounts_delta_hash.into())
    }

    /// Get the accounts delta hash for `slot` in the `accounts_delta_hashes` map
    pub fn get_accounts_delta_hash(&self, slot: Slot) -> Option<AccountsDeltaHash> {
        self.accounts_delta_hashes
            .lock()
            .unwrap()
            .get(&slot)
            .cloned()
    }

    /// When reconstructing AccountsDb from a snapshot, insert the `bank_hash_stats` into the
    /// internal bank hash stats map.
    ///
    /// This fn is only called when loading from a snapshot, which means AccountsDb is new and its
    /// bank hash stats map is unpopulated.  Except for slot 0.
    ///
    /// Slot 0 is a special case.  When a new AccountsDb is created--like when loading from a
    /// snapshot--the bank hash stats map is populated with a default entry at slot 0.  Remove the
    /// default entry at slot 0, and then insert the new value at `slot`.
    pub fn update_bank_hash_stats_from_snapshot(
        &mut self,
        slot: Slot,
        stats: BankHashStats,
    ) -> Option<BankHashStats> {
        let mut bank_hash_stats = self.bank_hash_stats.lock().unwrap();
        bank_hash_stats.remove(&0);
        bank_hash_stats.insert(slot, stats)
    }

    /// Get the bank hash stats for `slot` in the `bank_hash_stats` map
    pub fn get_bank_hash_stats(&self, slot: Slot) -> Option<BankHashStats> {
        self.bank_hash_stats.lock().unwrap().get(&slot).cloned()
    }

    fn update_index<'a, T: ReadableAccount + Sync>(
        &self,
        infos: Vec<AccountInfo>,
        accounts: &impl StorableAccounts<'a, T>,
        reclaim: UpsertReclaim,
        update_index_thread_selection: UpdateIndexThreadSelection,
    ) -> SlotList<AccountInfo> {
        let target_slot = accounts.target_slot();
        // using a thread pool here results in deadlock panics from bank_hashes.write()
        // so, instead we limit how many threads will be created to the same size as the bg thread pool
        let len = std::cmp::min(accounts.len(), infos.len());
        let threshold = 1;
        let update = |start, end| {
            let mut reclaims = Vec::with_capacity((end - start) / 2);

            (start..end).for_each(|i| {
                let info = infos[i];
                let pubkey_account = (accounts.pubkey(i), accounts.account(i));
                let pubkey = pubkey_account.0;
                let old_slot = accounts.slot(i);
                self.accounts_index.upsert(
                    target_slot,
                    old_slot,
                    pubkey,
                    pubkey_account.1,
                    &self.account_indexes,
                    info,
                    &mut reclaims,
                    reclaim,
                );
            });
            reclaims
        };
        if matches!(
            update_index_thread_selection,
            UpdateIndexThreadSelection::PoolWithThreshold,
        ) && len > threshold
        {
            let chunk_size = std::cmp::max(1, len / quarter_thread_count()); // # pubkeys/thread
            let batches = 1 + len / chunk_size;
            (0..batches)
                .into_par_iter()
                .map(|batch| {
                    let start = batch * chunk_size;
                    let end = std::cmp::min(start + chunk_size, len);
                    update(start, end)
                })
                .flatten()
                .collect::<Vec<_>>()
        } else {
            update(0, len)
        }
    }

    fn should_not_shrink(alive_bytes: u64, total_bytes: u64) -> bool {
        alive_bytes + PAGE_SIZE > total_bytes
    }

    fn is_shrinking_productive(slot: Slot, store: &Arc<AccountStorageEntry>) -> bool {
        let alive_count = store.count();
        let stored_count = store.approx_stored_count();
        let alive_bytes = store.alive_bytes() as u64;
        let total_bytes = store.capacity();

        if Self::should_not_shrink(alive_bytes, total_bytes) {
            trace!(
                "shrink_slot_forced ({}): not able to shrink at all: alive/stored: {} ({}b / {}b) save: {}",
                slot,
                alive_count,
                stored_count,
                total_bytes,
                total_bytes.saturating_sub(alive_bytes),
            );
            return false;
        }

        true
    }

    fn is_candidate_for_shrink(
        &self,
        store: &Arc<AccountStorageEntry>,
        allow_shrink_ancient: bool,
    ) -> bool {
        // appended ancient append vecs should not be shrunk by the normal shrink codepath.
        // It is not possible to identify ancient append vecs when we pack, so no check for ancient when we are not appending.
        let total_bytes = if self.create_ancient_storage == CreateAncientStorage::Append
            && is_ancient(&store.accounts)
        {
            if !allow_shrink_ancient {
                return false;
            }

            store.written_bytes()
        } else {
            store.capacity()
        };
        match self.shrink_ratio {
            AccountShrinkThreshold::TotalSpace { shrink_ratio: _ } => {
                Self::page_align(store.alive_bytes() as u64) < total_bytes
            }
            AccountShrinkThreshold::IndividualStore { shrink_ratio } => {
                (Self::page_align(store.alive_bytes() as u64) as f64 / total_bytes as f64)
                    < shrink_ratio
            }
        }
    }

    fn remove_dead_accounts<'a, I>(
        &'a self,
        reclaims: I,
        expected_slot: Option<Slot>,
        mut reclaimed_offsets: Option<&mut SlotOffsets>,
        reset_accounts: bool,
    ) -> IntSet<Slot>
    where
        I: Iterator<Item = &'a (Slot, AccountInfo)>,
    {
        assert!(self.storage.no_shrink_in_progress());

        let mut dead_slots = IntSet::default();
        let mut new_shrink_candidates = ShrinkCandidates::default();
        let mut measure = Measure::start("remove");
        for (slot, account_info) in reclaims {
            // No cached accounts should make it here
            assert!(!account_info.is_cached());
            if let Some(ref mut reclaimed_offsets) = reclaimed_offsets {
                reclaimed_offsets
                    .entry(*slot)
                    .or_default()
                    .insert(account_info.offset());
            }
            if let Some(expected_slot) = expected_slot {
                assert_eq!(*slot, expected_slot);
            }
            if let Some(store) = self
                .storage
                .get_account_storage_entry(*slot, account_info.store_id())
            {
                assert_eq!(
                    *slot, store.slot(),
                    "AccountsDB::accounts_index corrupted. Storage pointed to: {}, expected: {}, should only point to one slot",
                    store.slot(), *slot
                );
                let offset = account_info.offset();
                let account = store.accounts.get_account(offset).unwrap();
                let stored_size = account.0.stored_size();
                let count = store.remove_account(stored_size, reset_accounts);
                if count == 0 {
                    self.dirty_stores.insert(*slot, store.clone());
                    dead_slots.insert(*slot);
                } else if Self::is_shrinking_productive(*slot, &store)
                    && self.is_candidate_for_shrink(&store, false)
                {
                    // Checking that this single storage entry is ready for shrinking,
                    // should be a sufficient indication that the slot is ready to be shrunk
                    // because slots should only have one storage entry, namely the one that was
                    // created by `flush_slot_cache()`.
                    {
                        new_shrink_candidates.insert(*slot);
                    }
                }
            }
        }
        measure.stop();
        self.clean_accounts_stats
            .remove_dead_accounts_remove_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);

        let mut measure = Measure::start("shrink");
        let mut shrink_candidate_slots = self.shrink_candidate_slots.lock().unwrap();
        for slot in new_shrink_candidates {
            shrink_candidate_slots.insert(slot);
        }
        drop(shrink_candidate_slots);
        measure.stop();
        self.clean_accounts_stats
            .remove_dead_accounts_shrink_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);

        dead_slots.retain(|slot| {
            if let Some(slot_store) = self.storage.get_slot_storage_entry(*slot) {
                if slot_store.count() != 0 {
                    return false;
                }
            }
            true
        });

        dead_slots
    }

    /// pubkeys_removed_from_accounts_index - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn remove_dead_slots_metadata<'a>(
        &'a self,
        dead_slots_iter: impl Iterator<Item = &'a Slot> + Clone,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        // Should only be `Some` for non-cached slots
        purged_stored_account_slots: Option<&mut AccountSlots>,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        let mut measure = Measure::start("remove_dead_slots_metadata-ms");
        self.clean_dead_slots_from_accounts_index(
            dead_slots_iter.clone(),
            purged_slot_pubkeys,
            purged_stored_account_slots,
            pubkeys_removed_from_accounts_index,
        );

        let mut accounts_delta_hashes = self.accounts_delta_hashes.lock().unwrap();
        let mut bank_hash_stats = self.bank_hash_stats.lock().unwrap();
        for slot in dead_slots_iter {
            accounts_delta_hashes.remove(slot);
            bank_hash_stats.remove(slot);
        }
        drop(accounts_delta_hashes);
        drop(bank_hash_stats);

        measure.stop();
        inc_new_counter_info!("remove_dead_slots_metadata-ms", measure.as_ms() as usize);
    }

    /// lookup each pubkey in 'pubkeys' and unref it in the accounts index
    /// skip pubkeys that are in 'pubkeys_removed_from_accounts_index'
    fn unref_pubkeys<'a>(
        &'a self,
        pubkeys: impl Iterator<Item = &'a Pubkey> + Clone + Send + Sync,
        num_pubkeys: usize,
        pubkeys_removed_from_accounts_index: &'a PubkeysRemovedFromAccountsIndex,
    ) {
        let batches = 1 + (num_pubkeys / UNREF_ACCOUNTS_BATCH_SIZE);
        self.thread_pool_clean.install(|| {
            (0..batches).into_par_iter().for_each(|batch| {
                let skip = batch * UNREF_ACCOUNTS_BATCH_SIZE;
                self.accounts_index.scan(
                    pubkeys
                        .clone()
                        .skip(skip)
                        .take(UNREF_ACCOUNTS_BATCH_SIZE)
                        .filter(|pubkey| {
                            // filter out pubkeys that have already been removed from the accounts index in a previous step
                            let already_removed =
                                pubkeys_removed_from_accounts_index.contains(pubkey);
                            !already_removed
                        }),
                    |_pubkey, _slots_refs, _entry| {
                        /* unused */
                        AccountsIndexScanResult::Unref
                    },
                    Some(AccountsIndexScanResult::Unref),
                    false,
                )
            });
        });
    }

    /// lookup each pubkey in 'purged_slot_pubkeys' and unref it in the accounts index
    /// populate 'purged_stored_account_slots' by grouping 'purged_slot_pubkeys' by pubkey
    /// pubkeys_removed_from_accounts_index - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn unref_accounts(
        &self,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        purged_stored_account_slots: &mut AccountSlots,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        self.unref_pubkeys(
            purged_slot_pubkeys.iter().map(|(_slot, pubkey)| pubkey),
            purged_slot_pubkeys.len(),
            pubkeys_removed_from_accounts_index,
        );
        for (slot, pubkey) in purged_slot_pubkeys {
            purged_stored_account_slots
                .entry(pubkey)
                .or_default()
                .insert(slot);
        }
    }

    /// pubkeys_removed_from_accounts_index - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn clean_dead_slots_from_accounts_index<'a>(
        &'a self,
        dead_slots_iter: impl Iterator<Item = &'a Slot> + Clone,
        purged_slot_pubkeys: HashSet<(Slot, Pubkey)>,
        // Should only be `Some` for non-cached slots
        purged_stored_account_slots: Option<&mut AccountSlots>,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        let mut accounts_index_root_stats = AccountsIndexRootsStats::default();
        let mut measure = Measure::start("unref_from_storage");
        if let Some(purged_stored_account_slots) = purged_stored_account_slots {
            self.unref_accounts(
                purged_slot_pubkeys,
                purged_stored_account_slots,
                pubkeys_removed_from_accounts_index,
            );
        }
        measure.stop();
        accounts_index_root_stats.clean_unref_from_storage_us += measure.as_us();

        let mut measure = Measure::start("clean_dead_slot");
        let mut rooted_cleaned_count = 0;
        let mut unrooted_cleaned_count = 0;
        let dead_slots: Vec<_> = dead_slots_iter
            .map(|slot| {
                if self.accounts_index.clean_dead_slot(*slot) {
                    rooted_cleaned_count += 1;
                } else {
                    unrooted_cleaned_count += 1;
                }
                *slot
            })
            .collect();
        measure.stop();
        accounts_index_root_stats.clean_dead_slot_us += measure.as_us();
        if self.log_dead_slots.load(Ordering::Relaxed) {
            info!(
                "remove_dead_slots_metadata: {} dead slots",
                dead_slots.len()
            );
            trace!("remove_dead_slots_metadata: dead_slots: {:?}", dead_slots);
        }
        self.accounts_index
            .update_roots_stats(&mut accounts_index_root_stats);
        accounts_index_root_stats.rooted_cleaned_count += rooted_cleaned_count;
        accounts_index_root_stats.unrooted_cleaned_count += unrooted_cleaned_count;

        self.clean_accounts_stats
            .latest_accounts_index_roots_stats
            .update(&accounts_index_root_stats);
    }

    /// pubkeys_removed_from_accounts_index - These keys have already been removed from the accounts index
    ///    and should not be unref'd. If they exist in the accounts index, they are NEW.
    fn clean_stored_dead_slots(
        &self,
        dead_slots: &IntSet<Slot>,
        purged_account_slots: Option<&mut AccountSlots>,
        pubkeys_removed_from_accounts_index: &PubkeysRemovedFromAccountsIndex,
    ) {
        let mut measure = Measure::start("clean_stored_dead_slots-ms");
        let mut stores = vec![];
        // get all stores in a vec so we can iterate in parallel
        for slot in dead_slots.iter() {
            if let Some(slot_storage) = self.storage.get_slot_storage_entry(*slot) {
                stores.push(slot_storage);
            }
        }
        // get all pubkeys in all dead slots
        let purged_slot_pubkeys: HashSet<(Slot, Pubkey)> = {
            self.thread_pool_clean.install(|| {
                stores
                    .into_par_iter()
                    .map(|store| {
                        let slot = store.slot();
                        store
                            .accounts
                            .account_iter()
                            .map(|account| (slot, *account.pubkey()))
                            .collect::<Vec<(Slot, Pubkey)>>()
                    })
                    .flatten()
                    .collect::<HashSet<_>>()
            })
        };
        self.remove_dead_slots_metadata(
            dead_slots.iter(),
            purged_slot_pubkeys,
            purged_account_slots,
            pubkeys_removed_from_accounts_index,
        );
        measure.stop();
        inc_new_counter_info!("clean_stored_dead_slots-ms", measure.as_ms() as usize);
        self.clean_accounts_stats
            .clean_stored_dead_slots_us
            .fetch_add(measure.as_us(), Ordering::Relaxed);
    }

    pub fn store_cached<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        transactions: Option<&'a [Option<&'a SanitizedTransaction>]>,
    ) {
        self.store(
            accounts,
            &StoreTo::Cache,
            transactions,
            StoreReclaims::Default,
            UpdateIndexThreadSelection::PoolWithThreshold,
        );
    }

    pub(crate) fn store_cached_inline_update_index<
        'a,
        T: ReadableAccount + Sync + ZeroLamport + 'a,
    >(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        transactions: Option<&'a [Option<&'a SanitizedTransaction>]>,
    ) {
        self.store(
            accounts,
            &StoreTo::Cache,
            transactions,
            StoreReclaims::Default,
            UpdateIndexThreadSelection::Inline,
        );
    }

    /// Store the account update.
    /// only called by tests
    pub fn store_uncached(&self, slot: Slot, accounts: &[(&Pubkey, &AccountSharedData)]) {
        let storage = self.find_storage_candidate(slot, 1);
        self.store(
            (slot, accounts),
            &StoreTo::Storage(&storage),
            None,
            StoreReclaims::Default,
            UpdateIndexThreadSelection::PoolWithThreshold,
        );
    }

    fn store<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        store_to: &StoreTo,
        transactions: Option<&'a [Option<&'a SanitizedTransaction>]>,
        reclaim: StoreReclaims,
        update_index_thread_selection: UpdateIndexThreadSelection,
    ) {
        // If all transactions in a batch are errored,
        // it's possible to get a store with no accounts.
        if accounts.is_empty() {
            return;
        }

        let mut stats = BankHashStats::default();
        let mut total_data = 0;
        (0..accounts.len()).for_each(|index| {
            let account = accounts.account(index);
            total_data += account.data().len();
            stats.update(account);
        });

        self.stats
            .store_total_data
            .fetch_add(total_data as u64, Ordering::Relaxed);

        {
            // we need to drop the bank_hash_stats lock to prevent deadlocks
            self.bank_hash_stats
                .lock()
                .unwrap()
                .entry(accounts.target_slot())
                .or_default()
                .accumulate(&stats);
        }

        // we use default hashes for now since the same account may be stored to the cache multiple times
        self.store_accounts_unfrozen(
            accounts,
            None::<Vec<AccountHash>>,
            store_to,
            transactions,
            reclaim,
            update_index_thread_selection,
        );
        self.report_store_timings();
    }

    fn report_store_timings(&self) {
        if self.stats.last_store_report.should_update(1000) {
            let (
                read_only_cache_hits,
                read_only_cache_misses,
                read_only_cache_evicts,
                read_only_cache_load_us,
            ) = self.read_only_accounts_cache.get_and_reset_stats();
            datapoint_info!(
                "accounts_db_store_timings",
                (
                    "hash_accounts",
                    self.stats.store_hash_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_accounts",
                    self.stats.store_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "update_index",
                    self.stats.store_update_index.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "handle_reclaims",
                    self.stats.store_handle_reclaims.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "append_accounts",
                    self.stats.store_append_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "stakes_cache_check_and_store_us",
                    self.stats
                        .stakes_cache_check_and_store_us
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "num_accounts",
                    self.stats.store_num_accounts.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "total_data",
                    self.stats.store_total_data.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "read_only_accounts_cache_entries",
                    self.read_only_accounts_cache.cache_len(),
                    i64
                ),
                (
                    "read_only_accounts_cache_data_size",
                    self.read_only_accounts_cache.data_size(),
                    i64
                ),
                ("read_only_accounts_cache_hits", read_only_cache_hits, i64),
                (
                    "read_only_accounts_cache_misses",
                    read_only_cache_misses,
                    i64
                ),
                (
                    "read_only_accounts_cache_evicts",
                    read_only_cache_evicts,
                    i64
                ),
                (
                    "read_only_accounts_cache_load_us",
                    read_only_cache_load_us,
                    i64
                ),
                (
                    "calc_stored_meta_us",
                    self.stats.calc_stored_meta.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "handle_dead_keys_us",
                    self.stats.handle_dead_keys_us.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "purge_exact_us",
                    self.stats.purge_exact_us.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "purge_exact_count",
                    self.stats.purge_exact_count.swap(0, Ordering::Relaxed),
                    i64
                ),
            );

            let recycle_stores = self.recycle_stores.read().unwrap();
            datapoint_info!(
                "accounts_db_store_timings2",
                (
                    "recycle_store_count",
                    self.stats.recycle_store_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "current_recycle_store_count",
                    recycle_stores.entry_count(),
                    i64
                ),
                (
                    "current_recycle_store_bytes",
                    recycle_stores.total_bytes(),
                    i64
                ),
                (
                    "create_store_count",
                    self.stats.create_store_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_get_slot_store",
                    self.stats.store_get_slot_store.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "store_find_existing",
                    self.stats.store_find_existing.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "dropped_stores",
                    self.stats.dropped_stores.swap(0, Ordering::Relaxed),
                    i64
                ),
            );
        }
    }

    fn store_accounts_unfrozen<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        hashes: Option<Vec<impl Borrow<AccountHash>>>,
        store_to: &StoreTo,
        transactions: Option<&'a [Option<&'a SanitizedTransaction>]>,
        reclaim: StoreReclaims,
        update_index_thread_selection: UpdateIndexThreadSelection,
    ) {
        // This path comes from a store to a non-frozen slot.
        // If a store is dead here, then a newer update for
        // each pubkey in the store must exist in another
        // store in the slot. Thus it is safe to reset the store and
        // re-use it for a future store op. The pubkey ref counts should still
        // hold just 1 ref from this slot.
        let reset_accounts = true;

        self.store_accounts_custom(
            accounts,
            hashes,
            None::<Box<dyn Iterator<Item = u64>>>,
            store_to,
            reset_accounts,
            transactions,
            reclaim,
            update_index_thread_selection,
        );
    }

    pub fn store_accounts_frozen<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        hashes: Option<Vec<impl Borrow<AccountHash>>>,
        storage: &Arc<AccountStorageEntry>,
        write_version_producer: Option<Box<dyn Iterator<Item = StoredMetaWriteVersion>>>,
        reclaim: StoreReclaims,
    ) -> StoreAccountsTiming {
        // stores on a frozen slot should not reset
        // the append vec so that hashing could happen on the store
        // and accounts in the append_vec can be unrefed correctly
        let reset_accounts = false;
        self.store_accounts_custom(
            accounts,
            hashes,
            write_version_producer,
            &StoreTo::Storage(storage),
            reset_accounts,
            None,
            reclaim,
            UpdateIndexThreadSelection::PoolWithThreshold,
        )
    }

    fn store_accounts_custom<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
        hashes: Option<Vec<impl Borrow<AccountHash>>>,
        write_version_producer: Option<Box<dyn Iterator<Item = u64>>>,
        store_to: &StoreTo,
        reset_accounts: bool,
        transactions: Option<&[Option<&SanitizedTransaction>]>,
        reclaim: StoreReclaims,
        update_index_thread_selection: UpdateIndexThreadSelection,
    ) -> StoreAccountsTiming {
        let write_version_producer: Box<dyn Iterator<Item = u64>> = write_version_producer
            .unwrap_or_else(|| {
                let mut current_version = self.bulk_assign_write_version(accounts.len());
                Box::new(std::iter::from_fn(move || {
                    let ret = current_version;
                    current_version += 1;
                    Some(ret)
                }))
            });

        self.stats
            .store_num_accounts
            .fetch_add(accounts.len() as u64, Ordering::Relaxed);
        let mut store_accounts_time = Measure::start("store_accounts");
        let infos = self.store_accounts_to(
            &accounts,
            hashes,
            write_version_producer,
            store_to,
            transactions,
        );
        store_accounts_time.stop();
        self.stats
            .store_accounts
            .fetch_add(store_accounts_time.as_us(), Ordering::Relaxed);
        let mut update_index_time = Measure::start("update_index");

        let reclaim = if matches!(reclaim, StoreReclaims::Ignore) {
            UpsertReclaim::IgnoreReclaims
        } else if store_to.is_cached() {
            UpsertReclaim::PreviousSlotEntryWasCached
        } else {
            UpsertReclaim::PopulateReclaims
        };

        // if we are squashing a single slot, then we can expect a single dead slot
        let expected_single_dead_slot =
            (!accounts.contains_multiple_slots()).then(|| accounts.target_slot());

        // If the cache was flushed, then because `update_index` occurs
        // after the account are stored by the above `store_accounts_to`
        // call and all the accounts are stored, all reads after this point
        // will know to not check the cache anymore
        let mut reclaims =
            self.update_index(infos, &accounts, reclaim, update_index_thread_selection);

        // For each updated account, `reclaims` should only have at most one
        // item (if the account was previously updated in this slot).
        // filter out the cached reclaims as those don't actually map
        // to anything that needs to be cleaned in the backing storage
        // entries
        reclaims.retain(|(_, r)| !r.is_cached());

        if store_to.is_cached() {
            assert!(reclaims.is_empty());
        }

        update_index_time.stop();
        self.stats
            .store_update_index
            .fetch_add(update_index_time.as_us(), Ordering::Relaxed);

        // A store for a single slot should:
        // 1) Only make "reclaims" for the same slot
        // 2) Should not cause any slots to be removed from the storage
        // database because
        //    a) this slot  has at least one account (the one being stored),
        //    b)From 1) we know no other slots are included in the "reclaims"
        //
        // From 1) and 2) we guarantee passing `no_purge_stats` == None, which is
        // equivalent to asserting there will be no dead slots, is safe.
        let mut handle_reclaims_time = Measure::start("handle_reclaims");
        self.handle_reclaims(
            (!reclaims.is_empty()).then(|| reclaims.iter()),
            expected_single_dead_slot,
            None,
            reset_accounts,
            &HashSet::default(),
        );
        handle_reclaims_time.stop();
        self.stats
            .store_handle_reclaims
            .fetch_add(handle_reclaims_time.as_us(), Ordering::Relaxed);

        StoreAccountsTiming {
            store_accounts_elapsed: store_accounts_time.as_us(),
            update_index_elapsed: update_index_time.as_us(),
            handle_reclaims_elapsed: handle_reclaims_time.as_us(),
        }
    }

    pub fn add_root(&self, slot: Slot) -> AccountsAddRootTiming {
        let mut index_time = Measure::start("index_add_root");
        self.accounts_index.add_root(slot);
        index_time.stop();
        let mut cache_time = Measure::start("cache_add_root");
        self.accounts_cache.add_root(slot);
        cache_time.stop();
        let mut store_time = Measure::start("store_add_root");
        // We would not expect this slot to be shrinking right now, but other slots may be.
        // But, even if it was, we would just mark a store id as dirty unnecessarily and that is ok.
        // So, allow shrinking to be in progress.
        if let Some(store) = self
            .storage
            .get_slot_storage_entry_shrinking_in_progress_ok(slot)
        {
            self.dirty_stores.insert(slot, store);
        }
        store_time.stop();

        AccountsAddRootTiming {
            index_us: index_time.as_us(),
            cache_us: cache_time.as_us(),
            store_us: store_time.as_us(),
        }
    }

    /// Get storages to use for snapshots, for the requested slots
    pub fn get_snapshot_storages(
        &self,
        requested_slots: impl RangeBounds<Slot> + Sync,
    ) -> (Vec<Arc<AccountStorageEntry>>, Vec<Slot>) {
        let mut m = Measure::start("get slots");
        let mut slots_and_storages = self
            .storage
            .iter()
            .filter_map(|(slot, store)| {
                requested_slots
                    .contains(&slot)
                    .then_some((slot, Some(store)))
            })
            .collect::<Vec<_>>();
        m.stop();
        let mut m2 = Measure::start("filter");

        let chunk_size = 5_000;
        let wide = self.thread_pool_clean.install(|| {
            slots_and_storages
                .par_chunks_mut(chunk_size)
                .map(|slots_and_storages| {
                    slots_and_storages
                        .iter_mut()
                        .filter(|(slot, _)| self.accounts_index.is_alive_root(*slot))
                        .filter_map(|(slot, store)| {
                            let store = std::mem::take(store).unwrap();
                            store.has_accounts().then_some((store, *slot))
                        })
                        .collect::<Vec<(Arc<AccountStorageEntry>, Slot)>>()
                })
                .collect::<Vec<_>>()
        });
        m2.stop();
        let mut m3 = Measure::start("flatten");
        // some slots we found above may not have been a root or met the slot # constraint.
        // So the resulting 'slots' vector we return will be a subset of the raw keys we got initially.
        let mut slots = Vec::with_capacity(slots_and_storages.len());
        let result = wide
            .into_iter()
            .flatten()
            .map(|(storage, slot)| {
                slots.push(slot);
                storage
            })
            .collect::<Vec<_>>();
        m3.stop();

        debug!(
            "hash_total: get slots: {}, filter: {}, flatten: {}",
            m.as_us(),
            m2.as_us(),
            m3.as_us()
        );
        (result, slots)
    }

    /// return Some(lamports_to_top_off) if 'account' would collect rent
    fn stats_for_rent_payers<T: ReadableAccount>(
        pubkey: &Pubkey,
        account: &T,
        rent_collector: &RentCollector,
    ) -> Option<u64> {
        if account.lamports() == 0 {
            return None;
        }
        (rent_collector.should_collect_rent(pubkey, account)
            && !rent_collector.get_rent_due(account).is_exempt())
        .then(|| {
            let min_balance = rent_collector.rent.minimum_balance(account.data().len());
            // return lamports required to top off this account to make it rent exempt
            min_balance.saturating_sub(account.lamports())
        })
    }

    fn generate_index_for_slot(
        &self,
        storage: &Arc<AccountStorageEntry>,
        slot: Slot,
        store_id: AppendVecId,
        rent_collector: &RentCollector,
        storage_info: &StorageSizeAndCountMap,
    ) -> SlotIndexGenerationInfo {
        let mut accounts = storage.accounts.account_iter();
        if accounts.next().is_none() {
            return SlotIndexGenerationInfo::default();
        }
        let accounts = storage.accounts.account_iter();

        let secondary = !self.account_indexes.is_empty();

        let mut rent_paying_accounts_by_partition = Vec::default();
        let mut accounts_data_len = 0;
        let mut num_accounts_rent_paying = 0;
        let mut amount_to_top_off_rent = 0;
        let mut stored_size_alive = 0;

        let items = accounts.map(|stored_account| {
            stored_size_alive += stored_account.stored_size();
            let pubkey = stored_account.pubkey();
            if secondary {
                self.accounts_index.update_secondary_indexes(
                    pubkey,
                    &stored_account,
                    &self.account_indexes,
                );
            }
            if !stored_account.is_zero_lamport() {
                accounts_data_len += stored_account.data().len() as u64;
            }

            if let Some(amount_to_top_off_rent_this_account) =
                Self::stats_for_rent_payers(pubkey, &stored_account, rent_collector)
            {
                amount_to_top_off_rent += amount_to_top_off_rent_this_account;
                num_accounts_rent_paying += 1;
                // remember this rent-paying account pubkey
                rent_paying_accounts_by_partition.push(*pubkey);
            }

            (
                *pubkey,
                AccountInfo::new(
                    StorageLocation::AppendVec(store_id, stored_account.offset()), // will never be cached
                    stored_account.lamports(),
                ),
            )
        });

        let (dirty_pubkeys, insert_time_us, mut generate_index_results) = self
            .accounts_index
            .insert_new_if_missing_into_primary_index(slot, storage.approx_stored_count(), items);

        if let Some(duplicates_this_slot) = std::mem::take(&mut generate_index_results.duplicates) {
            // there were duplicate pubkeys in this same slot
            // Some were not inserted. This means some info like stored data is off.
            duplicates_this_slot
                .into_iter()
                .for_each(|(pubkey, (_slot, info))| {
                    let duplicate = storage.accounts.get_account(info.offset()).unwrap().0;
                    assert_eq!(&pubkey, duplicate.pubkey());
                    stored_size_alive = stored_size_alive.saturating_sub(duplicate.stored_size());
                    if !duplicate.is_zero_lamport() {
                        accounts_data_len =
                            accounts_data_len.saturating_sub(duplicate.data().len() as u64);
                    }
                });
        }

        {
            // second, collect into the shared DashMap once we've figured out all the info per store_id
            let mut info = storage_info.entry(store_id).or_default();
            info.stored_size += stored_size_alive;
            info.count += generate_index_results.count;
        }

        // dirty_pubkeys will contain a pubkey if an item has multiple rooted entries for
        // a given pubkey. If there is just a single item, there is no cleaning to
        // be done on that pubkey. Use only those pubkeys with multiple updates.
        if !dirty_pubkeys.is_empty() {
            self.uncleaned_pubkeys.insert(slot, dirty_pubkeys);
        }
        SlotIndexGenerationInfo {
            insert_time_us,
            num_accounts: generate_index_results.count as u64,
            num_accounts_rent_paying,
            accounts_data_len,
            amount_to_top_off_rent,
            rent_paying_accounts_by_partition,
        }
    }

    pub fn generate_index(
        &self,
        limit_load_slot_count_from_snapshot: Option<usize>,
        verify: bool,
        genesis_config: &GenesisConfig,
    ) -> IndexGenerationInfo {
        let mut total_time = Measure::start("generate_index");
        let mut slots = self.storage.all_slots();
        slots.sort_unstable();
        if let Some(limit) = limit_load_slot_count_from_snapshot {
            slots.truncate(limit); // get rid of the newer slots and keep just the older
        }
        let max_slot = slots.last().cloned().unwrap_or_default();
        let schedule = &genesis_config.epoch_schedule;
        let rent_collector = RentCollector::new(
            schedule.get_epoch(max_slot),
            schedule.clone(),
            genesis_config.slots_per_year(),
            genesis_config.rent.clone(),
        );
        let accounts_data_len = AtomicU64::new(0);

        let rent_paying_accounts_by_partition =
            Mutex::new(RentPayingAccountsByPartition::new(schedule));

        // pass == 0 always runs and generates the index
        // pass == 1 only runs if verify == true.
        // verify checks that all the expected items are in the accounts index and measures how long it takes to look them all up
        let passes = if verify { 2 } else { 1 };
        for pass in 0..passes {
            if pass == 0 {
                self.accounts_index
                    .set_startup(Startup::StartupWithExtraThreads);
            }
            let storage_info = StorageSizeAndCountMap::default();
            let total_processed_slots_across_all_threads = AtomicU64::new(0);
            let outer_slots_len = slots.len();
            let threads = if self.accounts_index.is_disk_index_enabled() {
                // these write directly to disk, so the more threads, the better
                num_cpus::get()
            } else {
                // seems to be a good hueristic given varying # cpus for in-mem disk index
                8
            };
            let chunk_size = (outer_slots_len / (std::cmp::max(1, threads.saturating_sub(1)))) + 1; // approximately 400k slots in a snapshot
            let mut index_time = Measure::start("index");
            let insertion_time_us = AtomicU64::new(0);
            let rent_paying = AtomicUsize::new(0);
            let amount_to_top_off_rent = AtomicU64::new(0);
            let total_including_duplicates = AtomicU64::new(0);
            let scan_time: u64 = slots
                .par_chunks(chunk_size)
                .map(|slots| {
                    let mut log_status = MultiThreadProgress::new(
                        &total_processed_slots_across_all_threads,
                        2,
                        outer_slots_len as u64,
                    );
                    let mut scan_time_sum = 0;
                    for (index, slot) in slots.iter().enumerate() {
                        let mut scan_time = Measure::start("scan");
                        log_status.report(index as u64);
                        let Some(storage) = self.storage.get_slot_storage_entry(*slot) else {
                            // no storage at this slot, no information to pull out
                            continue;
                        };
                        let store_id = storage.append_vec_id();

                        scan_time.stop();
                        scan_time_sum += scan_time.as_us();

                        let insert_us = if pass == 0 {
                            // generate index
                            self.maybe_throttle_index_generation();
                            let SlotIndexGenerationInfo {
                                insert_time_us: insert_us,
                                num_accounts: total_this_slot,
                                num_accounts_rent_paying: rent_paying_this_slot,
                                accounts_data_len: accounts_data_len_this_slot,
                                amount_to_top_off_rent: amount_to_top_off_rent_this_slot,
                                rent_paying_accounts_by_partition:
                                    rent_paying_accounts_by_partition_this_slot,
                            } = self.generate_index_for_slot(
                                &storage,
                                *slot,
                                store_id,
                                &rent_collector,
                                &storage_info,
                            );

                            rent_paying.fetch_add(rent_paying_this_slot, Ordering::Relaxed);
                            amount_to_top_off_rent
                                .fetch_add(amount_to_top_off_rent_this_slot, Ordering::Relaxed);
                            total_including_duplicates
                                .fetch_add(total_this_slot, Ordering::Relaxed);
                            accounts_data_len
                                .fetch_add(accounts_data_len_this_slot, Ordering::Relaxed);
                            let mut rent_paying_accounts_by_partition =
                                rent_paying_accounts_by_partition.lock().unwrap();
                            rent_paying_accounts_by_partition_this_slot
                                .iter()
                                .for_each(|k| {
                                    rent_paying_accounts_by_partition.add_account(k);
                                });

                            insert_us
                        } else {
                            // verify index matches expected and measure the time to get all items
                            assert!(verify);
                            let mut lookup_time = Measure::start("lookup_time");
                            for account_info in storage.accounts.account_iter() {
                                let key = account_info.pubkey();
                                let lock = self.accounts_index.get_bin(key);
                                let x = lock.get(key).unwrap();
                                let sl = x.slot_list.read().unwrap();
                                let mut count = 0;
                                for (slot2, account_info2) in sl.iter() {
                                    if slot2 == slot {
                                        count += 1;
                                        let ai = AccountInfo::new(
                                            StorageLocation::AppendVec(
                                                store_id,
                                                account_info.offset(),
                                            ), // will never be cached
                                            account_info.lamports(),
                                        );
                                        assert_eq!(&ai, account_info2);
                                    }
                                }
                                assert_eq!(1, count);
                            }
                            lookup_time.stop();
                            lookup_time.as_us()
                        };
                        insertion_time_us.fetch_add(insert_us, Ordering::Relaxed);
                    }
                    scan_time_sum
                })
                .sum();
            index_time.stop();

            info!("rent_collector: {:?}", rent_collector);
            let (total_items, min_bin_size, max_bin_size) = self
                .accounts_index
                .account_maps
                .iter()
                .map(|map_bin| map_bin.len_for_stats())
                .fold((0, usize::MAX, usize::MIN), |acc, len| {
                    (
                        acc.0 + len,
                        std::cmp::min(acc.1, len),
                        std::cmp::max(acc.2, len),
                    )
                });

            let mut index_flush_us = 0;
            let total_duplicate_slot_keys = AtomicU64::default();
            let mut populate_duplicate_keys_us = 0;
            // outer vec is accounts index bin (determined by pubkey value)
            // inner vec is the pubkeys within that bin that are present in > 1 slot
            let unique_pubkeys_by_bin = Mutex::new(Vec::<Vec<Pubkey>>::default());
            if pass == 0 {
                // tell accounts index we are done adding the initial accounts at startup
                let mut m = Measure::start("accounts_index_idle_us");
                self.accounts_index.set_startup(Startup::Normal);
                m.stop();
                index_flush_us = m.as_us();

                populate_duplicate_keys_us = measure_us!({
                    // this has to happen before visit_duplicate_pubkeys_during_startup below
                    // get duplicate keys from acct idx. We have to wait until we've finished flushing.
                    self.accounts_index
                        .populate_and_retrieve_duplicate_keys_from_startup(|slot_keys| {
                            total_duplicate_slot_keys
                                .fetch_add(slot_keys.len() as u64, Ordering::Relaxed);
                            let unique_keys =
                                HashSet::<Pubkey>::from_iter(slot_keys.iter().map(|(_, key)| *key));
                            for (slot, key) in slot_keys {
                                self.uncleaned_pubkeys.entry(slot).or_default().push(key);
                            }
                            let unique_pubkeys_by_bin_inner =
                                unique_keys.into_iter().collect::<Vec<_>>();
                            // does not matter that this is not ordered by slot
                            unique_pubkeys_by_bin
                                .lock()
                                .unwrap()
                                .push(unique_pubkeys_by_bin_inner);
                        });
                })
                .1;
            }
            let unique_pubkeys_by_bin = unique_pubkeys_by_bin.into_inner().unwrap();

            let mut timings = GenerateIndexTimings {
                index_flush_us,
                scan_time,
                index_time: index_time.as_us(),
                insertion_time_us: insertion_time_us.load(Ordering::Relaxed),
                min_bin_size,
                max_bin_size,
                total_items,
                rent_paying,
                amount_to_top_off_rent,
                total_duplicate_slot_keys: total_duplicate_slot_keys.load(Ordering::Relaxed),
                populate_duplicate_keys_us,
                total_including_duplicates: total_including_duplicates.load(Ordering::Relaxed),
                total_slots: slots.len() as u64,
                ..GenerateIndexTimings::default()
            };

            if pass == 0 {
                #[derive(Debug, Default)]
                struct DuplicatePubkeysVisitedInfo {
                    accounts_data_len_from_duplicates: u64,
                    uncleaned_roots: IntSet<Slot>,
                }
                impl DuplicatePubkeysVisitedInfo {
                    fn reduce(mut a: Self, mut b: Self) -> Self {
                        if a.uncleaned_roots.len() >= b.uncleaned_roots.len() {
                            a.merge(b);
                            a
                        } else {
                            b.merge(a);
                            b
                        }
                    }
                    fn merge(&mut self, other: Self) {
                        self.accounts_data_len_from_duplicates +=
                            other.accounts_data_len_from_duplicates;
                        self.uncleaned_roots.extend(other.uncleaned_roots);
                    }
                }

                // subtract data.len() from accounts_data_len for all old accounts that are in the index twice
                let mut accounts_data_len_dedup_timer =
                    Measure::start("handle accounts data len duplicates");
                let DuplicatePubkeysVisitedInfo {
                    accounts_data_len_from_duplicates,
                    uncleaned_roots,
                } = unique_pubkeys_by_bin
                    .par_iter()
                    .fold(
                        DuplicatePubkeysVisitedInfo::default,
                        |accum, pubkeys_by_bin| {
                            let intermediate = pubkeys_by_bin
                                .par_chunks(4096)
                                .fold(DuplicatePubkeysVisitedInfo::default, |accum, pubkeys| {
                                    let (accounts_data_len_from_duplicates, uncleaned_roots) = self
                                        .visit_duplicate_pubkeys_during_startup(
                                            pubkeys,
                                            &rent_collector,
                                            &timings,
                                        );
                                    let intermediate = DuplicatePubkeysVisitedInfo {
                                        accounts_data_len_from_duplicates,
                                        uncleaned_roots,
                                    };
                                    DuplicatePubkeysVisitedInfo::reduce(accum, intermediate)
                                })
                                .reduce(
                                    DuplicatePubkeysVisitedInfo::default,
                                    DuplicatePubkeysVisitedInfo::reduce,
                                );
                            DuplicatePubkeysVisitedInfo::reduce(accum, intermediate)
                        },
                    )
                    .reduce(
                        DuplicatePubkeysVisitedInfo::default,
                        DuplicatePubkeysVisitedInfo::reduce,
                    );
                accounts_data_len_dedup_timer.stop();
                timings.accounts_data_len_dedup_time_us = accounts_data_len_dedup_timer.as_us();
                timings.slots_to_clean = uncleaned_roots.len() as u64;

                self.accounts_index
                    .add_uncleaned_roots(uncleaned_roots.into_iter());
                accounts_data_len.fetch_sub(accounts_data_len_from_duplicates, Ordering::Relaxed);
                info!(
                    "accounts data len: {}",
                    accounts_data_len.load(Ordering::Relaxed)
                );
            }

            if pass == 0 {
                // Need to add these last, otherwise older updates will be cleaned
                for root in &slots {
                    self.accounts_index.add_root(*root);
                }

                self.set_storage_count_and_alive_bytes(storage_info, &mut timings);
            }
            total_time.stop();
            timings.total_time_us = total_time.as_us();
            timings.report(self.accounts_index.get_startup_stats());
        }

        self.accounts_index.log_secondary_indexes();

        IndexGenerationInfo {
            accounts_data_len: accounts_data_len.load(Ordering::Relaxed),
            rent_paying_accounts_by_partition: rent_paying_accounts_by_partition
                .into_inner()
                .unwrap(),
        }
    }

    /// Startup processes can consume large amounts of memory while inserting accounts into the index as fast as possible.
    /// Calling this can slow down the insertion process to allow flushing to disk to keep pace.
    fn maybe_throttle_index_generation(&self) {
        // This number is chosen to keep the initial ram usage sufficiently small
        // The process of generating the index is goverened entirely by how fast the disk index can be populated.
        // 10M accounts is sufficiently small that it will never have memory usage. It seems sufficiently large that it will provide sufficient performance.
        // Performance is measured by total time to generate the index.
        // Just estimating - 150M accounts can easily be held in memory in the accounts index on a 256G machine. 2-300M are also likely 'fine' during startup.
        // 550M was straining a 384G machine at startup.
        // This is a tunable parameter that just needs to be small enough to keep the generation threads from overwhelming RAM and oom at startup.
        const LIMIT: usize = 10_000_000;
        while self
            .accounts_index
            .get_startup_remaining_items_to_flush_estimate()
            > LIMIT
        {
            // 10 ms is long enough to allow some flushing to occur before insertion is resumed.
            // callers of this are typically run in parallel, so many threads will be sleeping at different starting intervals, waiting to resume insertion.
            sleep(Duration::from_millis(10));
        }
    }

    /// Used during generate_index() to:
    /// 1. get the _duplicate_ accounts data len from the given pubkeys
    /// 2. get the slots that contained duplicate pubkeys
    /// 3. update rent stats
    /// Note this should only be used when ALL entries in the accounts index are roots.
    /// returns (data len sum of all older duplicates, slots that contained duplicate pubkeys)
    fn visit_duplicate_pubkeys_during_startup(
        &self,
        pubkeys: &[Pubkey],
        rent_collector: &RentCollector,
        timings: &GenerateIndexTimings,
    ) -> (u64, IntSet<Slot>) {
        let mut accounts_data_len_from_duplicates = 0;
        let mut uncleaned_slots = IntSet::default();
        let mut removed_rent_paying = 0;
        let mut removed_top_off = 0;
        self.accounts_index.scan(
            pubkeys.iter(),
            |pubkey, slots_refs, _entry| {
                if let Some((slot_list, _ref_count)) = slots_refs {
                    if slot_list.len() > 1 {
                        // Only the account data len in the highest slot should be used, and the rest are
                        // duplicates.  So find the max slot to keep.
                        // Then sum up the remaining data len, which are the duplicates.
                        // All of the slots need to go in the 'uncleaned_slots' list. For clean to work properly,
                        // the slot where duplicate accounts are found in the index need to be in 'uncleaned_slots' list, too.
                        let max = slot_list.iter().map(|(slot, _)| slot).max().unwrap();
                        slot_list.iter().for_each(|(slot, account_info)| {
                            uncleaned_slots.insert(*slot);
                            if slot == max {
                                // the info in 'max' is the most recent, current info for this pubkey
                                return;
                            }
                            let maybe_storage_entry = self
                                .storage
                                .get_account_storage_entry(*slot, account_info.store_id());
                            let mut accessor = LoadedAccountAccessor::Stored(
                                maybe_storage_entry.map(|entry| (entry, account_info.offset())),
                            );
                            let loaded_account = accessor.check_and_get_loaded_account();
                            accounts_data_len_from_duplicates += loaded_account.data().len();
                            if let Some(lamports_to_top_off) =
                                Self::stats_for_rent_payers(pubkey, &loaded_account, rent_collector)
                            {
                                removed_rent_paying += 1;
                                removed_top_off += lamports_to_top_off;
                            }
                        });
                    }
                }
                AccountsIndexScanResult::OnlyKeepInMemoryIfDirty
            },
            None,
            false,
        );
        timings
            .rent_paying
            .fetch_sub(removed_rent_paying, Ordering::Relaxed);
        timings
            .amount_to_top_off_rent
            .fetch_sub(removed_top_off, Ordering::Relaxed);
        (accounts_data_len_from_duplicates as u64, uncleaned_slots)
    }

    fn set_storage_count_and_alive_bytes(
        &self,
        stored_sizes_and_counts: StorageSizeAndCountMap,
        timings: &mut GenerateIndexTimings,
    ) {
        // store count and size for each storage
        let mut storage_size_storages_time = Measure::start("storage_size_storages");
        for (_slot, store) in self.storage.iter() {
            let id = store.append_vec_id();
            // Should be default at this point
            assert_eq!(store.alive_bytes(), 0);
            if let Some(entry) = stored_sizes_and_counts.get(&id) {
                trace!(
                    "id: {} setting count: {} cur: {}",
                    id,
                    entry.count,
                    store.count(),
                );
                {
                    let mut count_and_status = store.count_and_status.lock_write();
                    assert_eq!(count_and_status.0, 0);
                    count_and_status.0 = entry.count;
                }
                store.alive_bytes.store(entry.stored_size, Ordering::SeqCst);
                assert!(
                    store.approx_stored_count() >= entry.count,
                    "{}, {}",
                    store.approx_stored_count(),
                    entry.count
                );
            } else {
                trace!("id: {} clearing count", id);
                store.count_and_status.lock_write().0 = 0;
            }
        }
        storage_size_storages_time.stop();
        timings.storage_size_storages_us = storage_size_storages_time.as_us();
    }

    pub fn print_accounts_stats(&self, label: &str) {
        self.print_index(label);
        self.print_count_and_status(label);
        info!("recycle_stores:");
        let recycle_stores = self.recycle_stores.read().unwrap();
        for (recycled_time, entry) in recycle_stores.iter() {
            info!(
                "  slot: {} id: {} count_and_status: {:?} approx_store_count: {} len: {} capacity: {} (recycled: {:?})",
                entry.slot(),
                entry.append_vec_id(),
                entry.count_and_status.read(),
                entry.approx_store_count.load(Ordering::Relaxed),
                entry.accounts.len(),
                entry.accounts.capacity(),
                recycled_time,
            );
        }
    }

    fn print_index(&self, label: &str) {
        let mut alive_roots: Vec<_> = self.accounts_index.all_alive_roots();
        #[allow(clippy::stable_sort_primitive)]
        alive_roots.sort();
        info!("{}: accounts_index alive_roots: {:?}", label, alive_roots,);
        let full_pubkey_range = Pubkey::from([0; 32])..=Pubkey::from([0xff; 32]);

        self.accounts_index.account_maps.iter().for_each(|map| {
            for (pubkey, account_entry) in map.items(&full_pubkey_range) {
                info!("  key: {} ref_count: {}", pubkey, account_entry.ref_count(),);
                info!(
                    "      slots: {:?}",
                    *account_entry.slot_list.read().unwrap()
                );
            }
        });
    }

    pub fn print_count_and_status(&self, label: &str) {
        let mut slots: Vec<_> = self.storage.all_slots();
        #[allow(clippy::stable_sort_primitive)]
        slots.sort();
        info!("{}: count_and status for {} slots:", label, slots.len());
        for slot in &slots {
            let entry = self.storage.get_slot_storage_entry(*slot).unwrap();
            info!(
                "  slot: {} id: {} count_and_status: {:?} approx_store_count: {} len: {} capacity: {}",
                slot,
                entry.append_vec_id(),
                entry.count_and_status.read(),
                entry.approx_store_count.load(Ordering::Relaxed),
                entry.accounts.len(),
                entry.accounts.capacity(),
            );
        }
    }
}

/// Specify the source of the accounts data when calculating the accounts hash
///
/// Using the Index is meant for testing the hash calculation itself and debugging;
/// not intended during normal validator operation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CalcAccountsHashDataSource {
    IndexForTests,
    Storages,
}

/// Which accounts hash calculation is being performed?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CalcAccountsHashKind {
    Full,
    Incremental,
}

impl CalcAccountsHashKind {
    /// How should zero-lamport accounts be handled by this accounts hash calculation?
    fn zero_lamport_accounts(&self) -> ZeroLamportAccounts {
        match self {
            CalcAccountsHashKind::Full => ZeroLamportAccounts::Excluded,
            CalcAccountsHashKind::Incremental => ZeroLamportAccounts::Included,
        }
    }
}

pub(crate) enum UpdateIndexThreadSelection {
    /// Use current thread only
    Inline,
    /// Use a thread-pool if the number of updates exceeds a threshold
    PoolWithThreshold,
}

// These functions/fields are only usable from a dev context (i.e. tests and benches)
#[cfg(feature = "dev-context-only-utils")]
impl AccountsDb {
    pub fn load_without_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.do_load(
            ancestors,
            pubkey,
            None,
            LoadHint::Unspecified,
            // callers of this expect zero lamport accounts that exist in the index to be returned as Some(empty)
            LoadZeroLamports::SomeWithZeroLamportAccountForTests,
        )
    }

    pub fn accounts_delta_hashes(&self) -> &Mutex<HashMap<Slot, AccountsDeltaHash>> {
        &self.accounts_delta_hashes
    }

    pub fn accounts_hashes(&self) -> &Mutex<HashMap<Slot, (AccountsHash, /*capitalization*/ u64)>> {
        &self.accounts_hashes
    }

    pub fn assert_load_account(&self, slot: Slot, pubkey: Pubkey, expected_lamports: u64) {
        let ancestors = vec![(slot, 0)].into_iter().collect();
        let (account, slot) = self.load_without_fixed_root(&ancestors, &pubkey).unwrap();
        assert_eq!((account.lamports(), slot), (expected_lamports, slot));
    }

    pub fn assert_not_load_account(&self, slot: Slot, pubkey: Pubkey) {
        let ancestors = vec![(slot, 0)].into_iter().collect();
        let load = self.load_without_fixed_root(&ancestors, &pubkey);
        assert!(load.is_none(), "{load:?}");
    }

    pub fn check_accounts(&self, pubkeys: &[Pubkey], slot: Slot, num: usize, count: usize) {
        let ancestors = vec![(slot, 0)].into_iter().collect();
        for _ in 0..num {
            let idx = thread_rng().gen_range(0..num);
            let account = self.load_without_fixed_root(&ancestors, &pubkeys[idx]);
            let account1 = Some((
                AccountSharedData::new(
                    (idx + count) as u64,
                    0,
                    AccountSharedData::default().owner(),
                ),
                slot,
            ));
            assert_eq!(account, account1);
        }
    }

    /// callers used to call store_uncached. But, this is not allowed anymore.
    pub fn store_for_tests(&self, slot: Slot, accounts: &[(&Pubkey, &AccountSharedData)]) {
        self.store(
            (slot, accounts),
            &StoreTo::Cache,
            None,
            StoreReclaims::Default,
            UpdateIndexThreadSelection::PoolWithThreshold,
        );
    }

    #[allow(clippy::needless_range_loop)]
    pub fn modify_accounts(&self, pubkeys: &[Pubkey], slot: Slot, num: usize, count: usize) {
        for idx in 0..num {
            let account = AccountSharedData::new(
                (idx + count) as u64,
                0,
                AccountSharedData::default().owner(),
            );
            self.store_for_tests(slot, &[(&pubkeys[idx], &account)]);
        }
    }

    pub fn check_storage(&self, slot: Slot, count: usize) {
        assert!(self.storage.get_slot_storage_entry(slot).is_some());
        let store = self.storage.get_slot_storage_entry(slot).unwrap();
        let total_count = store.count();
        assert_eq!(store.status(), AccountStorageStatus::Available);
        assert_eq!(total_count, count);
        let (expected_store_count, actual_store_count): (usize, usize) =
            (store.approx_stored_count(), store.all_accounts().len());
        assert_eq!(expected_store_count, actual_store_count);
    }

    pub fn create_account(
        &self,
        pubkeys: &mut Vec<Pubkey>,
        slot: Slot,
        num: usize,
        space: usize,
        num_vote: usize,
    ) {
        let ancestors = vec![(slot, 0)].into_iter().collect();
        for t in 0..num {
            let pubkey = solana_sdk::pubkey::new_rand();
            let account =
                AccountSharedData::new((t + 1) as u64, space, AccountSharedData::default().owner());
            pubkeys.push(pubkey);
            assert!(self.load_without_fixed_root(&ancestors, &pubkey).is_none());
            self.store_for_tests(slot, &[(&pubkey, &account)]);
        }
        for t in 0..num_vote {
            let pubkey = solana_sdk::pubkey::new_rand();
            let account =
                AccountSharedData::new((num + t + 1) as u64, space, &solana_vote_program::id());
            pubkeys.push(pubkey);
            let ancestors = vec![(slot, 0)].into_iter().collect();
            assert!(self.load_without_fixed_root(&ancestors, &pubkey).is_none());
            self.store_for_tests(slot, &[(&pubkey, &account)]);
        }
    }

    pub fn sizes_of_accounts_in_storage_for_tests(&self, slot: Slot) -> Vec<usize> {
        self.storage
            .get_slot_storage_entry(slot)
            .map(|storage| {
                storage
                    .accounts
                    .account_iter()
                    .map(|account| account.stored_size())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn ref_count_for_pubkey(&self, pubkey: &Pubkey) -> RefCount {
        self.accounts_index.ref_count_from_storage(pubkey)
    }

    pub fn alive_account_count_in_slot(&self, slot: Slot) -> usize {
        self.storage
            .get_slot_storage_entry(slot)
            .map(|storage| storage.count())
            .unwrap_or(0)
            .saturating_add(
                self.accounts_cache
                    .slot_cache(slot)
                    .map(|slot_cache| slot_cache.len())
                    .unwrap_or_default(),
            )
    }

    /// useful to adapt tests written prior to introduction of the write cache
    /// to use the write cache
    pub fn add_root_and_flush_write_cache(&self, slot: Slot) {
        self.add_root(slot);
        self.flush_root_write_cache(slot);
    }

    /// useful to adapt tests written prior to introduction of the write cache
    /// to use the write cache
    pub fn flush_root_write_cache(&self, root: Slot) {
        assert!(
            self.accounts_index
                .roots_tracker
                .read()
                .unwrap()
                .alive_roots
                .contains(&root),
            "slot: {root}"
        );
        self.flush_accounts_cache(true, Some(root));
    }

    pub fn all_account_count_in_append_vec(&self, slot: Slot) -> usize {
        let store = self.storage.get_slot_storage_entry(slot);
        if let Some(store) = store {
            let count = store.all_accounts().len();
            let stored_count = store.approx_stored_count();
            assert_eq!(stored_count, count);
            count
        } else {
            0
        }
    }
}

// These functions/fields are only usable from a dev context (i.e. tests and benches)
#[cfg(feature = "dev-context-only-utils")]
impl<'a> VerifyAccountsHashAndLamportsConfig<'a> {
    pub fn new_for_test(
        ancestors: &'a Ancestors,
        epoch_schedule: &'a EpochSchedule,
        rent_collector: &'a RentCollector,
    ) -> Self {
        Self {
            ancestors,
            test_hash_calculation: true,
            epoch_schedule,
            rent_collector,
            ignore_mismatch: false,
            store_detailed_debug_info: false,
            use_bg_thread_pool: false,
        }
    }
}

/// A set of utility functions used for testing and benchmarking
pub mod test_utils {
    use {
        super::*,
        crate::{accounts::Accounts, append_vec::aligned_stored_size},
    };

    pub fn create_test_accounts(
        accounts: &Accounts,
        pubkeys: &mut Vec<Pubkey>,
        num: usize,
        slot: Slot,
    ) {
        let data_size = 0;
        if accounts
            .accounts_db
            .storage
            .get_slot_storage_entry(slot)
            .is_none()
        {
            let bytes_required = num * aligned_stored_size(data_size);
            // allocate an append vec for this slot that can hold all the test accounts. This prevents us from creating more than 1 append vec for this slot.
            _ = accounts.accounts_db.create_and_insert_store(
                slot,
                AccountsDb::page_align(bytes_required as u64),
                "create_test_accounts",
            );
        }

        for t in 0..num {
            let pubkey = solana_sdk::pubkey::new_rand();
            let account = AccountSharedData::new(
                (t + 1) as u64,
                data_size,
                AccountSharedData::default().owner(),
            );
            accounts.store_slow_uncached(slot, &pubkey, &account);
            pubkeys.push(pubkey);
        }
    }

    // Only used by bench, not safe to call otherwise accounts can conflict with the
    // accounts cache!
    pub fn update_accounts_bench(accounts: &Accounts, pubkeys: &[Pubkey], slot: u64) {
        for pubkey in pubkeys {
            let amount = thread_rng().gen_range(0..10);
            let account = AccountSharedData::new(amount, 0, AccountSharedData::default().owner());
            accounts.store_slow_uncached(slot, pubkey, &account);
        }
    }
}
