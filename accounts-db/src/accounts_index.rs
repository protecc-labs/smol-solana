use {
    crate::{
        accounts_index_storage::{AccountsIndexStorage, Startup},
        accounts_partition::RentPayingAccountsByPartition,
        ancestors::Ancestors,
        bucket_map_holder::{Age, AtomicAge, BucketMapHolder},
        contains::Contains,
        in_mem_accounts_index::{InMemAccountsIndex, InsertNewEntryResults, StartupStats},
        inline_spl_token::{self, GenericTokenAccount},
        inline_spl_token_2022,
        pubkey_bins::PubkeyBinCalculator24,
        rolling_bit_field::RollingBitField,
        secondary_index::*,
    },
    log::*,
    ouroboros::self_referencing,
    rand::{thread_rng, Rng},
    rayon::{
        iter::{IntoParallelIterator, ParallelIterator},
        ThreadPool,
    },
    solana_measure::measure::Measure,
    solana_nohash_hasher::IntSet,
    solana_sdk::{
        account::ReadableAccount,
        clock::{BankId, Slot},
        pubkey::Pubkey,
    },
    std::{
        collections::{btree_map::BTreeMap, HashSet},
        fmt::Debug,
        ops::{
            Bound,
            Bound::{Excluded, Included, Unbounded},
            Range, RangeBounds,
        },
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
            Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard,
        },
    },
    thiserror::Error,
};

pub const ITER_BATCH_SIZE: usize = 1000;
pub const BINS_DEFAULT: usize = 8192;
pub const BINS_FOR_TESTING: usize = 2; // we want > 1, but each bin is a few disk files with a disk based index, so fewer is better
pub const BINS_FOR_BENCHMARKS: usize = 8192;
pub const FLUSH_THREADS_TESTING: usize = 1;
pub const ACCOUNTS_INDEX_CONFIG_FOR_TESTING: AccountsIndexConfig = AccountsIndexConfig {
    bins: Some(BINS_FOR_TESTING),
    flush_threads: Some(FLUSH_THREADS_TESTING),
    drives: None,
    index_limit_mb: IndexLimitMb::Unspecified,
    ages_to_stay_in_cache: None,
    scan_results_limit_bytes: None,
    started_from_validator: false,
};
pub const ACCOUNTS_INDEX_CONFIG_FOR_BENCHMARKS: AccountsIndexConfig = AccountsIndexConfig {
    bins: Some(BINS_FOR_BENCHMARKS),
    flush_threads: Some(FLUSH_THREADS_TESTING),
    drives: None,
    index_limit_mb: IndexLimitMb::Unspecified,
    ages_to_stay_in_cache: None,
    scan_results_limit_bytes: None,
    started_from_validator: false,
};
pub type ScanResult<T> = Result<T, ScanError>;
pub type SlotList<T> = Vec<(Slot, T)>;
pub type SlotSlice<'s, T> = &'s [(Slot, T)];
pub type RefCount = u64;
pub type AccountMap<T, U> = Arc<InMemAccountsIndex<T, U>>;

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct GenerateIndexResult<T: IndexValue> {
    /// number of accounts inserted in the index
    pub count: usize,
    /// pubkeys which were present multiple times in the insertion request.
    pub duplicates: Option<Vec<(Pubkey, (Slot, T))>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// how accounts index 'upsert' should handle reclaims
pub enum UpsertReclaim {
    /// previous entry for this slot in the index is expected to be cached, so irrelevant to reclaims
    PreviousSlotEntryWasCached,
    /// previous entry for this slot in the index may need to be reclaimed, so return it.
    /// reclaims is the only output of upsert, requiring a synchronous execution
    PopulateReclaims,
    /// overwrite existing data in the same slot and do not return in 'reclaims'
    IgnoreReclaims,
}

#[derive(Debug, Default)]
pub struct ScanConfig {
    /// checked by the scan. When true, abort scan.
    pub abort: Option<Arc<AtomicBool>>,

    /// true to allow return of all matching items and allow them to be unsorted.
    /// This is more efficient.
    pub collect_all_unsorted: bool,
}

impl ScanConfig {
    pub fn new(collect_all_unsorted: bool) -> Self {
        Self {
            collect_all_unsorted,
            ..ScanConfig::default()
        }
    }

    /// mark the scan as aborted
    pub fn abort(&self) {
        if let Some(abort) = self.abort.as_ref() {
            abort.store(true, Ordering::Relaxed)
        }
    }

    /// use existing 'abort' if available, otherwise allocate one
    pub fn recreate_with_abort(&self) -> Self {
        ScanConfig {
            abort: Some(self.abort.as_ref().map(Arc::clone).unwrap_or_default()),
            collect_all_unsorted: self.collect_all_unsorted,
        }
    }

    /// true if scan should abort
    pub fn is_aborted(&self) -> bool {
        if let Some(abort) = self.abort.as_ref() {
            abort.load(Ordering::Relaxed)
        } else {
            false
        }
    }
}

pub(crate) type AccountMapEntry<T> = Arc<AccountMapEntryInner<T>>;

pub trait IsCached {
    fn is_cached(&self) -> bool;
}

pub trait IndexValue: 'static + IsCached + ZeroLamport + DiskIndexValue {}

pub trait DiskIndexValue:
    'static + Clone + Debug + PartialEq + Copy + Default + Sync + Send
{
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ScanError {
    #[error("Node detected it replayed bad version of slot {slot:?} with id {bank_id:?}, thus the scan on said slot was aborted")]
    SlotRemoved { slot: Slot, bank_id: BankId },
    #[error("scan aborted: {0}")]
    Aborted(String),
}

enum ScanTypes<R: RangeBounds<Pubkey>> {
    Unindexed(Option<R>),
    Indexed(IndexKey),
}

#[derive(Debug, Clone, Copy)]
pub enum IndexKey {
    ProgramId(Pubkey),
    SplTokenMint(Pubkey),
    SplTokenOwner(Pubkey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccountIndex {
    ProgramId,
    SplTokenMint,
    SplTokenOwner,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccountSecondaryIndexesIncludeExclude {
    pub exclude: bool,
    pub keys: HashSet<Pubkey>,
}

/// specification of how much memory in-mem portion of account index can use
#[derive(Debug, Clone)]
pub enum IndexLimitMb {
    /// nothing explicit specified, so default
    Unspecified,
    /// limit was specified, use disk index for rest
    Limit(usize),
    /// in-mem-only was specified, no disk index
    InMemOnly,
}

impl Default for IndexLimitMb {
    fn default() -> Self {
        Self::Unspecified
    }
}

#[derive(Debug, Default, Clone)]
pub struct AccountsIndexConfig {
    pub bins: Option<usize>,
    pub flush_threads: Option<usize>,
    pub drives: Option<Vec<PathBuf>>,
    pub index_limit_mb: IndexLimitMb,
    pub ages_to_stay_in_cache: Option<Age>,
    pub scan_results_limit_bytes: Option<usize>,
    /// true if the accounts index is being created as a result of being started as a validator (as opposed to test, etc.)
    pub started_from_validator: bool,
}

#[derive(Debug, Default, Clone)]
pub struct AccountSecondaryIndexes {
    pub keys: Option<AccountSecondaryIndexesIncludeExclude>,
    pub indexes: HashSet<AccountIndex>,
}

impl AccountSecondaryIndexes {
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty()
    }
    pub fn contains(&self, index: &AccountIndex) -> bool {
        self.indexes.contains(index)
    }
    pub fn include_key(&self, key: &Pubkey) -> bool {
        match &self.keys {
            Some(options) => options.exclude ^ options.keys.contains(key),
            None => true, // include all keys
        }
    }
}

#[derive(Debug, Default)]
/// data per entry in in-mem accounts index
/// used to keep track of consistency with disk index
pub struct AccountMapEntryMeta {
    /// true if entry in in-mem idx has changes and needs to be written to disk
    pub dirty: AtomicBool,
    /// 'age' at which this entry should be purged from the cache (implements lru)
    pub age: AtomicAge,
}

impl AccountMapEntryMeta {
    pub fn new_dirty<T: IndexValue, U: DiskIndexValue + From<T> + Into<T>>(
        storage: &Arc<BucketMapHolder<T, U>>,
        is_cached: bool,
    ) -> Self {
        AccountMapEntryMeta {
            dirty: AtomicBool::new(true),
            age: AtomicAge::new(storage.future_age_to_flush(is_cached)),
        }
    }
    pub fn new_clean<T: IndexValue, U: DiskIndexValue + From<T> + Into<T>>(
        storage: &Arc<BucketMapHolder<T, U>>,
    ) -> Self {
        AccountMapEntryMeta {
            dirty: AtomicBool::new(false),
            age: AtomicAge::new(storage.future_age_to_flush(false)),
        }
    }
}

#[derive(Debug, Default)]
/// one entry in the in-mem accounts index
/// Represents the value for an account key in the in-memory accounts index
pub struct AccountMapEntryInner<T> {
    /// number of alive slots that contain >= 1 instances of account data for this pubkey
    /// where alive represents a slot that has not yet been removed by clean via AccountsDB::clean_stored_dead_slots() for containing no up to date account information
    ref_count: AtomicU64,
    /// list of slots in which this pubkey was updated
    /// Note that 'clean' removes outdated entries (ie. older roots) from this slot_list
    /// purge_slot() also removes non-rooted slots from this list
    pub slot_list: RwLock<SlotList<T>>,
    /// synchronization metadata for in-memory state since last flush to disk accounts index
    pub meta: AccountMapEntryMeta,
}

impl<T: IndexValue> AccountMapEntryInner<T> {
    pub fn new(slot_list: SlotList<T>, ref_count: RefCount, meta: AccountMapEntryMeta) -> Self {
        Self {
            slot_list: RwLock::new(slot_list),
            ref_count: AtomicU64::new(ref_count),
            meta,
        }
    }
    pub fn ref_count(&self) -> RefCount {
        self.ref_count.load(Ordering::Acquire)
    }

    pub fn addref(&self) {
        self.ref_count.fetch_add(1, Ordering::Release);
        self.set_dirty(true);
    }

    /// decrement the ref count
    /// return true if the old refcount was already 0. This indicates an under refcounting error in the system.
    pub fn unref(&self) -> bool {
        let previous = self.ref_count.fetch_sub(1, Ordering::Release);
        self.set_dirty(true);
        if previous == 0 {
            inc_new_counter_info!("accounts_index-deref_from_0", 1);
        }
        previous == 0
    }

    pub fn dirty(&self) -> bool {
        self.meta.dirty.load(Ordering::Acquire)
    }

    pub fn set_dirty(&self, value: bool) {
        self.meta.dirty.store(value, Ordering::Release)
    }

    /// set dirty to false, return true if was dirty
    pub fn clear_dirty(&self) -> bool {
        self.meta
            .dirty
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    pub fn age(&self) -> Age {
        self.meta.age.load(Ordering::Acquire)
    }

    pub fn set_age(&self, value: Age) {
        self.meta.age.store(value, Ordering::Release)
    }

    /// set age to 'next_age' if 'self.age' is 'expected_age'
    pub fn try_exchange_age(&self, next_age: Age, expected_age: Age) {
        let _ = self.meta.age.compare_exchange(
            expected_age,
            next_age,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}

pub enum AccountIndexGetResult<T: IndexValue> {
    /// (index entry, index in slot list)
    Found(ReadAccountMapEntry<T>, usize),
    NotFound,
}

#[self_referencing]
pub struct ReadAccountMapEntry<T: IndexValue> {
    owned_entry: AccountMapEntry<T>,
    #[borrows(owned_entry)]
    #[covariant]
    slot_list_guard: RwLockReadGuard<'this, SlotList<T>>,
}

impl<T: IndexValue> Debug for ReadAccountMapEntry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.borrow_owned_entry())
    }
}

impl<T: IndexValue> ReadAccountMapEntry<T> {
    pub fn from_account_map_entry(account_map_entry: AccountMapEntry<T>) -> Self {
        ReadAccountMapEntryBuilder {
            owned_entry: account_map_entry,
            slot_list_guard_builder: |lock| lock.slot_list.read().unwrap(),
        }
        .build()
    }

    pub fn slot_list(&self) -> &SlotList<T> {
        self.borrow_slot_list_guard()
    }

    pub fn ref_count(&self) -> RefCount {
        self.borrow_owned_entry().ref_count()
    }

    pub fn addref(&self) {
        self.borrow_owned_entry().addref();
    }
}

/// can be used to pre-allocate structures for insertion into accounts index outside of lock
pub enum PreAllocatedAccountMapEntry<T: IndexValue> {
    Entry(AccountMapEntry<T>),
    Raw((Slot, T)),
}

impl<T: IndexValue> ZeroLamport for PreAllocatedAccountMapEntry<T> {
    fn is_zero_lamport(&self) -> bool {
        match self {
            PreAllocatedAccountMapEntry::Entry(entry) => {
                entry.slot_list.read().unwrap()[0].1.is_zero_lamport()
            }
            PreAllocatedAccountMapEntry::Raw(raw) => raw.1.is_zero_lamport(),
        }
    }
}

impl<T: IndexValue> From<PreAllocatedAccountMapEntry<T>> for (Slot, T) {
    fn from(source: PreAllocatedAccountMapEntry<T>) -> (Slot, T) {
        match source {
            PreAllocatedAccountMapEntry::Entry(entry) => entry.slot_list.read().unwrap()[0],
            PreAllocatedAccountMapEntry::Raw(raw) => raw,
        }
    }
}

impl<T: IndexValue> PreAllocatedAccountMapEntry<T> {
    /// create an entry that is equivalent to this process:
    /// 1. new empty (refcount=0, slot_list={})
    /// 2. update(slot, account_info)
    /// This code is called when the first entry [ie. (slot,account_info)] for a pubkey is inserted into the index.
    pub fn new<U: DiskIndexValue + From<T> + Into<T>>(
        slot: Slot,
        account_info: T,
        storage: &Arc<BucketMapHolder<T, U>>,
        store_raw: bool,
    ) -> PreAllocatedAccountMapEntry<T> {
        if store_raw {
            Self::Raw((slot, account_info))
        } else {
            Self::Entry(Self::allocate(slot, account_info, storage))
        }
    }

    fn allocate<U: DiskIndexValue + From<T> + Into<T>>(
        slot: Slot,
        account_info: T,
        storage: &Arc<BucketMapHolder<T, U>>,
    ) -> AccountMapEntry<T> {
        let is_cached = account_info.is_cached();
        let ref_count = u64::from(!is_cached);
        let meta = AccountMapEntryMeta::new_dirty(storage, is_cached);
        Arc::new(AccountMapEntryInner::new(
            vec![(slot, account_info)],
            ref_count,
            meta,
        ))
    }

    pub fn into_account_map_entry<U: DiskIndexValue + From<T> + Into<T>>(
        self,
        storage: &Arc<BucketMapHolder<T, U>>,
    ) -> AccountMapEntry<T> {
        match self {
            Self::Entry(entry) => entry,
            Self::Raw((slot, account_info)) => Self::allocate(slot, account_info, storage),
        }
    }
}

#[derive(Debug)]
pub struct RootsTracker {
    /// Current roots where appendvecs or write cache has account data.
    /// Constructed during load from snapshots.
    /// Updated every time we add a new root or clean/shrink an append vec into irrelevancy.
    /// Range is approximately the last N slots where N is # slots per epoch.
    pub alive_roots: RollingBitField,
    uncleaned_roots: IntSet<Slot>,
}

impl Default for RootsTracker {
    fn default() -> Self {
        // we expect to keep a rolling set of 400k slots around at a time
        // 4M gives us plenty of extra(?!) room to handle a width 10x what we should need.
        // cost is 4M bits of memory, which is .5MB
        RootsTracker::new(4194304)
    }
}

impl RootsTracker {
    pub fn new(max_width: u64) -> Self {
        Self {
            alive_roots: RollingBitField::new(max_width),
            uncleaned_roots: IntSet::default(),
        }
    }

    pub fn min_alive_root(&self) -> Option<Slot> {
        self.alive_roots.min()
    }
}

#[derive(Debug, Default)]
pub struct AccountsIndexRootsStats {
    pub roots_len: Option<usize>,
    pub uncleaned_roots_len: Option<usize>,
    pub roots_range: Option<u64>,
    pub rooted_cleaned_count: usize,
    pub unrooted_cleaned_count: usize,
    pub clean_unref_from_storage_us: u64,
    pub clean_dead_slot_us: u64,
}

pub struct AccountsIndexIterator<'a, T: IndexValue, U: DiskIndexValue + From<T> + Into<T>> {
    account_maps: &'a LockMapTypeSlice<T, U>,
    bin_calculator: &'a PubkeyBinCalculator24,
    start_bound: Bound<Pubkey>,
    end_bound: Bound<Pubkey>,
    is_finished: bool,
    collect_all_unsorted: bool,
}

impl<'a, T: IndexValue, U: DiskIndexValue + From<T> + Into<T>> AccountsIndexIterator<'a, T, U> {
    fn range<R>(
        map: &AccountMaps<T, U>,
        range: R,
        collect_all_unsorted: bool,
    ) -> Vec<(Pubkey, AccountMapEntry<T>)>
    where
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        let mut result = map.items(&range);
        if !collect_all_unsorted {
            result.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        }
        result
    }

    fn clone_bound(bound: Bound<&Pubkey>) -> Bound<Pubkey> {
        match bound {
            Unbounded => Unbounded,
            Included(k) => Included(*k),
            Excluded(k) => Excluded(*k),
        }
    }

    fn bin_from_bound(&self, bound: &Bound<Pubkey>, unbounded_bin: usize) -> usize {
        match bound {
            Bound::Included(bound) | Bound::Excluded(bound) => {
                self.bin_calculator.bin_from_pubkey(bound)
            }
            Bound::Unbounded => unbounded_bin,
        }
    }

    fn start_bin(&self) -> usize {
        // start in bin where 'start_bound' would exist
        self.bin_from_bound(&self.start_bound, 0)
    }

    fn end_bin_inclusive(&self) -> usize {
        // end in bin where 'end_bound' would exist
        self.bin_from_bound(&self.end_bound, usize::MAX)
    }

    fn bin_start_and_range(&self) -> (usize, usize) {
        let start_bin = self.start_bin();
        // calculate the max range of bins to look in
        let end_bin_inclusive = self.end_bin_inclusive();
        let bin_range = if start_bin > end_bin_inclusive {
            0 // empty range
        } else if end_bin_inclusive == usize::MAX {
            usize::MAX
        } else {
            // the range is end_inclusive + 1 - start
            // end_inclusive could be usize::MAX already if no bound was specified
            end_bin_inclusive.saturating_add(1) - start_bin
        };
        (start_bin, bin_range)
    }

    pub fn new<R>(
        index: &'a AccountsIndex<T, U>,
        range: Option<&R>,
        collect_all_unsorted: bool,
    ) -> Self
    where
        R: RangeBounds<Pubkey>,
    {
        Self {
            start_bound: range
                .as_ref()
                .map(|r| Self::clone_bound(r.start_bound()))
                .unwrap_or(Unbounded),
            end_bound: range
                .as_ref()
                .map(|r| Self::clone_bound(r.end_bound()))
                .unwrap_or(Unbounded),
            account_maps: &index.account_maps,
            is_finished: false,
            bin_calculator: &index.bin_calculator,
            collect_all_unsorted,
        }
    }

    pub fn hold_range_in_memory<R>(&self, range: &R, start_holding: bool, thread_pool: &ThreadPool)
    where
        R: RangeBounds<Pubkey> + Debug + Sync,
    {
        // forward this hold request ONLY to the bins which contain keys in the specified range
        let (start_bin, bin_range) = self.bin_start_and_range();
        // the idea is this range shouldn't be more than a few buckets, but the process of loading from disk buckets is very slow
        // so, parallelize the bucket loads
        thread_pool.install(|| {
            (0..bin_range).into_par_iter().for_each(|idx| {
                let map = &self.account_maps[idx + start_bin];
                map.hold_range_in_memory(range, start_holding);
            });
        });
    }
}

impl<'a, T: IndexValue, U: DiskIndexValue + From<T> + Into<T>> Iterator
    for AccountsIndexIterator<'a, T, U>
{
    type Item = Vec<(Pubkey, AccountMapEntry<T>)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_finished {
            return None;
        }
        let (start_bin, bin_range) = self.bin_start_and_range();
        let mut chunk = Vec::with_capacity(ITER_BATCH_SIZE);
        'outer: for i in self.account_maps.iter().skip(start_bin).take(bin_range) {
            for (pubkey, account_map_entry) in Self::range(
                &i,
                (self.start_bound, self.end_bound),
                self.collect_all_unsorted,
            ) {
                if chunk.len() >= ITER_BATCH_SIZE && !self.collect_all_unsorted {
                    break 'outer;
                }
                let item = (pubkey, account_map_entry);
                chunk.push(item);
            }
        }

        if chunk.is_empty() {
            self.is_finished = true;
            return None;
        } else if self.collect_all_unsorted {
            self.is_finished = true;
        }

        self.start_bound = Excluded(chunk.last().unwrap().0);
        Some(chunk)
    }
}

pub trait ZeroLamport {
    fn is_zero_lamport(&self) -> bool;
}

type MapType<T, U> = AccountMap<T, U>;
type LockMapType<T, U> = Vec<MapType<T, U>>;
type LockMapTypeSlice<T, U> = [MapType<T, U>];
type AccountMaps<'a, T, U> = &'a MapType<T, U>;

#[derive(Debug, Default)]
pub struct ScanSlotTracker {
    is_removed: bool,
}

impl ScanSlotTracker {
    pub fn is_removed(&self) -> bool {
        self.is_removed
    }

    pub fn mark_removed(&mut self) {
        self.is_removed = true;
    }
}

#[derive(Copy, Clone)]
pub enum AccountsIndexScanResult {
    /// if the entry is not in the in-memory index, do not add it unless the entry becomes dirty
    OnlyKeepInMemoryIfDirty,
    /// keep the entry in the in-memory index
    KeepInMemory,
    /// reduce refcount by 1
    Unref,
}

#[derive(Debug)]
/// T: account info type to interact in in-memory items
/// U: account info type to be persisted to disk
pub struct AccountsIndex<T: IndexValue, U: DiskIndexValue + From<T> + Into<T>> {
    pub account_maps: LockMapType<T, U>,
    pub bin_calculator: PubkeyBinCalculator24,
    program_id_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    spl_token_mint_index: SecondaryIndex<DashMapSecondaryIndexEntry>,
    spl_token_owner_index: SecondaryIndex<RwLockSecondaryIndexEntry>,
    pub roots_tracker: RwLock<RootsTracker>,
    ongoing_scan_roots: RwLock<BTreeMap<Slot, u64>>,
    // Each scan has some latest slot `S` that is the tip of the fork the scan
    // is iterating over. The unique id of that slot `S` is recorded here (note we don't use
    // `S` as the id because there can be more than one version of a slot `S`). If a fork
    // is abandoned, all of the slots on that fork up to `S` will be removed via
    // `AccountsDb::remove_unrooted_slots()`. When the scan finishes, it'll realize that the
    // results of the scan may have been corrupted by `remove_unrooted_slots` and abort its results.
    //
    // `removed_bank_ids` tracks all the slot ids that were removed via `remove_unrooted_slots()` so any attempted scans
    // on any of these slots fails. This is safe to purge once the associated Bank is dropped and
    // scanning the fork with that Bank at the tip is no longer possible.
    pub removed_bank_ids: Mutex<HashSet<BankId>>,

    storage: AccountsIndexStorage<T, U>,

    /// when a scan's accumulated data exceeds this limit, abort the scan
    pub scan_results_limit_bytes: Option<usize>,

    /// # roots added since last check
    pub roots_added: AtomicUsize,
    /// # roots removed since last check
    pub roots_removed: AtomicUsize,
    /// # scans active currently
    pub active_scans: AtomicUsize,
    /// # of slots between latest max and latest scan
    pub max_distance_to_min_scan_slot: AtomicU64,

    /// populated at generate_index time - accounts that could possibly be rent paying
    pub rent_paying_accounts_by_partition: OnceLock<RentPayingAccountsByPartition>,
}

impl<T: IndexValue, U: DiskIndexValue + From<T> + Into<T>> AccountsIndex<T, U> {
    pub fn default_for_tests() -> Self {
        Self::new(Some(ACCOUNTS_INDEX_CONFIG_FOR_TESTING), Arc::default())
    }

    pub fn new(config: Option<AccountsIndexConfig>, exit: Arc<AtomicBool>) -> Self {
        let scan_results_limit_bytes = config
            .as_ref()
            .and_then(|config| config.scan_results_limit_bytes);
        let (account_maps, bin_calculator, storage) = Self::allocate_accounts_index(config, exit);
        Self {
            account_maps,
            bin_calculator,
            program_id_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new(
                "program_id_index_stats",
            ),
            spl_token_mint_index: SecondaryIndex::<DashMapSecondaryIndexEntry>::new(
                "spl_token_mint_index_stats",
            ),
            spl_token_owner_index: SecondaryIndex::<RwLockSecondaryIndexEntry>::new(
                "spl_token_owner_index_stats",
            ),
            roots_tracker: RwLock::<RootsTracker>::default(),
            ongoing_scan_roots: RwLock::<BTreeMap<Slot, u64>>::default(),
            removed_bank_ids: Mutex::<HashSet<BankId>>::default(),
            storage,
            scan_results_limit_bytes,
            roots_added: AtomicUsize::default(),
            roots_removed: AtomicUsize::default(),
            active_scans: AtomicUsize::default(),
            max_distance_to_min_scan_slot: AtomicU64::default(),
            rent_paying_accounts_by_partition: OnceLock::default(),
        }
    }

    fn allocate_accounts_index(
        config: Option<AccountsIndexConfig>,
        exit: Arc<AtomicBool>,
    ) -> (
        LockMapType<T, U>,
        PubkeyBinCalculator24,
        AccountsIndexStorage<T, U>,
    ) {
        let bins = config
            .as_ref()
            .and_then(|config| config.bins)
            .unwrap_or(BINS_DEFAULT);
        // create bin_calculator early to verify # bins is reasonable
        let bin_calculator = PubkeyBinCalculator24::new(bins);
        let storage = AccountsIndexStorage::new(bins, &config, exit);
        let account_maps = (0..bins)
            .map(|bin| Arc::clone(&storage.in_mem[bin]))
            .collect::<Vec<_>>();
        (account_maps, bin_calculator, storage)
    }

    fn iter<R>(&self, range: Option<&R>, collect_all_unsorted: bool) -> AccountsIndexIterator<T, U>
    where
        R: RangeBounds<Pubkey>,
    {
        AccountsIndexIterator::new(self, range, collect_all_unsorted)
    }

    /// is the accounts index using disk as a backing store
    pub fn is_disk_index_enabled(&self) -> bool {
        self.storage.storage.is_disk_index_enabled()
    }

    fn min_ongoing_scan_root_from_btree(ongoing_scan_roots: &BTreeMap<Slot, u64>) -> Option<Slot> {
        ongoing_scan_roots.keys().next().cloned()
    }

    fn do_checked_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        func: F,
        scan_type: ScanTypes<R>,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        {
            let locked_removed_bank_ids = self.removed_bank_ids.lock().unwrap();
            if locked_removed_bank_ids.contains(&scan_bank_id) {
                return Err(ScanError::SlotRemoved {
                    slot: ancestors.max_slot(),
                    bank_id: scan_bank_id,
                });
            }
        }

        self.active_scans.fetch_add(1, Ordering::Relaxed);
        let max_root = {
            let mut w_ongoing_scan_roots = self
                // This lock is also grabbed by clean_accounts(), so clean
                // has at most cleaned up to the current `max_root` (since
                // clean only happens *after* BankForks::set_root() which sets
                // the `max_root`)
                .ongoing_scan_roots
                .write()
                .unwrap();
            // `max_root()` grabs a lock while
            // the `ongoing_scan_roots` lock is held,
            // make sure inverse doesn't happen to avoid
            // deadlock
            let max_root_inclusive = self.max_root_inclusive();
            if let Some(min_ongoing_scan_root) =
                Self::min_ongoing_scan_root_from_btree(&w_ongoing_scan_roots)
            {
                if min_ongoing_scan_root < max_root_inclusive {
                    let current = max_root_inclusive - min_ongoing_scan_root;
                    self.max_distance_to_min_scan_slot
                        .fetch_max(current, Ordering::Relaxed);
                }
            }
            *w_ongoing_scan_roots.entry(max_root_inclusive).or_default() += 1;

            max_root_inclusive
        };

        // First we show that for any bank `B` that is a descendant of
        // the current `max_root`, it must be true that and `B.ancestors.contains(max_root)`,
        // regardless of the pattern of `squash()` behavior, where `ancestors` is the set
        // of ancestors that is tracked in each bank.
        //
        // Proof: At startup, if starting from a snapshot, generate_index() adds all banks
        // in the snapshot to the index via `add_root()` and so `max_root` will be the
        // greatest of these. Thus, so the claim holds at startup since there are no
        // descendants of `max_root`.
        //
        // Now we proceed by induction on each `BankForks::set_root()`.
        // Assume the claim holds when the `max_root` is `R`. Call the set of
        // descendants of `R` present in BankForks `R_descendants`.
        //
        // Then for any banks `B` in `R_descendants`, it must be that `B.ancestors.contains(S)`,
        // where `S` is any ancestor of `B` such that `S >= R`.
        //
        // For example:
        //          `R` -> `A` -> `C` -> `B`
        // Then `B.ancestors == {R, A, C}`
        //
        // Next we call `BankForks::set_root()` at some descendant of `R`, `R_new`,
        // where `R_new > R`.
        //
        // When we squash `R_new`, `max_root` in the AccountsIndex here is now set to `R_new`,
        // and all nondescendants of `R_new` are pruned.
        //
        // Now consider any outstanding references to banks in the system that are descended from
        // `max_root == R_new`. Take any one of these references and call it `B`. Because `B` is
        // a descendant of `R_new`, this means `B` was also a descendant of `R`. Thus `B`
        // must be a member of `R_descendants` because `B` was constructed and added to
        // BankForks before the `set_root`.
        //
        // This means by the guarantees of `R_descendants` described above, because
        // `R_new` is an ancestor of `B`, and `R < R_new < B`, then `B.ancestors.contains(R_new)`.
        //
        // Now until the next `set_root`, any new banks constructed from `new_from_parent` will
        // also have `max_root == R_new` in their ancestor set, so the claim holds for those descendants
        // as well. Once the next `set_root` happens, we once again update `max_root` and the same
        // inductive argument can be applied again to show the claim holds.

        // Check that the `max_root` is present in `ancestors`. From the proof above, if
        // `max_root` is not present in `ancestors`, this means the bank `B` with the
        // given `ancestors` is not descended from `max_root, which means
        // either:
        // 1) `B` is on a different fork or
        // 2) `B` is an ancestor of `max_root`.
        // In both cases we can ignore the given ancestors and instead just rely on the roots
        // present as `max_root` indicates the roots present in the index are more up to date
        // than the ancestors given.
        let empty = Ancestors::default();
        let ancestors = if ancestors.contains_key(&max_root) {
            ancestors
        } else {
            /*
            This takes of edge cases like:

            Diagram 1:

                        slot 0
                          |
                        slot 1
                      /        \
                 slot 2         |
                    |       slot 3 (max root)
            slot 4 (scan)

            By the time the scan on slot 4 is called, slot 2 may already have been
            cleaned by a clean on slot 3, but slot 4 may not have been cleaned.
            The state in slot 2 would have been purged and is not saved in any roots.
            In this case, a scan on slot 4 wouldn't accurately reflect the state when bank 4
            was frozen. In cases like this, we default to a scan on the latest roots by
            removing all `ancestors`.
            */
            &empty
        };

        /*
        Now there are two cases, either `ancestors` is empty or nonempty:

        1) If ancestors is empty, then this is the same as a scan on a rooted bank,
        and `ongoing_scan_roots` provides protection against cleanup of roots necessary
        for the scan, and  passing `Some(max_root)` to `do_scan_accounts()` ensures newer
        roots don't appear in the scan.

        2) If ancestors is non-empty, then from the `ancestors_contains(&max_root)` above, we know
        that the fork structure must look something like:

        Diagram 2:

                Build fork structure:
                        slot 0
                          |
                    slot 1 (max_root)
                    /            \
             slot 2              |
                |            slot 3 (potential newer max root)
              slot 4
                |
             slot 5 (scan)

        Consider both types of ancestors, ancestor <= `max_root` and
        ancestor > `max_root`, where `max_root == 1` as illustrated above.

        a) The set of `ancestors <= max_root` are all rooted, which means their state
        is protected by the same guarantees as 1).

        b) As for the `ancestors > max_root`, those banks have at least one reference discoverable
        through the chain of `Bank::BankRc::parent` starting from the calling bank. For instance
        bank 5's parent reference keeps bank 4 alive, which will prevent the `Bank::drop()` from
        running and cleaning up bank 4. Furthermore, no cleans can happen past the saved max_root == 1,
        so a potential newer max root at 3 will not clean up any of the ancestors > 1, so slot 4
        will not be cleaned in the middle of the scan either. (NOTE similar reasoning is employed for
        assert!() justification in AccountsDb::retry_to_get_account_accessor)
        */
        match scan_type {
            ScanTypes::Unindexed(range) => {
                // Pass "" not to log metrics, so RPC doesn't get spammy
                self.do_scan_accounts(metric_name, ancestors, func, range, Some(max_root), config);
            }
            ScanTypes::Indexed(IndexKey::ProgramId(program_id)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.program_id_index,
                    &program_id,
                    Some(max_root),
                    config,
                );
            }
            ScanTypes::Indexed(IndexKey::SplTokenMint(mint_key)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.spl_token_mint_index,
                    &mint_key,
                    Some(max_root),
                    config,
                );
            }
            ScanTypes::Indexed(IndexKey::SplTokenOwner(owner_key)) => {
                self.do_scan_secondary_index(
                    ancestors,
                    func,
                    &self.spl_token_owner_index,
                    &owner_key,
                    Some(max_root),
                    config,
                );
            }
        }

        {
            self.active_scans.fetch_sub(1, Ordering::Relaxed);
            let mut ongoing_scan_roots = self.ongoing_scan_roots.write().unwrap();
            let count = ongoing_scan_roots.get_mut(&max_root).unwrap();
            *count -= 1;
            if *count == 0 {
                ongoing_scan_roots.remove(&max_root);
            }
        }

        // If the fork with tip at bank `scan_bank_id` was removed during our scan, then the scan
        // may have been corrupted, so abort the results.
        let was_scan_corrupted = self
            .removed_bank_ids
            .lock()
            .unwrap()
            .contains(&scan_bank_id);

        if was_scan_corrupted {
            Err(ScanError::SlotRemoved {
                slot: ancestors.max_slot(),
                bank_id: scan_bank_id,
            })
        } else {
            Ok(())
        }
    }

    fn do_unchecked_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        func: F,
        range: Option<R>,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        self.do_scan_accounts(metric_name, ancestors, func, range, None, config);
    }

    // Scan accounts and return latest version of each account that is either:
    // 1) rooted or
    // 2) present in ancestors
    fn do_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        mut func: F,
        range: Option<R>,
        max_root: Option<Slot>,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        // TODO: expand to use mint index to find the `pubkey_list` below more efficiently
        // instead of scanning the entire range
        let mut total_elapsed_timer = Measure::start("total");
        let mut num_keys_iterated = 0;
        let mut latest_slot_elapsed = 0;
        let mut load_account_elapsed = 0;
        let mut read_lock_elapsed = 0;
        let mut iterator_elapsed = 0;
        let mut iterator_timer = Measure::start("iterator_elapsed");
        for pubkey_list in self.iter(range.as_ref(), config.collect_all_unsorted) {
            iterator_timer.stop();
            iterator_elapsed += iterator_timer.as_us();
            for (pubkey, list) in pubkey_list {
                num_keys_iterated += 1;
                let mut read_lock_timer = Measure::start("read_lock");
                let list_r = &list.slot_list.read().unwrap();
                read_lock_timer.stop();
                read_lock_elapsed += read_lock_timer.as_us();
                let mut latest_slot_timer = Measure::start("latest_slot");
                if let Some(index) = self.latest_slot(Some(ancestors), list_r, max_root) {
                    latest_slot_timer.stop();
                    latest_slot_elapsed += latest_slot_timer.as_us();
                    let mut load_account_timer = Measure::start("load_account");
                    func(&pubkey, (&list_r[index].1, list_r[index].0));
                    load_account_timer.stop();
                    load_account_elapsed += load_account_timer.as_us();
                }
                if config.is_aborted() {
                    return;
                }
            }
            iterator_timer = Measure::start("iterator_elapsed");
        }

        total_elapsed_timer.stop();
        if !metric_name.is_empty() {
            datapoint_info!(
                metric_name,
                ("total_elapsed", total_elapsed_timer.as_us(), i64),
                ("latest_slot_elapsed", latest_slot_elapsed, i64),
                ("read_lock_elapsed", read_lock_elapsed, i64),
                ("load_account_elapsed", load_account_elapsed, i64),
                ("iterator_elapsed", iterator_elapsed, i64),
                ("num_keys_iterated", num_keys_iterated, i64),
            )
        }
    }

    fn do_scan_secondary_index<
        F,
        SecondaryIndexEntryType: SecondaryIndexEntry + Default + Sync + Send,
    >(
        &self,
        ancestors: &Ancestors,
        mut func: F,
        index: &SecondaryIndex<SecondaryIndexEntryType>,
        index_key: &Pubkey,
        max_root: Option<Slot>,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        for pubkey in index.get(index_key) {
            // Maybe these reads from the AccountsIndex can be batched every time it
            // grabs the read lock as well...
            if let AccountIndexGetResult::Found(list_r, index) =
                self.get(&pubkey, Some(ancestors), max_root)
            {
                let entry = &list_r.slot_list()[index];
                func(&pubkey, (&entry.1, entry.0));
            }
            if config.is_aborted() {
                break;
            }
        }
    }

    pub fn get_account_read_entry(&self, pubkey: &Pubkey) -> Option<ReadAccountMapEntry<T>> {
        let lock = self.get_bin(pubkey);
        self.get_account_read_entry_with_lock(pubkey, &lock)
    }

    pub fn get_account_read_entry_with_lock(
        &self,
        pubkey: &Pubkey,
        lock: &AccountMaps<'_, T, U>,
    ) -> Option<ReadAccountMapEntry<T>> {
        lock.get(pubkey)
            .map(ReadAccountMapEntry::from_account_map_entry)
    }

    fn slot_list_mut<RT>(
        &self,
        pubkey: &Pubkey,
        user: impl for<'a> FnOnce(&mut RwLockWriteGuard<'a, SlotList<T>>) -> RT,
    ) -> Option<RT> {
        let read_lock = self.get_bin(pubkey);
        read_lock.slot_list_mut(pubkey, user)
    }

    /// Remove keys from the account index if the key's slot list is empty.
    /// Returns the keys that were removed from the index. These keys should not be accessed again in the current code path.
    #[must_use]
    pub fn handle_dead_keys(
        &self,
        dead_keys: &[&Pubkey],
        account_indexes: &AccountSecondaryIndexes,
    ) -> HashSet<Pubkey> {
        let mut pubkeys_removed_from_accounts_index = HashSet::default();
        if !dead_keys.is_empty() {
            for key in dead_keys.iter() {
                let w_index = self.get_bin(key);
                if w_index.remove_if_slot_list_empty(**key) {
                    pubkeys_removed_from_accounts_index.insert(**key);
                    // Note it's only safe to remove all the entries for this key
                    // because we have the lock for this key's entry in the AccountsIndex,
                    // so no other thread is also updating the index
                    self.purge_secondary_indexes_by_inner_key(key, account_indexes);
                }
            }
        }
        pubkeys_removed_from_accounts_index
    }

    /// call func with every pubkey and index visible from a given set of ancestors
    pub(crate) fn scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        func: F,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        // Pass "" not to log metrics, so RPC doesn't get spammy
        self.do_checked_scan_accounts(
            "",
            ancestors,
            scan_bank_id,
            func,
            ScanTypes::Unindexed(None::<Range<Pubkey>>),
            config,
        )
    }

    pub(crate) fn unchecked_scan_accounts<F>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        func: F,
        config: &ScanConfig,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        self.do_unchecked_scan_accounts(
            metric_name,
            ancestors,
            func,
            None::<Range<Pubkey>>,
            config,
        );
    }

    /// call func with every pubkey and index visible from a given set of ancestors with range
    /// Only guaranteed to be safe when called from rent collection
    pub(crate) fn range_scan_accounts<F, R>(
        &self,
        metric_name: &'static str,
        ancestors: &Ancestors,
        range: R,
        config: &ScanConfig,
        func: F,
    ) where
        F: FnMut(&Pubkey, (&T, Slot)),
        R: RangeBounds<Pubkey> + std::fmt::Debug,
    {
        // Only the rent logic should be calling this, which doesn't need the safety checks
        self.do_unchecked_scan_accounts(metric_name, ancestors, func, Some(range), config);
    }

    /// call func with every pubkey and index visible from a given set of ancestors
    pub(crate) fn index_scan_accounts<F>(
        &self,
        ancestors: &Ancestors,
        scan_bank_id: BankId,
        index_key: IndexKey,
        func: F,
        config: &ScanConfig,
    ) -> Result<(), ScanError>
    where
        F: FnMut(&Pubkey, (&T, Slot)),
    {
        // Pass "" not to log metrics, so RPC doesn't get spammy
        self.do_checked_scan_accounts(
            "",
            ancestors,
            scan_bank_id,
            func,
            ScanTypes::<Range<Pubkey>>::Indexed(index_key),
            config,
        )
    }

    pub fn get_rooted_entries(
        &self,
        slice: SlotSlice<T>,
        max_inclusive: Option<Slot>,
    ) -> SlotList<T> {
        let max_inclusive = max_inclusive.unwrap_or(Slot::MAX);
        let lock = &self.roots_tracker.read().unwrap().alive_roots;
        slice
            .iter()
            .filter(|(slot, _)| *slot <= max_inclusive && lock.contains(slot))
            .cloned()
            .collect()
    }

    /// returns true if, after this fn call:
    /// accounts index entry for `pubkey` has an empty slot list
    /// or `pubkey` does not exist in accounts index
    pub(crate) fn purge_exact<'a, C>(
        &'a self,
        pubkey: &Pubkey,
        slots_to_purge: &'a C,
        reclaims: &mut SlotList<T>,
    ) -> bool
    where
        C: Contains<'a, Slot>,
    {
        self.slot_list_mut(pubkey, |slot_list| {
            slot_list.retain(|(slot, item)| {
                let should_purge = slots_to_purge.contains(slot);
                if should_purge {
                    reclaims.push((*slot, *item));
                    false
                } else {
                    true
                }
            });
            slot_list.is_empty()
        })
        .unwrap_or(true)
    }

    pub fn min_ongoing_scan_root(&self) -> Option<Slot> {
        Self::min_ongoing_scan_root_from_btree(&self.ongoing_scan_roots.read().unwrap())
    }

    // Given a SlotSlice `L`, a list of ancestors and a maximum slot, find the latest element
    // in `L`, where the slot `S` is an ancestor or root, and if `S` is a root, then `S <= max_root`
    pub(crate) fn latest_slot(
        &self,
        ancestors: Option<&Ancestors>,
        slice: SlotSlice<T>,
        max_root_inclusive: Option<Slot>,
    ) -> Option<usize> {
        let mut current_max = 0;
        let mut rv = None;
        if let Some(ancestors) = ancestors {
            if !ancestors.is_empty() {
                for (i, (slot, _t)) in slice.iter().rev().enumerate() {
                    if (rv.is_none() || *slot > current_max) && ancestors.contains_key(slot) {
                        rv = Some(i);
                        current_max = *slot;
                    }
                }
            }
        }

        let max_root_inclusive = max_root_inclusive.unwrap_or(Slot::MAX);
        let mut tracker = None;

        for (i, (slot, _t)) in slice.iter().rev().enumerate() {
            if (rv.is_none() || *slot > current_max) && *slot <= max_root_inclusive {
                let lock = match tracker {
                    Some(inner) => inner,
                    None => self.roots_tracker.read().unwrap(),
                };
                if lock.alive_roots.contains(slot) {
                    rv = Some(i);
                    current_max = *slot;
                }
                tracker = Some(lock);
            }
        }

        rv.map(|index| slice.len() - 1 - index)
    }

    pub fn hold_range_in_memory<R>(&self, range: &R, start_holding: bool, thread_pool: &ThreadPool)
    where
        R: RangeBounds<Pubkey> + Debug + Sync,
    {
        let iter = self.iter(Some(range), true);
        iter.hold_range_in_memory(range, start_holding, thread_pool);
    }

    /// get stats related to startup
    pub(crate) fn get_startup_stats(&self) -> &StartupStats {
        &self.storage.storage.startup_stats
    }

    pub fn set_startup(&self, value: Startup) {
        self.storage.set_startup(value);
    }

    pub fn get_startup_remaining_items_to_flush_estimate(&self) -> usize {
        self.storage.get_startup_remaining_items_to_flush_estimate()
    }

    /// For each pubkey, find the slot list in the accounts index
    ///   apply 'avoid_callback_result' if specified.
    ///   otherwise, call `callback`
    /// if 'provide_entry_in_callback' is true, populate callback with the Arc of the entry itself.
    pub(crate) fn scan<'a, F, I>(
        &self,
        pubkeys: I,
        mut callback: F,
        avoid_callback_result: Option<AccountsIndexScanResult>,
        provide_entry_in_callback: bool,
    ) where
        // params:
        //  pubkey looked up
        //  slots_refs is Option<(slot_list, ref_count)>
        //    None if 'pubkey' is not in accounts index.
        //   slot_list: comes from accounts index for 'pubkey'
        //   ref_count: refcount of entry in index
        //   entry, if 'provide_entry_in_callback' is true
        // if 'avoid_callback_result' is Some(_), then callback is NOT called
        //  and _ is returned as if callback were called.
        F: FnMut(
            &'a Pubkey,
            Option<(&SlotList<T>, RefCount)>,
            Option<&AccountMapEntry<T>>,
        ) -> AccountsIndexScanResult,
        I: Iterator<Item = &'a Pubkey>,
    {
        let mut lock = None;
        let mut last_bin = self.bins(); // too big, won't match
        pubkeys.into_iter().for_each(|pubkey| {
            let bin = self.bin_calculator.bin_from_pubkey(pubkey);
            if bin != last_bin {
                // cannot re-use lock since next pubkey is in a different bin than previous one
                lock = Some(&self.account_maps[bin]);
                last_bin = bin;
            }
            lock.as_ref().unwrap().get_internal(pubkey, |entry| {
                let mut cache = false;
                match entry {
                    Some(locked_entry) => {
                        let result = if let Some(result) = avoid_callback_result.as_ref() {
                            *result
                        } else {
                            let slot_list = &locked_entry.slot_list.read().unwrap();
                            callback(
                                pubkey,
                                Some((slot_list, locked_entry.ref_count())),
                                provide_entry_in_callback.then_some(locked_entry),
                            )
                        };
                        cache = match result {
                            AccountsIndexScanResult::Unref => {
                                if locked_entry.unref() {
                                    info!("scan: refcount of item already at 0: {pubkey}");
                                }
                                true
                            }
                            AccountsIndexScanResult::KeepInMemory => true,
                            AccountsIndexScanResult::OnlyKeepInMemoryIfDirty => false,
                        };
                    }
                    None => {
                        avoid_callback_result.unwrap_or_else(|| callback(pubkey, None, None));
                    }
                }
                (cache, ())
            });
        });
    }

    /// Get an account
    /// The latest account that appears in `ancestors` or `roots` is returned.
    pub fn get(
        &self,
        pubkey: &Pubkey,
        ancestors: Option<&Ancestors>,
        max_root: Option<Slot>,
    ) -> AccountIndexGetResult<T> {
        let read_lock = self.get_bin(pubkey);
        let account = read_lock
            .get(pubkey)
            .map(ReadAccountMapEntry::from_account_map_entry);

        match account {
            Some(locked_entry) => {
                let slot_list = locked_entry.slot_list();
                let found_index = self.latest_slot(ancestors, slot_list, max_root);
                match found_index {
                    Some(found_index) => AccountIndexGetResult::Found(locked_entry, found_index),
                    None => AccountIndexGetResult::NotFound,
                }
            }
            None => AccountIndexGetResult::NotFound,
        }
    }

    // Get the maximum root <= `max_allowed_root` from the given `slice`
    fn get_newest_root_in_slot_list(
        alive_roots: &RollingBitField,
        slice: SlotSlice<T>,
        max_allowed_root_inclusive: Option<Slot>,
    ) -> Slot {
        let mut max_root = 0;
        for (slot, _) in slice.iter() {
            if let Some(max_allowed_root_inclusive) = max_allowed_root_inclusive {
                if *slot > max_allowed_root_inclusive {
                    continue;
                }
            }
            if *slot > max_root && alive_roots.contains(slot) {
                max_root = *slot;
            }
        }
        max_root
    }

    fn update_spl_token_secondary_indexes<G: GenericTokenAccount>(
        &self,
        token_id: &Pubkey,
        pubkey: &Pubkey,
        account_owner: &Pubkey,
        account_data: &[u8],
        account_indexes: &AccountSecondaryIndexes,
    ) {
        if *account_owner == *token_id {
            if account_indexes.contains(&AccountIndex::SplTokenOwner) {
                if let Some(owner_key) = G::unpack_account_owner(account_data) {
                    if account_indexes.include_key(owner_key) {
                        self.spl_token_owner_index.insert(owner_key, pubkey);
                    }
                }
            }

            if account_indexes.contains(&AccountIndex::SplTokenMint) {
                if let Some(mint_key) = G::unpack_account_mint(account_data) {
                    if account_indexes.include_key(mint_key) {
                        self.spl_token_mint_index.insert(mint_key, pubkey);
                    }
                }
            }
        }
    }

    pub fn get_index_key_size(&self, index: &AccountIndex, index_key: &Pubkey) -> Option<usize> {
        match index {
            AccountIndex::ProgramId => self.program_id_index.index.get(index_key).map(|x| x.len()),
            AccountIndex::SplTokenOwner => self
                .spl_token_owner_index
                .index
                .get(index_key)
                .map(|x| x.len()),
            AccountIndex::SplTokenMint => self
                .spl_token_mint_index
                .index
                .get(index_key)
                .map(|x| x.len()),
        }
    }

    /// log any secondary index counts, if non-zero
    pub(crate) fn log_secondary_indexes(&self) {
        if !self.program_id_index.index.is_empty() {
            info!("secondary index: {:?}", AccountIndex::ProgramId);
            self.program_id_index.log_contents();
        }
        if !self.spl_token_mint_index.index.is_empty() {
            info!("secondary index: {:?}", AccountIndex::SplTokenMint);
            self.spl_token_mint_index.log_contents();
        }
        if !self.spl_token_owner_index.index.is_empty() {
            info!("secondary index: {:?}", AccountIndex::SplTokenOwner);
            self.spl_token_owner_index.log_contents();
        }
    }

    pub(crate) fn update_secondary_indexes(
        &self,
        pubkey: &Pubkey,
        account: &impl ReadableAccount,
        account_indexes: &AccountSecondaryIndexes,
    ) {
        if account_indexes.is_empty() {
            return;
        }

        let account_owner = account.owner();
        let account_data = account.data();

        if account_indexes.contains(&AccountIndex::ProgramId)
            && account_indexes.include_key(account_owner)
        {
            self.program_id_index.insert(account_owner, pubkey);
        }
        // Note because of the below check below on the account data length, when an
        // account hits zero lamports and is reset to AccountSharedData::Default, then we skip
        // the below updates to the secondary indexes.
        //
        // Skipping means not updating secondary index to mark the account as missing.
        // This doesn't introduce false positives during a scan because the caller to scan
        // provides the ancestors to check. So even if a zero-lamport account is not yet
        // removed from the secondary index, the scan function will:
        // 1) consult the primary index via `get(&pubkey, Some(ancestors), max_root)`
        // and find the zero-lamport version
        // 2) When the fetch from storage occurs, it will return AccountSharedData::Default
        // (as persisted tombstone for snapshots). This will then ultimately be
        // filtered out by post-scan filters, like in `get_filtered_spl_token_accounts_by_owner()`.

        self.update_spl_token_secondary_indexes::<inline_spl_token::Account>(
            &inline_spl_token::id(),
            pubkey,
            account_owner,
            account_data,
            account_indexes,
        );
        self.update_spl_token_secondary_indexes::<inline_spl_token_2022::Account>(
            &inline_spl_token_2022::id(),
            pubkey,
            account_owner,
            account_data,
            account_indexes,
        );
    }

    pub(crate) fn get_bin(&self, pubkey: &Pubkey) -> AccountMaps<T, U> {
        &self.account_maps[self.bin_calculator.bin_from_pubkey(pubkey)]
    }

    pub fn bins(&self) -> usize {
        self.account_maps.len()
    }

    /// remove the earlier instances of each pubkey when the pubkey exists later in the `Vec`.
    /// Could also be done with HashSet.
    /// Returns `HashSet` of duplicate pubkeys.
    fn remove_older_duplicate_pubkeys(
        items: &mut Vec<(Pubkey, (Slot, T))>,
    ) -> Option<Vec<(Pubkey, (Slot, T))>> {
        if items.len() < 2 {
            return None;
        }
        // stable sort by pubkey.
        // Earlier entries are overwritten by later entries
        items.sort_by(|a, b| a.0.cmp(&b.0));
        let mut duplicates = None::<Vec<(Pubkey, (Slot, T))>>;

        // Iterate the items vec from the end to the beginning. Adjacent duplicated items will be
        // written to the front of the vec.
        let n = items.len();
        let mut last_key = items[n - 1].0;
        let mut write = n - 1;
        let mut curr = write;

        while curr > 0 {
            let curr_item = items[curr - 1];

            if curr_item.0 == last_key {
                let mut duplicates_insert = duplicates.unwrap_or_default();
                duplicates_insert.push(curr_item);
                duplicates = Some(duplicates_insert);
                curr -= 1;
            } else {
                if curr < write {
                    items[write - 1] = curr_item;
                }
                curr -= 1;
                write -= 1;
                last_key = curr_item.0;
            }
        }

        items.drain(..(write - curr));

        duplicates
    }

    // Same functionally to upsert, but:
    // 1. operates on a batch of items
    // 2. holds the write lock for the duration of adding the items
    // Can save time when inserting lots of new keys.
    // But, does NOT update secondary index
    // This is designed to be called at startup time.
    // returns (dirty_pubkeys, insertion_time_us, GenerateIndexResult)
    #[allow(clippy::needless_collect)]
    pub(crate) fn insert_new_if_missing_into_primary_index(
        &self,
        slot: Slot,
        approx_items_len: usize,
        items: impl Iterator<Item = (Pubkey, T)>,
    ) -> (Vec<Pubkey>, u64, GenerateIndexResult<T>) {
        // big enough so not likely to re-allocate, small enough to not over-allocate by too much
        // this assumes the largest bin contains twice the expected amount of the average size per bin
        let bins = self.bins();
        let expected_items_per_bin = approx_items_len * 2 / bins;
        let use_disk = self.storage.storage.disk.is_some();
        let mut binned = (0..bins)
            .map(|_| Vec::with_capacity(expected_items_per_bin))
            .collect::<Vec<_>>();
        let mut count = 0;
        let mut dirty_pubkeys = items
            .filter_map(|(pubkey, account_info)| {
                let pubkey_bin = self.bin_calculator.bin_from_pubkey(&pubkey);
                // this value is equivalent to what update() below would have created if we inserted a new item
                let is_zero_lamport = account_info.is_zero_lamport();
                let result = if is_zero_lamport { Some(pubkey) } else { None };

                binned[pubkey_bin].push((pubkey, (slot, account_info)));
                result
            })
            .collect::<Vec<_>>();

        let insertion_time = AtomicU64::new(0);

        // offset bin processing in the 'binned' array by a random amount.
        // This results in calls to insert_new_entry_if_missing_with_lock from different threads starting at different bins to avoid
        // lock contention.
        let random_offset = thread_rng().gen_range(0..bins);
        let mut duplicates = Vec::default();
        (0..bins).for_each(|pubkey_bin| {
            let pubkey_bin = (pubkey_bin + random_offset) % bins;
            let mut items = std::mem::take(&mut binned[pubkey_bin]);
            if items.is_empty() {
                return;
            }

            let these_duplicates = Self::remove_older_duplicate_pubkeys(&mut items);
            if let Some(mut these_duplicates) = these_duplicates {
                duplicates.append(&mut these_duplicates);
            }

            let r_account_maps = &self.account_maps[pubkey_bin];
            let mut insert_time = Measure::start("insert_into_primary_index");
            // count only considers non-duplicate accounts
            count += items.len();
            if use_disk {
                r_account_maps.startup_insert_only(items.into_iter());
            } else {
                // not using disk buckets, so just write to in-mem
                // this is no longer the default case
                items
                    .into_iter()
                    .for_each(|(pubkey, (slot, account_info))| {
                        let new_entry = PreAllocatedAccountMapEntry::new(
                            slot,
                            account_info,
                            &self.storage.storage,
                            use_disk,
                        );
                        match r_account_maps
                            .insert_new_entry_if_missing_with_lock(pubkey, new_entry)
                        {
                            InsertNewEntryResults::DidNotExist => {}
                            InsertNewEntryResults::ExistedNewEntryZeroLamports => {}
                            InsertNewEntryResults::ExistedNewEntryNonZeroLamports => {
                                dirty_pubkeys.push(pubkey);
                            }
                        }
                    });
            }
            insert_time.stop();
            insertion_time.fetch_add(insert_time.as_us(), Ordering::Relaxed);
        });

        (
            dirty_pubkeys,
            insertion_time.load(Ordering::Relaxed),
            GenerateIndexResult {
                count,
                duplicates: (!duplicates.is_empty()).then_some(duplicates),
            },
        )
    }

    /// use Vec<> because the internal vecs are already allocated per bin
    pub(crate) fn populate_and_retrieve_duplicate_keys_from_startup(
        &self,
        f: impl Fn(Vec<(Slot, Pubkey)>) + Sync + Send,
    ) {
        (0..self.bins())
            .into_par_iter()
            .map(|pubkey_bin| {
                let r_account_maps = &self.account_maps[pubkey_bin];
                r_account_maps.populate_and_retrieve_duplicate_keys_from_startup()
            })
            .for_each(f);
    }

    /// Updates the given pubkey at the given slot with the new account information.
    /// on return, the index's previous account info may be returned in 'reclaims' depending on 'previous_slot_entry_was_cached'
    pub fn upsert(
        &self,
        new_slot: Slot,
        old_slot: Slot,
        pubkey: &Pubkey,
        account: &impl ReadableAccount,
        account_indexes: &AccountSecondaryIndexes,
        account_info: T,
        reclaims: &mut SlotList<T>,
        reclaim: UpsertReclaim,
    ) {
        // vast majority of updates are to item already in accounts index, so store as raw to avoid unnecessary allocations
        let store_raw = true;

        // We don't atomically update both primary index and secondary index together.
        // This certainly creates a small time window with inconsistent state across the two indexes.
        // However, this is acceptable because:
        //
        //  - A strict consistent view at any given moment of time is not necessary, because the only
        //  use case for the secondary index is `scan`, and `scans` are only supported/require consistency
        //  on frozen banks, and this inconsistency is only possible on working banks.
        //
        //  - The secondary index is never consulted as primary source of truth for gets/stores.
        //  So, what the accounts_index sees alone is sufficient as a source of truth for other non-scan
        //  account operations.
        let new_item = PreAllocatedAccountMapEntry::new(
            new_slot,
            account_info,
            &self.storage.storage,
            store_raw,
        );
        let map = self.get_bin(pubkey);

        map.upsert(pubkey, new_item, Some(old_slot), reclaims, reclaim);
        self.update_secondary_indexes(pubkey, account, account_indexes);
    }

    pub fn ref_count_from_storage(&self, pubkey: &Pubkey) -> RefCount {
        let map = self.get_bin(pubkey);
        map.get_internal(pubkey, |entry| {
            (
                false,
                entry.map(|entry| entry.ref_count()).unwrap_or_default(),
            )
        })
    }

    fn purge_secondary_indexes_by_inner_key(
        &self,
        inner_key: &Pubkey,
        account_indexes: &AccountSecondaryIndexes,
    ) {
        if account_indexes.contains(&AccountIndex::ProgramId) {
            self.program_id_index.remove_by_inner_key(inner_key);
        }

        if account_indexes.contains(&AccountIndex::SplTokenOwner) {
            self.spl_token_owner_index.remove_by_inner_key(inner_key);
        }

        if account_indexes.contains(&AccountIndex::SplTokenMint) {
            self.spl_token_mint_index.remove_by_inner_key(inner_key);
        }
    }

    fn purge_older_root_entries(
        &self,
        slot_list: &mut SlotList<T>,
        reclaims: &mut SlotList<T>,
        max_clean_root_inclusive: Option<Slot>,
    ) {
        let newest_root_in_slot_list;
        let max_clean_root_inclusive = {
            let roots_tracker = &self.roots_tracker.read().unwrap();
            newest_root_in_slot_list = Self::get_newest_root_in_slot_list(
                &roots_tracker.alive_roots,
                slot_list,
                max_clean_root_inclusive,
            );
            max_clean_root_inclusive.unwrap_or_else(|| roots_tracker.alive_roots.max_inclusive())
        };

        slot_list.retain(|(slot, value)| {
            let should_purge = Self::can_purge_older_entries(
                // Note that we have a root that is inclusive here.
                // Calling a function that expects 'exclusive'
                // This is expected behavior for this call.
                max_clean_root_inclusive,
                newest_root_in_slot_list,
                *slot,
            ) && !value.is_cached();
            if should_purge {
                reclaims.push((*slot, *value));
            }
            !should_purge
        });
    }

    /// return true if pubkey was removed from the accounts index
    ///  or does not exist in the accounts index
    /// This means it should NOT be unref'd later.
    #[must_use]
    pub fn clean_rooted_entries(
        &self,
        pubkey: &Pubkey,
        reclaims: &mut SlotList<T>,
        max_clean_root_inclusive: Option<Slot>,
    ) -> bool {
        let mut is_slot_list_empty = false;
        let missing_in_accounts_index = self
            .slot_list_mut(pubkey, |slot_list| {
                self.purge_older_root_entries(slot_list, reclaims, max_clean_root_inclusive);
                is_slot_list_empty = slot_list.is_empty();
            })
            .is_none();

        let mut removed = false;
        // If the slot list is empty, remove the pubkey from `account_maps`. Make sure to grab the
        // lock and double check the slot list is still empty, because another writer could have
        // locked and inserted the pubkey in-between when `is_slot_list_empty=true` and the call to
        // remove() below.
        if is_slot_list_empty {
            let w_maps = self.get_bin(pubkey);
            removed = w_maps.remove_if_slot_list_empty(*pubkey);
        }
        removed || missing_in_accounts_index
    }

    /// When can an entry be purged?
    ///
    /// If we get a slot update where slot != newest_root_in_slot_list for an account where slot <
    /// max_clean_root_exclusive, then we know it's safe to delete because:
    ///
    /// a) If slot < newest_root_in_slot_list, then we know the update is outdated by a later rooted
    /// update, namely the one in newest_root_in_slot_list
    ///
    /// b) If slot > newest_root_in_slot_list, then because slot < max_clean_root_exclusive and we know there are
    /// no roots in the slot list between newest_root_in_slot_list and max_clean_root_exclusive, (otherwise there
    /// would be a bigger newest_root_in_slot_list, which is a contradiction), then we know slot must be
    /// an unrooted slot less than max_clean_root_exclusive and thus safe to clean as well.
    fn can_purge_older_entries(
        max_clean_root_exclusive: Slot,
        newest_root_in_slot_list: Slot,
        slot: Slot,
    ) -> bool {
        slot < max_clean_root_exclusive && slot != newest_root_in_slot_list
    }

    /// Given a list of slots, return a new list of only the slots that are rooted
    pub fn get_rooted_from_list<'a>(&self, slots: impl Iterator<Item = &'a Slot>) -> Vec<Slot> {
        let roots_tracker = self.roots_tracker.read().unwrap();
        slots
            .filter_map(|s| {
                if roots_tracker.alive_roots.contains(s) {
                    Some(*s)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_alive_root(&self, slot: Slot) -> bool {
        self.roots_tracker
            .read()
            .unwrap()
            .alive_roots
            .contains(&slot)
    }

    pub fn add_root(&self, slot: Slot) {
        self.roots_added.fetch_add(1, Ordering::Relaxed);
        let mut w_roots_tracker = self.roots_tracker.write().unwrap();
        // `AccountsDb::flush_accounts_cache()` relies on roots being added in order
        assert!(slot >= w_roots_tracker.alive_roots.max_inclusive());
        // 'slot' is a root, so it is both 'root' and 'original'
        w_roots_tracker.alive_roots.insert(slot);
    }

    pub fn add_uncleaned_roots<I>(&self, roots: I)
    where
        I: IntoIterator<Item = Slot>,
    {
        let mut w_roots_tracker = self.roots_tracker.write().unwrap();
        w_roots_tracker.uncleaned_roots.extend(roots);
    }

    pub fn max_root_inclusive(&self) -> Slot {
        self.roots_tracker
            .read()
            .unwrap()
            .alive_roots
            .max_inclusive()
    }

    /// Remove the slot when the storage for the slot is freed
    /// Accounts no longer reference this slot.
    /// return true if slot was a root
    pub fn clean_dead_slot(&self, slot: Slot) -> bool {
        let mut w_roots_tracker = self.roots_tracker.write().unwrap();
        let removed_from_unclean_roots = w_roots_tracker.uncleaned_roots.remove(&slot);
        if !w_roots_tracker.alive_roots.remove(&slot) {
            if removed_from_unclean_roots {
                error!("clean_dead_slot-removed_from_unclean_roots: {}", slot);
                inc_new_counter_error!("clean_dead_slot-removed_from_unclean_roots", 1, 1);
            }
            false
        } else {
            drop(w_roots_tracker);
            self.roots_removed.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    pub(crate) fn update_roots_stats(&self, stats: &mut AccountsIndexRootsStats) {
        let roots_tracker = self.roots_tracker.read().unwrap();
        stats.roots_len = Some(roots_tracker.alive_roots.len());
        stats.uncleaned_roots_len = Some(roots_tracker.uncleaned_roots.len());
        stats.roots_range = Some(roots_tracker.alive_roots.range_width());
    }

    pub fn min_alive_root(&self) -> Option<Slot> {
        self.roots_tracker.read().unwrap().min_alive_root()
    }

    pub(crate) fn reset_uncleaned_roots(&self, max_clean_root: Option<Slot>) {
        let mut cleaned_roots = HashSet::new();
        let mut w_roots_tracker = self.roots_tracker.write().unwrap();
        w_roots_tracker.uncleaned_roots.retain(|root| {
            let is_cleaned = max_clean_root
                .map(|max_clean_root| *root <= max_clean_root)
                .unwrap_or(true);
            if is_cleaned {
                cleaned_roots.insert(*root);
            }
            // Only keep the slots that have yet to be cleaned
            !is_cleaned
        });
    }

    pub fn num_alive_roots(&self) -> usize {
        self.roots_tracker.read().unwrap().alive_roots.len()
    }

    pub fn all_alive_roots(&self) -> Vec<Slot> {
        let tracker = self.roots_tracker.read().unwrap();
        tracker.alive_roots.get_all()
    }

    pub fn clone_uncleaned_roots(&self) -> IntSet<Slot> {
        self.roots_tracker.read().unwrap().uncleaned_roots.clone()
    }

    pub fn uncleaned_roots_len(&self) -> usize {
        self.roots_tracker.read().unwrap().uncleaned_roots.len()
    }

    // These functions/fields are only usable from a dev context (i.e. tests and benches)
    #[cfg(feature = "dev-context-only-utils")]
    // filter any rooted entries and return them along with a bool that indicates
    // if this account has no more entries. Note this does not update the secondary
    // indexes!
    pub fn purge_roots(&self, pubkey: &Pubkey) -> (SlotList<T>, bool) {
        self.slot_list_mut(pubkey, |slot_list| {
            let reclaims = self.get_rooted_entries(slot_list, None);
            slot_list.retain(|(slot, _)| !self.is_alive_root(*slot));
            (reclaims, slot_list.is_empty())
        })
        .unwrap()
    }
}

// These functions/fields are only usable from a dev context (i.e. tests and benches)
#[cfg(feature = "dev-context-only-utils")]
impl<T: IndexValue> AccountIndexGetResult<T> {
    pub fn unwrap(self) -> (ReadAccountMapEntry<T>, usize) {
        match self {
            AccountIndexGetResult::Found(lock, size) => (lock, size),
            _ => {
                panic!("trying to unwrap AccountIndexGetResult with non-Success result");
            }
        }
    }

    pub fn is_none(&self) -> bool {
        !self.is_some()
    }

    pub fn is_some(&self) -> bool {
        matches!(self, AccountIndexGetResult::Found(_lock, _size))
    }

    pub fn map<V, F: FnOnce((ReadAccountMapEntry<T>, usize)) -> V>(self, f: F) -> Option<V> {
        match self {
            AccountIndexGetResult::Found(lock, size) => Some(f((lock, size))),
            _ => None,
        }
    }
}
