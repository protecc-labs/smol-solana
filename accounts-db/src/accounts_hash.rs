use {
    crate::{
        accounts_db::{AccountStorageEntry, PUBKEY_BINS_FOR_CALCULATING_HASHES},
        active_stats::{ActiveStatItem, ActiveStats},
        ancestors::Ancestors,
        pubkey_bins::PubkeyBinCalculator24,
        rent_collector::RentCollector,
    },
    bytemuck::{Pod, Zeroable},
    log::*,
    memmap2::MmapMut,
    rayon::prelude::*,
    solana_measure::{measure::Measure, measure_us},
    solana_sdk::{
        hash::{Hash, Hasher},
        pubkey::Pubkey,
        slot_history::Slot,
        sysvar::epoch_schedule::EpochSchedule,
    },
    std::{
        borrow::Borrow,
        convert::TryInto,
        io::{Seek, SeekFrom, Write},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc,
        },
        thread, time,
    },
    tempfile::tempfile_in,
};
pub const MERKLE_FANOUT: usize = 16;

/// 1 file containing account hashes sorted by pubkey, mapped into memory
struct MmapAccountHashesFile {
    /// raw slice of `Hash` values. Can be a larger slice than `count`
    mmap: MmapMut,
    /// # of valid Hash entries in `mmap`
    count: usize,
}

impl MmapAccountHashesFile {
    /// return a slice of account hashes starting at 'index'
    fn read(&self, index: usize) -> &[Hash] {
        let start = std::mem::size_of::<Hash>() * index;
        let end = std::mem::size_of::<Hash>() * self.count;
        let bytes = &self.mmap[start..end];
        bytemuck::cast_slice(bytes)
    }

    /// write a hash to the end of mmap file.
    fn write(&mut self, hash: &Hash) {
        let start = self.count * std::mem::size_of::<Hash>();
        let end = start + std::mem::size_of::<Hash>();
        self.mmap[start..end].copy_from_slice(hash.as_ref());
        self.count += 1;
    }
}

/// 1 file containing account hashes sorted by pubkey
struct AccountHashesFile {
    /// # hashes and an open file that will be deleted on drop. None if there are zero hashes to represent, and thus, no file.
    writer: Option<MmapAccountHashesFile>,
    /// The directory where temporary cache files are put
    dir_for_temp_cache_files: PathBuf,
    /// # bytes allocated
    capacity: usize,
}

impl AccountHashesFile {
    /// return a mmap reader that can be accessed  by slice
    fn get_reader(&mut self) -> Option<MmapAccountHashesFile> {
        std::mem::take(&mut self.writer)
    }

    /// # hashes stored in this file
    fn count(&self) -> usize {
        self.writer
            .as_ref()
            .map(|writer| writer.count)
            .unwrap_or_default()
    }

    /// write 'hash' to the file
    /// If the file isn't open, create it first.
    fn write(&mut self, hash: &Hash) {
        if self.writer.is_none() {
            // we have hashes to write but no file yet, so create a file that will auto-delete on drop

            let get_file = || -> Result<_, std::io::Error> {
                let mut data = tempfile_in(&self.dir_for_temp_cache_files).unwrap_or_else(|err| {
                    panic!(
                        "Unable to create file within {}: {err}",
                        self.dir_for_temp_cache_files.display()
                    )
                });

                // Theoretical performance optimization: write a zero to the end of
                // the file so that we won't have to resize it later, which may be
                // expensive.
                assert!(self.capacity > 0);
                data.seek(SeekFrom::Start((self.capacity - 1) as u64))?;
                data.write_all(&[0])?;
                data.rewind()?;
                data.flush()?;
                Ok(data)
            };

            // Retry 5 times to allocate the AccountHashesFile. The memory might be fragmented and
            // causes memory allocation failure. Therefore, let's retry after failure. Hoping that the
            // kernel has the chance to defrag the memory between the retries, and retries succeed.
            let mut num_retries = 0;
            let data = loop {
                num_retries += 1;

                match get_file() {
                    Ok(data) => {
                        break data;
                    }
                    Err(err) => {
                        info!(
                            "Unable to create account hashes file within {}: {}, retry counter {}",
                            self.dir_for_temp_cache_files.display(),
                            err,
                            num_retries
                        );

                        if num_retries > 5 {
                            panic!(
                                "Unable to create account hashes file within {}: after {} retries",
                                self.dir_for_temp_cache_files.display(),
                                num_retries
                            );
                        }
                        datapoint_info!(
                            "retry_account_hashes_file_allocation",
                            ("retry", num_retries, i64)
                        );
                        thread::sleep(time::Duration::from_millis(num_retries * 100));
                    }
                }
            };

            //UNSAFE: Required to create a Mmap
            let map = unsafe { MmapMut::map_mut(&data) };
            let map = map.unwrap_or_else(|e| {
                error!(
                    "Failed to map the data file (size: {}): {}.\n
                        Please increase sysctl vm.max_map_count or equivalent for your platform.",
                    self.capacity, e
                );
                std::process::exit(1);
            });

            self.writer = Some(MmapAccountHashesFile {
                mmap: map,
                count: 0,
            });
        }
        self.writer.as_mut().unwrap().write(hash);
    }
}

/// parameters to calculate accounts hash
#[derive(Debug)]
pub struct CalcAccountsHashConfig<'a> {
    /// true to use a thread pool dedicated to bg operations
    pub use_bg_thread_pool: bool,
    /// verify every hash in append vec/write cache with a recalculated hash
    pub check_hash: bool,
    /// 'ancestors' is used to get storages
    pub ancestors: Option<&'a Ancestors>,
    /// does hash calc need to consider account data that exists in the write cache?
    /// if so, 'ancestors' will be used for this purpose as well as storages.
    pub epoch_schedule: &'a EpochSchedule,
    pub rent_collector: &'a RentCollector,
    /// used for tracking down hash mismatches after the fact
    pub store_detailed_debug_info_on_failure: bool,
}

// smallest, 3 quartiles, largest, average
pub type StorageSizeQuartileStats = [usize; 6];

#[derive(Debug, Default)]
pub struct HashStats {
    pub total_us: u64,
    pub mark_time_us: u64,
    pub cache_hash_data_us: u64,
    pub scan_time_total_us: u64,
    pub zeros_time_total_us: u64,
    pub hash_time_total_us: u64,
    pub sort_time_total_us: u64,
    pub hash_total: usize,
    pub num_snapshot_storage: usize,
    pub scan_chunks: usize,
    pub num_slots: usize,
    pub num_dirty_slots: usize,
    pub collect_snapshots_us: u64,
    pub storage_sort_us: u64,
    pub storage_size_quartiles: StorageSizeQuartileStats,
    pub oldest_root: Slot,
    pub roots_older_than_epoch: AtomicUsize,
    pub accounts_in_roots_older_than_epoch: AtomicUsize,
    pub append_vec_sizes_older_than_epoch: AtomicUsize,
    pub longest_ancient_scan_us: AtomicU64,
    pub sum_ancient_scans_us: AtomicU64,
    pub count_ancient_scans: AtomicU64,
    pub pubkey_bin_search_us: AtomicU64,
}
impl HashStats {
    pub fn calc_storage_size_quartiles(&mut self, storages: &[Arc<AccountStorageEntry>]) {
        let mut sum = 0;
        let mut sizes = storages
            .iter()
            .map(|storage| {
                let cap = storage.accounts.capacity() as usize;
                sum += cap;
                cap
            })
            .collect::<Vec<_>>();
        sizes.sort_unstable();
        let len = sizes.len();
        self.storage_size_quartiles = if len == 0 {
            StorageSizeQuartileStats::default()
        } else {
            [
                *sizes.first().unwrap(),
                sizes[len / 4],
                sizes[len * 2 / 4],
                sizes[len * 3 / 4],
                *sizes.last().unwrap(),
                sum / len,
            ]
        };
    }

    pub fn log(&self) {
        datapoint_info!(
            "calculate_accounts_hash_from_storages",
            ("total_us", self.total_us, i64),
            ("mark_time_us", self.mark_time_us, i64),
            ("cache_hash_data_us", self.cache_hash_data_us, i64),
            ("accounts_scan_us", self.scan_time_total_us, i64),
            ("eliminate_zeros_us", self.zeros_time_total_us, i64),
            ("hash_us", self.hash_time_total_us, i64),
            ("sort_us", self.sort_time_total_us, i64),
            ("hash_total", self.hash_total, i64),
            ("storage_sort_us", self.storage_sort_us, i64),
            ("collect_snapshots_us", self.collect_snapshots_us, i64),
            ("num_snapshot_storage", self.num_snapshot_storage, i64),
            ("scan_chunks", self.scan_chunks, i64),
            ("num_slots", self.num_slots, i64),
            ("num_dirty_slots", self.num_dirty_slots, i64),
            ("storage_size_min", self.storage_size_quartiles[0], i64),
            (
                "storage_size_quartile_1",
                self.storage_size_quartiles[1],
                i64
            ),
            (
                "storage_size_quartile_2",
                self.storage_size_quartiles[2],
                i64
            ),
            (
                "storage_size_quartile_3",
                self.storage_size_quartiles[3],
                i64
            ),
            ("storage_size_max", self.storage_size_quartiles[4], i64),
            ("storage_size_avg", self.storage_size_quartiles[5], i64),
            (
                "roots_older_than_epoch",
                self.roots_older_than_epoch.load(Ordering::Relaxed),
                i64
            ),
            ("oldest_root", self.oldest_root, i64),
            (
                "longest_ancient_scan_us",
                self.longest_ancient_scan_us.load(Ordering::Relaxed),
                i64
            ),
            (
                "sum_ancient_scans_us",
                self.sum_ancient_scans_us.load(Ordering::Relaxed),
                i64
            ),
            (
                "count_ancient_scans",
                self.count_ancient_scans.load(Ordering::Relaxed),
                i64
            ),
            (
                "append_vec_sizes_older_than_epoch",
                self.append_vec_sizes_older_than_epoch
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "accounts_in_roots_older_than_epoch",
                self.accounts_in_roots_older_than_epoch
                    .load(Ordering::Relaxed),
                i64
            ),
            (
                "pubkey_bin_search_us",
                self.pubkey_bin_search_us.load(Ordering::Relaxed),
                i64
            ),
        );
    }
}

/// While scanning appendvecs, this is the info that needs to be extracted, de-duped, and sorted from what is stored in an append vec.
/// Note this can be saved/loaded during hash calculation to a memory mapped file whose contents are
/// [CalculateHashIntermediate]
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Pod, Zeroable)]
pub struct CalculateHashIntermediate {
    pub hash: AccountHash,
    pub lamports: u64,
    pub pubkey: Pubkey,
}

// In order to safely guarantee CalculateHashIntermediate is Pod, it cannot have any padding
const _: () = assert!(
    std::mem::size_of::<CalculateHashIntermediate>()
        == std::mem::size_of::<AccountHash>()
            + std::mem::size_of::<u64>()
            + std::mem::size_of::<Pubkey>(),
    "CalculateHashIntermediate cannot have any padding"
);

#[derive(Debug, PartialEq, Eq)]
struct CumulativeOffset {
    /// Since the source data is at most 2D, two indexes are enough.
    index: [usize; 2],
    start_offset: usize,
}

trait ExtractSliceFromRawData<'b, T: 'b> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T];
}

impl<'b, T: 'b> ExtractSliceFromRawData<'b, T> for Vec<Vec<T>> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T] {
        &self[offset.index[0]][start..]
    }
}

impl<'b, T: 'b> ExtractSliceFromRawData<'b, T> for Vec<Vec<Vec<T>>> {
    fn extract<'a>(&'b self, offset: &'a CumulativeOffset, start: usize) -> &'b [T] {
        &self[offset.index[0]][offset.index[1]][start..]
    }
}

// Allow retrieving &[start..end] from a logical src: Vec<T>, where src is really Vec<Vec<T>> (or later Vec<Vec<Vec<T>>>)
// This model prevents callers from having to flatten which saves both working memory and time.
#[derive(Default, Debug)]
struct CumulativeOffsets {
    cumulative_offsets: Vec<CumulativeOffset>,
    total_count: usize,
}

/// used by merkle tree calculation to lookup account hashes by overall index
#[derive(Default)]
struct CumulativeHashesFromFiles {
    /// source of hashes in order
    readers: Vec<MmapAccountHashesFile>,
    /// look up reader index and offset by overall index
    cumulative: CumulativeOffsets,
}

impl CumulativeHashesFromFiles {
    /// Calculate offset from overall index to which file and offset within that file based on the length of each hash file.
    /// Also collect readers to access the data.
    fn from_files(hashes: Vec<AccountHashesFile>) -> Self {
        let mut readers = Vec::with_capacity(hashes.len());
        let cumulative = CumulativeOffsets::new(hashes.into_iter().filter_map(|mut hash_file| {
            // ignores all hashfiles that have zero entries
            hash_file.get_reader().map(|reader| {
                let count = reader.count;
                readers.push(reader);
                count
            })
        }));
        Self {
            cumulative,
            readers,
        }
    }

    /// total # of items referenced
    fn total_count(&self) -> usize {
        self.cumulative.total_count
    }

    // return the biggest slice possible that starts at the overall index 'start'
    fn get_slice(&self, start: usize) -> &[Hash] {
        let (start, offset) = self.cumulative.find(start);
        let data_source_index = offset.index[0];
        let data = &self.readers[data_source_index];
        // unwrap here because we should never ask for data that doesn't exist. If we do, then cumulative calculated incorrectly.
        data.read(start)
    }
}

impl CumulativeOffsets {
    fn new<I>(iter: I) -> Self
    where
        I: Iterator<Item = usize>,
    {
        let mut total_count: usize = 0;
        let cumulative_offsets: Vec<_> = iter
            .enumerate()
            .filter_map(|(i, len)| {
                if len > 0 {
                    let result = CumulativeOffset {
                        index: [i, i],
                        start_offset: total_count,
                    };
                    total_count += len;
                    Some(result)
                } else {
                    None
                }
            })
            .collect();

        Self {
            cumulative_offsets,
            total_count,
        }
    }

    fn from_raw<T>(raw: &[Vec<T>]) -> Self {
        Self::new(raw.iter().map(|v| v.len()))
    }

    /// find the index of the data source that contains 'start'
    fn find_index(&self, start: usize) -> usize {
        assert!(!self.cumulative_offsets.is_empty());
        match self.cumulative_offsets[..].binary_search_by(|index| index.start_offset.cmp(&start)) {
            Ok(index) => index,
            Err(index) => index - 1, // we would insert at index so we are before the item at index
        }
    }

    /// given overall start index 'start'
    /// return ('start', which is the offset into the data source at 'index',
    ///     and 'index', which is the data source to use)
    fn find(&self, start: usize) -> (usize, &CumulativeOffset) {
        let index = self.find_index(start);
        let index = &self.cumulative_offsets[index];
        let start = start - index.start_offset;
        (start, index)
    }

    // return the biggest slice possible that starts at 'start'
    fn get_slice<'a, 'b, T, U>(&'a self, raw: &'b U, start: usize) -> &'b [T]
    where
        U: ExtractSliceFromRawData<'b, T> + 'b,
    {
        let (start, index) = self.find(start);
        raw.extract(index, start)
    }
}

#[derive(Debug)]
pub struct AccountsHasher<'a> {
    pub zero_lamport_accounts: ZeroLamportAccounts,
    /// The directory where temporary cache files are put
    pub dir_for_temp_cache_files: PathBuf,
    pub(crate) active_stats: &'a ActiveStats,
}

/// Pointer to a specific item in chunked accounts hash slices.
#[derive(Debug, Clone, Copy)]
struct SlotGroupPointer {
    /// slot group index
    slot_group_index: usize,
    /// offset within a slot group
    offset: usize,
}

/// A struct for the location of an account hash item inside chunked accounts hash slices.
#[derive(Debug)]
struct ItemLocation<'a> {
    /// account's pubkey
    key: &'a Pubkey,
    /// pointer to the item in slot group slices
    pointer: SlotGroupPointer,
}

impl<'a> AccountsHasher<'a> {
    pub fn calculate_hash(hashes: Vec<Vec<Hash>>) -> (Hash, usize) {
        let cumulative_offsets = CumulativeOffsets::from_raw(&hashes);

        let hash_total = cumulative_offsets.total_count;
        let result = AccountsHasher::compute_merkle_root_from_slices(
            hash_total,
            MERKLE_FANOUT,
            None,
            |start: usize| cumulative_offsets.get_slice(&hashes, start),
            None,
        );
        (result.0, hash_total)
    }

    pub fn compute_merkle_root(hashes: Vec<(Pubkey, Hash)>, fanout: usize) -> Hash {
        Self::compute_merkle_root_loop(hashes, fanout, |t| &t.1)
    }

    // this function avoids an infinite recursion compiler error
    pub fn compute_merkle_root_recurse(hashes: Vec<Hash>, fanout: usize) -> Hash {
        Self::compute_merkle_root_loop(hashes, fanout, |t| t)
    }

    pub fn div_ceil(x: usize, y: usize) -> usize {
        let mut result = x / y;
        if x % y != 0 {
            result += 1;
        }
        result
    }

    // For the first iteration, there could be more items in the tuple than just hash and lamports.
    // Using extractor allows us to avoid an unnecessary array copy on the first iteration.
    pub fn compute_merkle_root_loop<T, F>(hashes: Vec<T>, fanout: usize, extractor: F) -> Hash
    where
        F: Fn(&T) -> &Hash + std::marker::Sync,
        T: std::marker::Sync,
    {
        if hashes.is_empty() {
            return Hasher::default().result();
        }

        let mut time = Measure::start("time");

        let total_hashes = hashes.len();
        let chunks = Self::div_ceil(total_hashes, fanout);

        let result: Vec<_> = (0..chunks)
            .into_par_iter()
            .map(|i| {
                let start_index = i * fanout;
                let end_index = std::cmp::min(start_index + fanout, total_hashes);

                let mut hasher = Hasher::default();
                for item in hashes.iter().take(end_index).skip(start_index) {
                    let h = extractor(item);
                    hasher.hash(h.as_ref());
                }

                hasher.result()
            })
            .collect();
        time.stop();
        debug!("hashing {} {}", total_hashes, time);

        if result.len() == 1 {
            result[0]
        } else {
            Self::compute_merkle_root_recurse(result, fanout)
        }
    }

    fn calculate_three_level_chunks(
        total_hashes: usize,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        specific_level_count: Option<usize>,
    ) -> (usize, usize, bool) {
        const THREE_LEVEL_OPTIMIZATION: usize = 3; // this '3' is dependent on the code structure below where we manually unroll
        let target = fanout.pow(THREE_LEVEL_OPTIMIZATION as u32);

        // Only use the 3 level optimization if we have at least 4 levels of data.
        // Otherwise, we'll be serializing a parallel operation.
        let threshold = target * fanout;
        let mut three_level = max_levels_per_pass.unwrap_or(usize::MAX) >= THREE_LEVEL_OPTIMIZATION
            && total_hashes >= threshold;
        if three_level {
            if let Some(specific_level_count_value) = specific_level_count {
                three_level = specific_level_count_value >= THREE_LEVEL_OPTIMIZATION;
            }
        }
        let (num_hashes_per_chunk, levels_hashed) = if three_level {
            (target, THREE_LEVEL_OPTIMIZATION)
        } else {
            (fanout, 1)
        };
        (num_hashes_per_chunk, levels_hashed, three_level)
    }

    // This function is designed to allow hashes to be located in multiple, perhaps multiply deep vecs.
    // The caller provides a function to return a slice from the source data.
    fn compute_merkle_root_from_slices<'b, F, T>(
        total_hashes: usize,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        get_hash_slice_starting_at_index: F,
        specific_level_count: Option<usize>,
    ) -> (Hash, Vec<Hash>)
    where
        // returns a slice of hashes starting at the given overall index
        F: Fn(usize) -> &'b [T] + std::marker::Sync,
        T: Borrow<Hash> + std::marker::Sync + 'b,
    {
        if total_hashes == 0 {
            return (Hasher::default().result(), vec![]);
        }

        let mut time = Measure::start("time");

        let (num_hashes_per_chunk, levels_hashed, three_level) = Self::calculate_three_level_chunks(
            total_hashes,
            fanout,
            max_levels_per_pass,
            specific_level_count,
        );

        let chunks = Self::div_ceil(total_hashes, num_hashes_per_chunk);

        // initial fetch - could return entire slice
        let data = get_hash_slice_starting_at_index(0);
        let data_len = data.len();

        let result: Vec<_> = (0..chunks)
            .into_par_iter()
            .map(|i| {
                // summary:
                // this closure computes 1 or 3 levels of merkle tree (all chunks will be 1 or all will be 3)
                // for a subset (our chunk) of the input data [start_index..end_index]

                // index into get_hash_slice_starting_at_index where this chunk's range begins
                let start_index = i * num_hashes_per_chunk;
                // index into get_hash_slice_starting_at_index where this chunk's range ends
                let end_index = std::cmp::min(start_index + num_hashes_per_chunk, total_hashes);

                // will compute the final result for this closure
                let mut hasher = Hasher::default();

                // index into 'data' where we are currently pulling data
                // if we exhaust our data, then we will request a new slice, and data_index resets to 0, the beginning of the new slice
                let mut data_index = start_index;
                // source data, which we may refresh when we exhaust
                let mut data = data;
                // len of the source data
                let mut data_len = data_len;

                if !three_level {
                    // 1 group of fanout
                    // The result of this loop is a single hash value from fanout input hashes.
                    for i in start_index..end_index {
                        if data_index >= data_len {
                            // we exhausted our data, fetch next slice starting at i
                            data = get_hash_slice_starting_at_index(i);
                            data_len = data.len();
                            data_index = 0;
                        }
                        hasher.hash(data[data_index].borrow().as_ref());
                        data_index += 1;
                    }
                } else {
                    // hash 3 levels of fanout simultaneously.
                    // This codepath produces 1 hash value for between 1..=fanout^3 input hashes.
                    // It is equivalent to running the normal merkle tree calculation 3 iterations on the input.
                    //
                    // big idea:
                    //  merkle trees usually reduce the input vector by a factor of fanout with each iteration
                    //  example with fanout 2:
                    //   start:     [0,1,2,3,4,5,6,7]      in our case: [...16M...] or really, 1B
                    //   iteration0 [.5, 2.5, 4.5, 6.5]                 [... 1M...]
                    //   iteration1 [1.5, 5.5]                          [...65k...]
                    //   iteration2 3.5                                 [...4k... ]
                    //  So iteration 0 consumes N elements, hashes them in groups of 'fanout' and produces a vector of N/fanout elements
                    //   and the process repeats until there is only 1 hash left.
                    //
                    //  With the three_level code path, we make each chunk we iterate of size fanout^3 (4096)
                    //  So, the input could be 16M hashes and the output will be 4k hashes, or N/fanout^3
                    //  The goal is to reduce the amount of data that has to be constructed and held in memory.
                    //  When we know we have enough hashes, then, in 1 pass, we hash 3 levels simultaneously, storing far fewer intermediate hashes.
                    //
                    // Now, some details:
                    // The result of this loop is a single hash value from fanout^3 input hashes.
                    // concepts:
                    //  what we're conceptually hashing: "raw_hashes"[start_index..end_index]
                    //   example: [a,b,c,d,e,f]
                    //   but... hashes[] may really be multiple vectors that are pieced together.
                    //   example: [[a,b],[c],[d,e,f]]
                    //   get_hash_slice_starting_at_index(any_index) abstracts that and returns a slice starting at raw_hashes[any_index..]
                    //   such that the end of get_hash_slice_starting_at_index may be <, >, or = end_index
                    //   example: get_hash_slice_starting_at_index(1) returns [b]
                    //            get_hash_slice_starting_at_index(3) returns [d,e,f]
                    // This code is basically 3 iterations of merkle tree hashing occurring simultaneously.
                    // The first fanout raw hashes are hashed in hasher_k. This is iteration0
                    // Once hasher_k has hashed fanout hashes, hasher_k's result hash is hashed in hasher_j and then discarded
                    // hasher_k then starts over fresh and hashes the next fanout raw hashes. This is iteration0 again for a new set of data.
                    // Once hasher_j has hashed fanout hashes (from k), hasher_j's result hash is hashed in hasher and then discarded
                    // Once hasher has hashed fanout hashes (from j), then the result of hasher is the hash for fanout^3 raw hashes.
                    // If there are < fanout^3 hashes, then this code stops when it runs out of raw hashes and returns whatever it hashed.
                    // This is always how the very last elements work in a merkle tree.
                    let mut i = start_index;
                    while i < end_index {
                        let mut hasher_j = Hasher::default();
                        for _j in 0..fanout {
                            let mut hasher_k = Hasher::default();
                            let end = std::cmp::min(end_index - i, fanout);
                            for _k in 0..end {
                                if data_index >= data_len {
                                    // we exhausted our data, fetch next slice starting at i
                                    data = get_hash_slice_starting_at_index(i);
                                    data_len = data.len();
                                    data_index = 0;
                                }
                                hasher_k.hash(data[data_index].borrow().as_ref());
                                data_index += 1;
                                i += 1;
                            }
                            hasher_j.hash(hasher_k.result().as_ref());
                            if i >= end_index {
                                break;
                            }
                        }
                        hasher.hash(hasher_j.result().as_ref());
                    }
                }

                hasher.result()
            })
            .collect();
        time.stop();
        debug!("hashing {} {}", total_hashes, time);

        if let Some(mut specific_level_count_value) = specific_level_count {
            specific_level_count_value -= levels_hashed;
            if specific_level_count_value == 0 {
                (Hash::default(), result)
            } else {
                assert!(specific_level_count_value > 0);
                // We did not hash the number of levels required by 'specific_level_count', so repeat
                Self::compute_merkle_root_from_slices_recurse(
                    result,
                    fanout,
                    max_levels_per_pass,
                    Some(specific_level_count_value),
                )
            }
        } else {
            (
                if result.len() == 1 {
                    result[0]
                } else {
                    Self::compute_merkle_root_recurse(result, fanout)
                },
                vec![], // no intermediate results needed by caller
            )
        }
    }

    fn compute_merkle_root_from_slices_recurse(
        hashes: Vec<Hash>,
        fanout: usize,
        max_levels_per_pass: Option<usize>,
        specific_level_count: Option<usize>,
    ) -> (Hash, Vec<Hash>) {
        Self::compute_merkle_root_from_slices(
            hashes.len(),
            fanout,
            max_levels_per_pass,
            |start| &hashes[start..],
            specific_level_count,
        )
    }

    pub fn accumulate_account_hashes(mut hashes: Vec<(Pubkey, AccountHash)>) -> Hash {
        hashes.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Self::compute_merkle_root_loop(hashes, MERKLE_FANOUT, |i| &i.1 .0)
    }

    pub fn compare_two_hash_entries(
        a: &CalculateHashIntermediate,
        b: &CalculateHashIntermediate,
    ) -> std::cmp::Ordering {
        // note partial_cmp only returns None with floating point comparisons
        a.pubkey.partial_cmp(&b.pubkey).unwrap()
    }

    pub fn checked_cast_for_capitalization(balance: u128) -> u64 {
        balance.try_into().unwrap_or_else(|_| {
            panic!("overflow is detected while summing capitalization: {balance}")
        })
    }

    /// returns:
    /// Vec, with one entry per bin
    ///  for each entry, Vec<Hash> in pubkey order
    /// If return Vec<AccountHashesFile> was flattened, it would be all hashes, in pubkey order.
    fn de_dup_accounts(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        stats: &mut HashStats,
        max_bin: usize,
    ) -> (Vec<AccountHashesFile>, u64) {
        // 1. eliminate zero lamport accounts
        // 2. pick the highest slot or (slot = and highest version) of each pubkey
        // 3. produce this output:
        // a. vec: PUBKEY_BINS_FOR_CALCULATING_HASHES in pubkey order
        //      vec: individual hashes in pubkey order, 1 hash per
        // b. lamports
        let _guard = self.active_stats.activate(ActiveStatItem::HashDeDup);

        #[derive(Default)]
        struct DedupResult {
            hashes_files: Vec<AccountHashesFile>,
            hashes_count: usize,
            lamports_sum: u64,
        }

        let mut zeros = Measure::start("eliminate zeros");
        let DedupResult {
            hashes_files: hashes,
            hashes_count: hash_total,
            lamports_sum: lamports_total,
        } = (0..max_bin)
            .into_par_iter()
            .fold(DedupResult::default, |mut accum, bin| {
                let (hashes_file, lamports_bin) =
                    self.de_dup_accounts_in_parallel(sorted_data_by_pubkey, bin, max_bin, stats);

                accum.lamports_sum = accum
                    .lamports_sum
                    .checked_add(lamports_bin)
                    .expect("summing capitalization cannot overflow");
                accum.hashes_count += hashes_file.count();
                accum.hashes_files.push(hashes_file);
                accum
            })
            .reduce(
                || DedupResult {
                    hashes_files: Vec::with_capacity(max_bin),
                    ..Default::default()
                },
                |mut a, mut b| {
                    a.lamports_sum = a
                        .lamports_sum
                        .checked_add(b.lamports_sum)
                        .expect("summing capitalization cannot overflow");
                    a.hashes_count += b.hashes_count;
                    a.hashes_files.append(&mut b.hashes_files);
                    a
                },
            );
        zeros.stop();
        stats.zeros_time_total_us += zeros.as_us();
        stats.hash_total += hash_total;
        (hashes, lamports_total)
    }

    /// Given the item location, return the item in the `CalculatedHashIntermediate` slices and the next item location in the same bin.
    /// If the end of the `CalculatedHashIntermediate` slice is reached or all the accounts in current bin have been exhausted, return `None` for next item location.
    fn get_item<'b>(
        sorted_data_by_pubkey: &[&'b [CalculateHashIntermediate]],
        bin: usize,
        binner: &PubkeyBinCalculator24,
        item_loc: &ItemLocation<'b>,
    ) -> (&'b CalculateHashIntermediate, Option<ItemLocation<'b>>) {
        let division_data = &sorted_data_by_pubkey[item_loc.pointer.slot_group_index];
        let mut index = item_loc.pointer.offset;
        index += 1;
        let mut next = None;

        while index < division_data.len() {
            // still more items where we found the previous key, so just increment the index for that slot group, skipping all pubkeys that are equal
            let next_key = &division_data[index].pubkey;
            if next_key == item_loc.key {
                index += 1;
                continue; // duplicate entries of same pubkey, so keep skipping
            }

            if binner.bin_from_pubkey(next_key) > bin {
                // the next pubkey is not in our bin
                break;
            }

            // point to the next pubkey > key
            next = Some(ItemLocation {
                key: next_key,
                pointer: SlotGroupPointer {
                    slot_group_index: item_loc.pointer.slot_group_index,
                    offset: index,
                },
            });
            break;
        }

        // this is the previous first item that was requested
        (&division_data[index - 1], next)
    }

    /// `hash_data` must be sorted by `binner.bin_from_pubkey()`
    /// return index in `hash_data` of first pubkey that is in `bin`, based on `binner`
    fn binary_search_for_first_pubkey_in_bin(
        hash_data: &[CalculateHashIntermediate],
        bin: usize,
        binner: &PubkeyBinCalculator24,
    ) -> Option<usize> {
        let potential_index = if bin == 0 {
            // `bin` == 0 is special because there cannot be `bin`-1
            // so either element[0] is in bin 0 or there is nothing in bin 0.
            0
        } else {
            // search for the first pubkey that is in `bin`
            // There could be many keys in a row with the same `bin`.
            // So, for each pubkey, use calculated_bin * 2 + 1 as the bin of a given pubkey for binary search.
            // And compare the bin of each pubkey with `bin` * 2.
            // So all keys that are in `bin` will compare as `bin` * 2 + 1
            // all keys that are in `bin`-1 will compare as ((`bin` - 1) * 2 + 1), which is (`bin` * 2 - 1)
            // NO keys will compare as `bin` * 2 because we add 1.
            // So, the binary search will NEVER return Ok(found_index), but will always return Err(index of first key in `bin`).
            // Note that if NO key is in `bin`, then the key at the found index will be in a bin > `bin`, so return None.
            let just_prior_to_desired_bin = bin * 2;
            let search = hash_data.binary_search_by(|data| {
                (1 + 2 * binner.bin_from_pubkey(&data.pubkey)).cmp(&just_prior_to_desired_bin)
            });
            // returns Err(index where item should be) since the desired item will never exist
            search.expect_err("it is impossible to find a matching bin")
        };
        // note that `potential_index` could be == hash_data.len(). This indicates the first key in `bin` would be
        // after the data we have. Thus, no key is in `bin`.
        // This also handles the case where `hash_data` is empty, since len() will be 0 and `get` will return None.
        hash_data.get(potential_index).and_then(|potential_data| {
            (binner.bin_from_pubkey(&potential_data.pubkey) == bin).then_some(potential_index)
        })
    }

    /// `hash_data` must be sorted by `binner.bin_from_pubkey()`
    /// return index in `hash_data` of first pubkey that is in `bin`, based on `binner`
    fn find_first_pubkey_in_bin(
        hash_data: &[CalculateHashIntermediate],
        bin: usize,
        bins: usize,
        binner: &PubkeyBinCalculator24,
        stats: &HashStats,
    ) -> Option<usize> {
        if hash_data.is_empty() {
            return None;
        }
        let (result, us) = measure_us!({
            // assume uniform distribution of pubkeys and choose first guess based on bin we're looking for
            let i = hash_data.len() * bin / bins;
            let estimate = &hash_data[i];

            let pubkey_bin = binner.bin_from_pubkey(&estimate.pubkey);
            let range = if pubkey_bin >= bin {
                // i pubkey matches or is too large, so look <= i for the first pubkey in the right bin
                // i+1 could be the first pubkey in the right bin
                0..(i + 1)
            } else {
                // i pubkey is too small, so look after i
                (i + 1)..hash_data.len()
            };
            Some(
                range.start +
                // binary search the subset
                Self::binary_search_for_first_pubkey_in_bin(
                    &hash_data[range],
                    bin,
                    binner,
                )?,
            )
        });
        stats.pubkey_bin_search_us.fetch_add(us, Ordering::Relaxed);
        result
    }

    /// Return the working_set and max number of pubkeys for hash dedup.
    /// `working_set` holds SlotGroupPointer {slot_group_index, offset} for items in account's pubkey descending order.
    fn initialize_dedup_working_set(
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        pubkey_bin: usize,
        bins: usize,
        binner: &PubkeyBinCalculator24,
        stats: &HashStats,
    ) -> (
        Vec<SlotGroupPointer>, /* working_set */
        usize,                 /* max_inclusive_num_pubkeys */
    ) {
        // working_set holds the lowest items for each slot_group sorted by pubkey descending (min_key is the last)
        let mut working_set: Vec<SlotGroupPointer> = Vec::default();

        // Initialize 'working_set', which holds the current lowest item in each slot group.
        // `working_set` should be initialized in reverse order of slot_groups. Later slot_groups are
        // processed first. For each slot_group, if the lowest item for current slot group is
        // already in working_set (i.e. inserted by a later slot group), the next lowest item
        // in this slot group is searched and checked, until either one that is `not` in the
        // working_set is found, which will then be inserted, or no next lowest item is found.
        // Iterating in reverse order of slot_group will guarantee that each slot group will be
        // scanned only once and scanned continuously. Therefore, it can achieve better data
        // locality during the scan.
        let max_inclusive_num_pubkeys = sorted_data_by_pubkey
            .iter()
            .enumerate()
            .rev()
            .map(|(i, hash_data)| {
                let first_pubkey_in_bin =
                    Self::find_first_pubkey_in_bin(hash_data, pubkey_bin, bins, binner, stats);

                if let Some(first_pubkey_in_bin) = first_pubkey_in_bin {
                    let mut next = Some(ItemLocation {
                        key: &hash_data[first_pubkey_in_bin].pubkey,
                        pointer: SlotGroupPointer {
                            slot_group_index: i,
                            offset: first_pubkey_in_bin,
                        },
                    });

                    Self::add_next_item(
                        &mut next,
                        &mut working_set,
                        sorted_data_by_pubkey,
                        pubkey_bin,
                        binner,
                    );

                    let mut first_pubkey_in_next_bin = first_pubkey_in_bin + 1;
                    while first_pubkey_in_next_bin < hash_data.len() {
                        if binner.bin_from_pubkey(&hash_data[first_pubkey_in_next_bin].pubkey)
                            != pubkey_bin
                        {
                            break;
                        }
                        first_pubkey_in_next_bin += 1;
                    }
                    first_pubkey_in_next_bin - first_pubkey_in_bin
                } else {
                    0
                }
            })
            .sum::<usize>();

        (working_set, max_inclusive_num_pubkeys)
    }

    /// Add next item into hash dedup working set
    fn add_next_item<'b>(
        next: &mut Option<ItemLocation<'b>>,
        working_set: &mut Vec<SlotGroupPointer>,
        sorted_data_by_pubkey: &[&'b [CalculateHashIntermediate]],
        pubkey_bin: usize,
        binner: &PubkeyBinCalculator24,
    ) {
        // looping to add next item to working set
        while let Some(ItemLocation { key, pointer }) = std::mem::take(next) {
            // if `new key` is less than the min key in the working set, skip binary search and
            // insert item to the end vec directly
            if let Some(SlotGroupPointer {
                slot_group_index: current_min_slot_group_index,
                offset: current_min_offset,
            }) = working_set.last()
            {
                let current_min_key = &sorted_data_by_pubkey[*current_min_slot_group_index]
                    [*current_min_offset]
                    .pubkey;
                if key < current_min_key {
                    working_set.push(pointer);
                    break;
                }
            }

            let found = working_set.binary_search_by(|pointer| {
                let prob = &sorted_data_by_pubkey[pointer.slot_group_index][pointer.offset].pubkey;
                (*key).cmp(prob)
            });

            match found {
                Err(index) => {
                    // found a new new key, insert into the working_set. This is O(n/2) on
                    // average. Theoretically, this operation could be expensive and may be further
                    // optimized in future.
                    working_set.insert(index, pointer);
                    break;
                }
                Ok(index) => {
                    let found = &mut working_set[index];
                    if found.slot_group_index > pointer.slot_group_index {
                        // There is already a later slot group that contains this key in the working_set,
                        // look up again.
                        let (_item, new_next) = Self::get_item(
                            sorted_data_by_pubkey,
                            pubkey_bin,
                            binner,
                            &ItemLocation { key, pointer },
                        );
                        *next = new_next;
                    } else {
                        // A previous slot contains this key, replace it, and look for next item in the previous slot group.
                        let (_item, new_next) = Self::get_item(
                            sorted_data_by_pubkey,
                            pubkey_bin,
                            binner,
                            &ItemLocation {
                                key,
                                pointer: *found,
                            },
                        );
                        *found = pointer;
                        *next = new_next;
                    }
                }
            }
        }
    }

    // go through: [..][pubkey_bin][..] and return hashes and lamport sum
    //   slot groups^                ^accounts found in a slot group, sorted by pubkey, higher slot, write_version
    // 1. handle zero lamport accounts
    // 2. pick the highest slot or (slot = and highest version) of each pubkey
    // 3. produce this output:
    //   a. AccountHashesFile: individual account hashes in pubkey order
    //   b. lamport sum
    fn de_dup_accounts_in_parallel(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        pubkey_bin: usize,
        bins: usize,
        stats: &HashStats,
    ) -> (AccountHashesFile, u64) {
        let binner = PubkeyBinCalculator24::new(bins);

        // working_set hold the lowest items for each slot_group sorted by pubkey descending (min_key is the last)
        let (mut working_set, max_inclusive_num_pubkeys) = Self::initialize_dedup_working_set(
            sorted_data_by_pubkey,
            pubkey_bin,
            bins,
            &binner,
            stats,
        );

        let mut hashes = AccountHashesFile {
            writer: None,
            dir_for_temp_cache_files: self.dir_for_temp_cache_files.clone(),
            capacity: max_inclusive_num_pubkeys * std::mem::size_of::<Hash>(),
        };

        let mut overall_sum = 0;

        while let Some(pointer) = working_set.pop() {
            let key = &sorted_data_by_pubkey[pointer.slot_group_index][pointer.offset].pubkey;

            // get the min item, add lamports, get hash
            let (item, mut next) = Self::get_item(
                sorted_data_by_pubkey,
                pubkey_bin,
                &binner,
                &ItemLocation { key, pointer },
            );

            // add lamports and get hash
            if item.lamports != 0 {
                overall_sum = Self::checked_cast_for_capitalization(
                    item.lamports as u128 + overall_sum as u128,
                );
                hashes.write(&item.hash.0);
            } else {
                // if lamports == 0, check if they should be included
                if self.zero_lamport_accounts == ZeroLamportAccounts::Included {
                    // For incremental accounts hash, the hash of a zero lamport account is
                    // the hash of its pubkey
                    let hash = blake3::hash(bytemuck::bytes_of(&item.pubkey));
                    let hash = Hash::new_from_array(hash.into());
                    hashes.write(&hash);
                }
            }

            Self::add_next_item(
                &mut next,
                &mut working_set,
                sorted_data_by_pubkey,
                pubkey_bin,
                &binner,
            );
        }

        (hashes, overall_sum)
    }

    /// input:
    /// vec: group of slot data, ordered by Slot (low to high)
    ///   vec: [..] - items found in that slot range Sorted by: Pubkey, higher Slot, higher Write version (if pubkey =)
    pub fn rest_of_hash_calculation(
        &self,
        sorted_data_by_pubkey: &[&[CalculateHashIntermediate]],
        stats: &mut HashStats,
    ) -> (Hash, u64) {
        let (hashes, total_lamports) = self.de_dup_accounts(
            sorted_data_by_pubkey,
            stats,
            PUBKEY_BINS_FOR_CALCULATING_HASHES,
        );

        let cumulative = CumulativeHashesFromFiles::from_files(hashes);

        let _guard = self.active_stats.activate(ActiveStatItem::HashMerkleTree);
        let mut hash_time = Measure::start("hash");
        let (hash, _) = Self::compute_merkle_root_from_slices(
            cumulative.total_count(),
            MERKLE_FANOUT,
            None,
            |start| cumulative.get_slice(start),
            None,
        );
        hash_time.stop();
        stats.hash_time_total_us += hash_time.as_us();
        (hash, total_lamports)
    }
}

/// How should zero-lamport accounts be treated by the accounts hasher?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ZeroLamportAccounts {
    Excluded,
    Included,
}

/// Hash of an account
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Pod, Zeroable, AbiExample)]
pub struct AccountHash(pub Hash);

// Ensure the newtype wrapper never changes size from the underlying Hash
// This also ensures there are no padding bytes, which is required to safely implement Pod
const _: () = assert!(std::mem::size_of::<AccountHash>() == std::mem::size_of::<Hash>());

/// Hash of accounts
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AccountsHashKind {
    Full(AccountsHash),
    Incremental(IncrementalAccountsHash),
}
impl AccountsHashKind {
    pub fn as_hash(&self) -> &Hash {
        match self {
            AccountsHashKind::Full(AccountsHash(hash))
            | AccountsHashKind::Incremental(IncrementalAccountsHash(hash)) => hash,
        }
    }
}
impl From<AccountsHash> for AccountsHashKind {
    fn from(accounts_hash: AccountsHash) -> Self {
        AccountsHashKind::Full(accounts_hash)
    }
}
impl From<IncrementalAccountsHash> for AccountsHashKind {
    fn from(incremental_accounts_hash: IncrementalAccountsHash) -> Self {
        AccountsHashKind::Incremental(incremental_accounts_hash)
    }
}

/// Hash of accounts
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountsHash(pub Hash);
/// Hash of accounts that includes zero-lamport accounts
/// Used with incremental snapshots
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct IncrementalAccountsHash(pub Hash);

/// Hash of accounts written in a single slot
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountsDeltaHash(pub Hash);

/// Snapshot serde-safe accounts delta hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeAccountsDeltaHash(pub Hash);

impl From<SerdeAccountsDeltaHash> for AccountsDeltaHash {
    fn from(accounts_delta_hash: SerdeAccountsDeltaHash) -> Self {
        Self(accounts_delta_hash.0)
    }
}
impl From<AccountsDeltaHash> for SerdeAccountsDeltaHash {
    fn from(accounts_delta_hash: AccountsDeltaHash) -> Self {
        Self(accounts_delta_hash.0)
    }
}

/// Snapshot serde-safe accounts hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeAccountsHash(pub Hash);

impl From<SerdeAccountsHash> for AccountsHash {
    fn from(accounts_hash: SerdeAccountsHash) -> Self {
        Self(accounts_hash.0)
    }
}
impl From<AccountsHash> for SerdeAccountsHash {
    fn from(accounts_hash: AccountsHash) -> Self {
        Self(accounts_hash.0)
    }
}

/// Snapshot serde-safe incremental accounts hash
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq, AbiExample)]
pub struct SerdeIncrementalAccountsHash(pub Hash);

impl From<SerdeIncrementalAccountsHash> for IncrementalAccountsHash {
    fn from(incremental_accounts_hash: SerdeIncrementalAccountsHash) -> Self {
        Self(incremental_accounts_hash.0)
    }
}
impl From<IncrementalAccountsHash> for SerdeIncrementalAccountsHash {
    fn from(incremental_accounts_hash: IncrementalAccountsHash) -> Self {
        Self(incremental_accounts_hash.0)
    }
}
