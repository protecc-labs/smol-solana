//! BucketMap is a mostly contention free concurrent map backed by MmapMut

use {
    crate::{
        bucket_api::BucketApi, bucket_stats::BucketMapStats, restart::Restart, MaxSearch, RefCount,
    },
    solana_sdk::pubkey::Pubkey,
    std::{
        convert::TryInto,
        fmt::Debug,
        fs::{self},
        path::PathBuf,
        sync::{Arc, Mutex},
    },
    tempfile::TempDir,
};

#[derive(Debug, Default, Clone)]
pub struct BucketMapConfig {
    pub max_buckets: usize,
    pub drives: Option<Vec<PathBuf>>,
    pub max_search: Option<MaxSearch>,
    /// A file with a known path where the current state of the bucket files on disk is saved as the index is running.
    /// This file can be used to restore the index files as they existed prior to the process being stopped.
    pub restart_config_file: Option<PathBuf>,
}

impl BucketMapConfig {
    /// Create a new BucketMapConfig
    /// NOTE: BucketMap requires that max_buckets is a power of two
    pub fn new(max_buckets: usize) -> BucketMapConfig {
        BucketMapConfig {
            max_buckets,
            ..BucketMapConfig::default()
        }
    }
}

pub struct BucketMap<T: Clone + Copy + Debug + PartialEq + 'static> {
    buckets: Vec<Arc<BucketApi<T>>>,
    drives: Arc<Vec<PathBuf>>,
    max_buckets_pow2: u8,
    pub stats: Arc<BucketMapStats>,
    pub temp_dir: Option<TempDir>,
    /// true if dropping self removes all folders.
    /// This is primarily for test environments.
    pub erase_drives_on_drop: bool,
}

impl<T: Clone + Copy + Debug + PartialEq> Drop for BucketMap<T> {
    fn drop(&mut self) {
        if self.temp_dir.is_none() && self.erase_drives_on_drop {
            BucketMap::<T>::erase_previous_drives(&self.drives);
        }
    }
}

impl<T: Clone + Copy + Debug + PartialEq> Debug for BucketMap<T> {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

// this should be <= 1 << DEFAULT_CAPACITY or we end up searching the same items over and over - probably not a big deal since it is so small anyway
pub(crate) const MAX_SEARCH_DEFAULT: MaxSearch = 32;

/// used to communicate resize necessary and current size.
#[derive(Debug)]
pub enum BucketMapError {
    /// (bucket_index, current_capacity_pow2)
    /// Note that this is specific to data buckets, which grow in powers of 2
    DataNoSpace((u64, u8)),

    /// current_capacity_entries
    /// Note that this is specific to index buckets, which can be 'Actual' sizes
    IndexNoSpace(u64),
}

impl<T: Clone + Copy + Debug + PartialEq> BucketMap<T> {
    pub fn new(config: BucketMapConfig) -> Self {
        assert_ne!(
            config.max_buckets, 0,
            "Max number of buckets must be non-zero"
        );
        assert!(
            config.max_buckets.is_power_of_two(),
            "Max number of buckets must be a power of two"
        );
        let max_search = config.max_search.unwrap_or(MAX_SEARCH_DEFAULT);

        let mut restart = Restart::get_restart_file(&config);

        if restart.is_none() {
            // If we were able to load a restart file from the previous run, then don't wipe the accounts index drives from last time.
            // Unused files will be wiped by `get_restartable_buckets`
            if let Some(drives) = config.drives.as_ref() {
                Self::erase_previous_drives(drives);
            }
        }

        let stats = Arc::default();

        if restart.is_none() {
            restart = Restart::new(&config);
        }

        let mut temp_dir = None;
        let drives = config.drives.unwrap_or_else(|| {
            temp_dir = Some(TempDir::new().unwrap());
            vec![temp_dir.as_ref().unwrap().path().to_path_buf()]
        });
        let drives = Arc::new(drives);

        let restart = restart.map(|restart| Arc::new(Mutex::new(restart)));

        let restartable_buckets =
            Restart::get_restartable_buckets(restart.as_ref(), &drives, config.max_buckets);

        let buckets = restartable_buckets
            .into_iter()
            .map(|restartable_bucket| {
                Arc::new(BucketApi::new(
                    Arc::clone(&drives),
                    max_search,
                    Arc::clone(&stats),
                    restartable_bucket,
                ))
            })
            .collect();

        // A simple log2 function that is correct if x is a power of two
        let log2 = |x: usize| usize::BITS - x.leading_zeros() - 1;

        Self {
            buckets,
            drives,
            max_buckets_pow2: log2(config.max_buckets) as u8,
            stats,
            temp_dir,
            // if we are keeping track of restart, then don't wipe the drives on drop
            erase_drives_on_drop: restart.is_none(),
        }
    }

    fn erase_previous_drives(drives: &[PathBuf]) {
        drives.iter().for_each(|folder| {
            let _ = fs::remove_dir_all(folder);
            let _ = fs::create_dir_all(folder);
        })
    }

    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Get the values for Pubkey `key`
    pub fn read_value(&self, key: &Pubkey) -> Option<(Vec<T>, RefCount)> {
        self.get_bucket(key).read_value(key)
    }

    /// Delete the Pubkey `key`
    pub fn delete_key(&self, key: &Pubkey) {
        self.get_bucket(key).delete_key(key);
    }

    /// Update Pubkey `key`'s value with 'value'
    pub fn insert(&self, key: &Pubkey, value: (&[T], RefCount)) {
        self.get_bucket(key).insert(key, value)
    }

    /// Update Pubkey `key`'s value with 'value'
    pub fn try_insert(&self, key: &Pubkey, value: (&[T], RefCount)) -> Result<(), BucketMapError> {
        self.get_bucket(key).try_write(key, value)
    }

    /// Update Pubkey `key`'s value with function `updatefn`
    pub fn update<F>(&self, key: &Pubkey, updatefn: F)
    where
        F: FnMut(Option<(&[T], RefCount)>) -> Option<(Vec<T>, RefCount)>,
    {
        self.get_bucket(key).update(key, updatefn)
    }

    pub fn get_bucket(&self, key: &Pubkey) -> &Arc<BucketApi<T>> {
        self.get_bucket_from_index(self.bucket_ix(key))
    }

    pub fn get_bucket_from_index(&self, ix: usize) -> &Arc<BucketApi<T>> {
        &self.buckets[ix]
    }

    /// Get the bucket index for Pubkey `key`
    pub fn bucket_ix(&self, key: &Pubkey) -> usize {
        if self.max_buckets_pow2 > 0 {
            let location = read_be_u64(key.as_ref());
            (location >> (u64::BITS - self.max_buckets_pow2 as u32)) as usize
        } else {
            0
        }
    }
}

/// Look at the first 8 bytes of the input and reinterpret them as a u64
fn read_be_u64(input: &[u8]) -> u64 {
    assert!(input.len() >= std::mem::size_of::<u64>());
    u64::from_be_bytes(input[0..std::mem::size_of::<u64>()].try_into().unwrap())
}
