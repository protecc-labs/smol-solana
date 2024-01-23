//! Persistent info of disk index files to allow files to be reused on restart.
use {
    crate::bucket_map::{BucketMapConfig, MAX_SEARCH_DEFAULT},
    bytemuck::{Pod, Zeroable},
    memmap2::MmapMut,
    std::{
        collections::HashMap,
        fmt::{Debug, Formatter},
        fs::{self, remove_file, OpenOptions},
        io::{Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

/// written into file. Change this if expected file contents change.
const HEADER_VERSION: u64 = 1;

/// written into file at top.
#[derive(Debug, Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub(crate) struct Header {
    /// version of this file. Differences here indicate the file is not usable.
    version: u64,
    /// number of buckets these files represent.
    buckets: u64,
    /// u8 representing how many entries to search for during collisions.
    /// If this is different, then the contents of the index file's contents are likely not as helpful.
    max_search: u8,
    /// padding to make size of Header be an even multiple of u128
    _dummy: [u8; 15],
}

// In order to safely guarantee Header is Pod, it cannot have any padding.
const _: () = assert!(
    std::mem::size_of::<Header>() == std::mem::size_of::<u128>() * 2,
    "incorrect size of header struct"
);

#[derive(Debug, Pod, Zeroable, Copy, Clone)]
#[repr(C)]
pub(crate) struct OneIndexBucket {
    /// disk bucket file names are random u128s
    file_name: u128,
    /// each bucket uses a random value to hash with pubkeys. Without this, hashing would be inconsistent between restarts.
    random: u64,
    /// padding to make size of OneIndexBucket be an even multiple of u128
    _dummy: u64,
}

// In order to safely guarantee Header is Pod, it cannot have any padding.
const _: () = assert!(
    std::mem::size_of::<OneIndexBucket>() == std::mem::size_of::<u128>() * 2,
    "incorrect size of header struct"
);

pub(crate) struct Restart {
    mmap: MmapMut,
}

#[derive(Clone, Default)]
/// keep track of mapping from a single bucket to the shared mmap file
pub(crate) struct RestartableBucket {
    /// shared struct keeping track of each bucket's file
    pub(crate) restart: Option<Arc<Mutex<Restart>>>,
    /// which index self represents inside `restart`
    pub(crate) index: usize,
    /// path disk index file is at for startup
    pub(crate) path: Option<PathBuf>,
}

impl RestartableBucket {
    /// this bucket is now using `file_name` and `random`.
    /// This gets written into the restart file so that on restart we can re-open the file and re-hash with the same random.
    pub(crate) fn set_file(&self, file_name: u128, random: u64) {
        if let Some(mut restart) = self.restart.as_ref().map(|restart| restart.lock().unwrap()) {
            let bucket = restart.get_bucket_mut(self.index);
            bucket.file_name = file_name;
            bucket.random = random;
        }
    }
    /// retrieve the file_name and random that were used prior to the current restart.
    /// This was written into the restart file on the prior run by `set_file`.
    pub(crate) fn get(&self) -> Option<(u128, u64)> {
        self.restart.as_ref().map(|restart| {
            let restart = restart.lock().unwrap();
            let bucket = restart.get_bucket(self.index);
            (bucket.file_name, bucket.random)
        })
    }
}

impl Debug for RestartableBucket {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:?}",
            &self.restart.as_ref().map(|restart| restart.lock().unwrap())
        )?;
        Ok(())
    }
}

impl Debug for Restart {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let header = self.get_header();
        writeln!(f, "{:?}", header)?;
        write!(
            f,
            "{:?}",
            (0..header.buckets)
                .map(|index| self.get_bucket(index as usize))
                .take(10)
                .collect::<Vec<_>>()
        )?;
        Ok(())
    }
}

impl Restart {
    /// create a new restart file for use next time we restart on this machine
    pub(crate) fn new(config: &BucketMapConfig) -> Option<Restart> {
        let expected_len = Self::expected_len(config.max_buckets);

        let path = config.restart_config_file.as_ref();
        let path = path?;
        _ = remove_file(path);

        let mmap = Self::new_map(path, expected_len as u64).ok()?;

        let mut restart = Restart { mmap };
        let header = restart.get_header_mut();
        header.version = HEADER_VERSION;
        header.buckets = config.max_buckets as u64;
        header.max_search = config.max_search.unwrap_or(MAX_SEARCH_DEFAULT);

        (0..config.max_buckets).for_each(|index| {
            let bucket = restart.get_bucket_mut(index);
            bucket.file_name = 0;
            bucket.random = 0;
        });

        Some(restart)
    }

    /// loads and mmaps restart file if it exists
    /// returns None if the file doesn't exist or is incompatible or corrupt (in obvious ways)
    pub(crate) fn get_restart_file(config: &BucketMapConfig) -> Option<Restart> {
        let path = config.restart_config_file.as_ref()?;
        let metadata = std::fs::metadata(path).ok()?;
        let file_len = metadata.len();

        let expected_len = Self::expected_len(config.max_buckets);
        if expected_len as u64 != file_len {
            // mismatched len, so ignore this file
            return None;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path)
            .ok()?;
        let mmap = unsafe { MmapMut::map_mut(&file).unwrap() };

        let restart = Restart { mmap };
        let header = restart.get_header();
        if header.version != HEADER_VERSION
            || header.buckets != config.max_buckets as u64
            || header.max_search != config.max_search.unwrap_or(MAX_SEARCH_DEFAULT)
        {
            // file doesn't match our current configuration, so we have to restart with fresh buckets
            return None;
        }

        Some(restart)
    }

    /// expected len of file given this many buckets
    fn expected_len(max_buckets: usize) -> usize {
        std::mem::size_of::<Header>() + max_buckets * std::mem::size_of::<OneIndexBucket>()
    }

    /// return all files that matched bucket files in `drives`
    /// matching files will be parsable as u128
    fn get_all_possible_index_files_in_drives(drives: &[PathBuf]) -> HashMap<u128, PathBuf> {
        let mut result = HashMap::default();
        drives.iter().for_each(|drive| {
            if drive.is_dir() {
                let dir = fs::read_dir(drive);
                if let Ok(dir) = dir {
                    for entry in dir.flatten() {
                        if let Some(name) = entry.path().file_name() {
                            if let Some(id) = name.to_str().and_then(|str| str.parse::<u128>().ok())
                            {
                                result.insert(id, entry.path());
                            }
                        }
                    }
                }
            }
        });
        result
    }

    /// get one `RestartableBucket` for each bucket.
    /// If a potentially reusable file exists, then put that file's path in `RestartableBucket` for that bucket.
    /// Delete all files that cannot possibly be re-used.
    pub(crate) fn get_restartable_buckets(
        restart: Option<&Arc<Mutex<Restart>>>,
        drives: &Arc<Vec<PathBuf>>,
        num_buckets: usize,
    ) -> Vec<RestartableBucket> {
        let mut paths = Self::get_all_possible_index_files_in_drives(drives);
        let results = (0..num_buckets)
            .map(|index| {
                let path = restart.and_then(|restart| {
                    let restart = restart.lock().unwrap();
                    let id = restart.get_bucket(index).file_name;
                    paths.remove(&id)
                });
                RestartableBucket {
                    restart: restart.map(Arc::clone),
                    index,
                    path,
                }
            })
            .collect();

        paths.into_iter().for_each(|path| {
            // delete any left over files that we won't be using
            _ = fs::remove_file(path.1);
        });

        results
    }

    /// create mmap from `file`
    fn new_map(file: impl AsRef<Path>, capacity: u64) -> Result<MmapMut, std::io::Error> {
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file)?;

        if capacity > 0 {
            // Theoretical performance optimization: write a zero to the end of
            // the file so that we won't have to resize it later, which may be
            // expensive.
            data.seek(SeekFrom::Start(capacity - 1)).unwrap();
            data.write_all(&[0]).unwrap();
            data.rewind().unwrap();
        }
        data.flush().unwrap();
        Ok(unsafe { MmapMut::map_mut(&data).unwrap() })
    }

    fn get_header(&self) -> &Header {
        let item_slice = &self.mmap[..std::mem::size_of::<Header>()];
        bytemuck::from_bytes(item_slice)
    }

    fn get_header_mut(&mut self) -> &mut Header {
        let bytes = &mut self.mmap[..std::mem::size_of::<Header>()];
        bytemuck::from_bytes_mut(bytes)
    }

    fn get_bucket(&self, index: usize) -> &OneIndexBucket {
        let record_len = std::mem::size_of::<OneIndexBucket>();
        let start = std::mem::size_of::<Header>() + record_len * index;
        let end = start + record_len;
        let item_slice: &[u8] = &self.mmap[start..end];
        bytemuck::from_bytes(item_slice)
    }

    fn get_bucket_mut(&mut self, index: usize) -> &mut OneIndexBucket {
        let record_len = std::mem::size_of::<OneIndexBucket>();
        let start = std::mem::size_of::<Header>() + record_len * index;
        let end = start + record_len;
        let item_slice: &mut [u8] = &mut self.mmap[start..end];
        bytemuck::from_bytes_mut(item_slice)
    }
}
