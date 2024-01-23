#[allow(deprecated)]
use solana_sdk::sysvar::recent_blockhashes;
use {
    serde::{Deserialize, Serialize},
    solana_sdk::{
        clock::MAX_RECENT_BLOCKHASHES, fee_calculator::FeeCalculator, hash::Hash, timing::timestamp,
    },
    std::collections::HashMap,
};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, AbiExample)]
struct HashAge {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,
}

/// Low memory overhead, so can be cloned for every checkpoint
#[frozen_abi(digest = "8upYCMG37Awf4FGQ5kKtZARHP1QfD2GMpQCPnwCCsxhu")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AbiExample)]
pub struct BlockhashQueue {
    /// index of last hash to be registered
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: Option<Hash>,

    ages: HashMap<Hash, HashAge>,

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,
}

impl Default for BlockhashQueue {
    fn default() -> Self {
        Self::new(MAX_RECENT_BLOCKHASHES)
    }
}

impl BlockhashQueue {
    pub fn new(max_age: usize) -> Self {
        Self {
            ages: HashMap::new(),
            last_hash_index: 0,
            last_hash: None,
            max_age,
        }
    }

    pub fn last_hash(&self) -> Hash {
        self.last_hash.expect("no hash has been set")
    }

    pub fn get_lamports_per_signature(&self, hash: &Hash) -> Option<u64> {
        self.ages
            .get(hash)
            .map(|hash_age| hash_age.fee_calculator.lamports_per_signature)
    }

    /// Check if the age of the hash is within the queue's max age
    pub fn is_hash_valid(&self, hash: &Hash) -> bool {
        self.ages.get(hash).is_some()
    }

    /// Check if the age of the hash is within the specified age
    pub fn is_hash_valid_for_age(&self, hash: &Hash, max_age: usize) -> bool {
        self.ages
            .get(hash)
            .map(|age| Self::is_hash_index_valid(self.last_hash_index, max_age, age.hash_index))
            .unwrap_or(false)
    }

    pub fn get_hash_age(&self, hash: &Hash) -> Option<u64> {
        self.ages
            .get(hash)
            .map(|age| self.last_hash_index - age.hash_index)
    }

    pub fn genesis_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.ages.insert(
            *hash,
            HashAge {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_index: 0,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    fn is_hash_index_valid(last_hash_index: u64, max_age: usize, hash_index: u64) -> bool {
        last_hash_index - hash_index <= max_age as u64
    }

    pub fn register_hash(&mut self, hash: &Hash, lamports_per_signature: u64) {
        self.last_hash_index += 1;
        if self.ages.len() >= self.max_age {
            self.ages.retain(|_, age| {
                Self::is_hash_index_valid(self.last_hash_index, self.max_age, age.hash_index)
            });
        }

        self.ages.insert(
            *hash,
            HashAge {
                fee_calculator: FeeCalculator::new(lamports_per_signature),
                hash_index: self.last_hash_index,
                timestamp: timestamp(),
            },
        );

        self.last_hash = Some(*hash);
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    #[allow(deprecated)]
    pub fn get_recent_blockhashes(&self) -> impl Iterator<Item = recent_blockhashes::IterItem> {
        (self.ages).iter().map(|(k, v)| {
            recent_blockhashes::IterItem(v.hash_index, k, v.fee_calculator.lamports_per_signature)
        })
    }

    pub fn get_max_age(&self) -> usize {
        self.max_age
    }
}
