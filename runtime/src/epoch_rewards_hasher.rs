use {
    crate::bank::StakeRewards,
    siphasher::sip::SipHasher13,
    solana_sdk::{hash::Hash, pubkey::Pubkey},
    std::hash::Hasher,
};

#[derive(Debug, Clone)]
pub(crate) struct EpochRewardsHasher {
    hasher: SipHasher13,
    partitions: usize,
}

impl EpochRewardsHasher {
    /// Use SipHasher13 keyed on the `seed` for calculating epoch reward partition
    pub(crate) fn new(partitions: usize, seed: &Hash) -> Self {
        let mut hasher = SipHasher13::new();
        hasher.write(seed.as_ref());
        Self { hasher, partitions }
    }

    /// Return partition index (0..partitions) by hashing `address` with the `hasher`
    pub(crate) fn hash_address_to_partition(self, address: &Pubkey) -> usize {
        let Self {
            mut hasher,
            partitions,
        } = self;
        hasher.write(address.as_ref());
        let hash64 = hasher.finish();

        hash_to_partition(hash64, partitions)
    }
}

/// Compute the partition index by modulo the address hash to number of partitions w.o bias.
/// (rand_int * DESIRED_RANGE_MAX) / (RAND_MAX + 1)
fn hash_to_partition(hash: u64, partitions: usize) -> usize {
    ((partitions as u128)
        .saturating_mul(u128::from(hash))
        .saturating_div(u128::from(u64::MAX).saturating_add(1))) as usize
}

pub(crate) fn hash_rewards_into_partitions(
    stake_rewards: StakeRewards,
    parent_blockhash: &Hash,
    num_partitions: usize,
) -> Vec<StakeRewards> {
    let hasher = EpochRewardsHasher::new(num_partitions, parent_blockhash);
    let mut rewards = vec![vec![]; num_partitions];

    for reward in stake_rewards {
        // clone here so the hasher's state is re-used on each call to `hash_address_to_partition`.
        // This prevents us from re-hashing the seed each time.
        // The clone is explicit (as opposed to an implicit copy) so it is clear this is intended.
        let partition_index = hasher
            .clone()
            .hash_address_to_partition(&reward.stake_pubkey);
        rewards[partition_index].push(reward);
    }
    rewards
}
