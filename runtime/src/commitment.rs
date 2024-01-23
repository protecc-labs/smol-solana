use {
    solana_sdk::{clock::Slot, commitment_config::CommitmentLevel},
    solana_vote_program::vote_state::MAX_LOCKOUT_HISTORY,
    std::collections::HashMap,
};

pub const VOTE_THRESHOLD_SIZE: f64 = 2f64 / 3f64;

pub type BlockCommitmentArray = [u64; MAX_LOCKOUT_HISTORY + 1];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockCommitment {
    pub commitment: BlockCommitmentArray,
}

impl BlockCommitment {
    pub fn increase_confirmation_stake(&mut self, confirmation_count: usize, stake: u64) {
        assert!(confirmation_count > 0 && confirmation_count <= MAX_LOCKOUT_HISTORY);
        self.commitment[confirmation_count - 1] += stake;
    }

    pub fn get_confirmation_stake(&mut self, confirmation_count: usize) -> u64 {
        assert!(confirmation_count > 0 && confirmation_count <= MAX_LOCKOUT_HISTORY);
        self.commitment[confirmation_count - 1]
    }

    pub fn increase_rooted_stake(&mut self, stake: u64) {
        self.commitment[MAX_LOCKOUT_HISTORY] += stake;
    }

    pub fn get_rooted_stake(&self) -> u64 {
        self.commitment[MAX_LOCKOUT_HISTORY]
    }

    pub fn new(commitment: BlockCommitmentArray) -> Self {
        Self { commitment }
    }
}

/// A node's view of cluster commitment as per a particular bank
#[derive(Default)]
pub struct BlockCommitmentCache {
    /// Map of all commitment levels of current ancestor slots, aggregated from the vote account
    /// data in the bank
    block_commitment: HashMap<Slot, BlockCommitment>,
    /// Cache slot details. Cluster data is calculated from the block_commitment map, and cached in
    /// the struct to avoid the expense of recalculating on every call.
    commitment_slots: CommitmentSlots,
    /// Total stake active during the bank's epoch
    total_stake: u64,
}

impl std::fmt::Debug for BlockCommitmentCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockCommitmentCache")
            .field("block_commitment", &self.block_commitment)
            .field("total_stake", &self.total_stake)
            .field(
                "bank",
                &format_args!("Bank({{current_slot: {:?}}})", self.commitment_slots.slot),
            )
            .field("root", &self.commitment_slots.root)
            .finish()
    }
}

impl BlockCommitmentCache {
    pub fn new(
        block_commitment: HashMap<Slot, BlockCommitment>,
        total_stake: u64,
        commitment_slots: CommitmentSlots,
    ) -> Self {
        Self {
            block_commitment,
            commitment_slots,
            total_stake,
        }
    }

    pub fn get_block_commitment(&self, slot: Slot) -> Option<&BlockCommitment> {
        self.block_commitment.get(&slot)
    }

    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    pub fn slot(&self) -> Slot {
        self.commitment_slots.slot
    }

    pub fn root(&self) -> Slot {
        self.commitment_slots.root
    }

    pub fn highest_confirmed_slot(&self) -> Slot {
        self.commitment_slots.highest_confirmed_slot
    }

    pub fn highest_super_majority_root(&self) -> Slot {
        self.commitment_slots.highest_super_majority_root
    }

    pub fn commitment_slots(&self) -> CommitmentSlots {
        self.commitment_slots
    }

    pub fn highest_gossip_confirmed_slot(&self) -> Slot {
        // TODO: combine bank caches
        // Currently, this information is provided by OptimisticallyConfirmedBank::bank.slot()
        self.highest_confirmed_slot()
    }

    #[allow(deprecated)]
    pub fn slot_with_commitment(&self, commitment_level: CommitmentLevel) -> Slot {
        match commitment_level {
            CommitmentLevel::Recent | CommitmentLevel::Processed => self.slot(),
            CommitmentLevel::Root => self.root(),
            CommitmentLevel::Single => self.highest_confirmed_slot(),
            CommitmentLevel::SingleGossip | CommitmentLevel::Confirmed => {
                self.highest_gossip_confirmed_slot()
            }
            CommitmentLevel::Max | CommitmentLevel::Finalized => self.highest_super_majority_root(),
        }
    }

    fn highest_slot_with_confirmation_count(&self, confirmation_count: usize) -> Slot {
        assert!(confirmation_count > 0 && confirmation_count <= MAX_LOCKOUT_HISTORY);
        for slot in (self.root()..self.slot()).rev() {
            if let Some(count) = self.get_confirmation_count(slot) {
                if count >= confirmation_count {
                    return slot;
                }
            }
        }
        self.commitment_slots.root
    }

    pub fn calculate_highest_confirmed_slot(&self) -> Slot {
        self.highest_slot_with_confirmation_count(1)
    }

    pub fn get_confirmation_count(&self, slot: Slot) -> Option<usize> {
        self.get_lockout_count(slot, VOTE_THRESHOLD_SIZE)
    }

    // Returns the lowest level at which at least `minimum_stake_percentage` of the total epoch
    // stake is locked out
    fn get_lockout_count(&self, slot: Slot, minimum_stake_percentage: f64) -> Option<usize> {
        self.get_block_commitment(slot).map(|block_commitment| {
            let iterator = block_commitment.commitment.iter().enumerate().rev();
            let mut sum = 0;
            for (i, stake) in iterator {
                sum += stake;
                if (sum as f64 / self.total_stake as f64) > minimum_stake_percentage {
                    return i + 1;
                }
            }
            0
        })
    }

    pub fn new_for_tests() -> Self {
        let mut block_commitment: HashMap<Slot, BlockCommitment> = HashMap::new();
        block_commitment.insert(0, BlockCommitment::default());
        Self {
            block_commitment,
            total_stake: 42,
            ..Self::default()
        }
    }

    pub fn new_for_tests_with_slots(slot: Slot, root: Slot) -> Self {
        let mut block_commitment: HashMap<Slot, BlockCommitment> = HashMap::new();
        block_commitment.insert(0, BlockCommitment::default());
        Self {
            block_commitment,
            total_stake: 42,
            commitment_slots: CommitmentSlots {
                slot,
                root,
                highest_confirmed_slot: root,
                highest_super_majority_root: root,
            },
        }
    }

    pub fn set_highest_confirmed_slot(&mut self, slot: Slot) {
        self.commitment_slots.highest_confirmed_slot = slot;
    }

    pub fn set_highest_super_majority_root(&mut self, root: Slot) {
        self.commitment_slots.highest_super_majority_root = root;
    }

    pub fn initialize_slots(&mut self, slot: Slot, root: Slot) {
        self.commitment_slots.slot = slot;
        self.commitment_slots.root = root;
    }

    pub fn set_all_slots(&mut self, slot: Slot, root: Slot) {
        self.commitment_slots.slot = slot;
        self.commitment_slots.highest_confirmed_slot = slot;
        self.commitment_slots.root = root;
        self.commitment_slots.highest_super_majority_root = root;
    }
}

#[derive(Default, Clone, Copy)]
pub struct CommitmentSlots {
    /// The slot of the bank from which all other slots were calculated.
    pub slot: Slot,
    /// The current node root
    pub root: Slot,
    /// Highest cluster-confirmed slot
    pub highest_confirmed_slot: Slot,
    /// Highest slot rooted by a super majority of the cluster
    pub highest_super_majority_root: Slot,
}

impl CommitmentSlots {
    pub fn new_from_slot(slot: Slot) -> Self {
        Self {
            slot,
            ..Self::default()
        }
    }
}
