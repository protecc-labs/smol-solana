//! The `bank_forks` module implements BankForks a DAG of checkpointed Banks

use {
    crate::{
        accounts_background_service::{AbsRequestSender, SnapshotRequest, SnapshotRequestKind},
        bank::{epoch_accounts_hash_utils, Bank, SquashTiming},
        installed_scheduler_pool::{
            BankWithScheduler, InstalledSchedulerPoolArc, SchedulingContext,
        },
        snapshot_config::SnapshotConfig,
    },
    log::*,
    solana_measure::measure::Measure,
    solana_program_runtime::loaded_programs::{BlockRelation, ForkGraph},
    solana_sdk::{
        clock::{Epoch, Slot},
        hash::Hash,
        timing,
    },
    std::{
        collections::{hash_map::Entry, HashMap, HashSet},
        ops::Index,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
        time::Instant,
    },
};

pub const MAX_ROOT_DISTANCE_FOR_VOTE_ONLY: Slot = 400;
pub type AtomicSlot = AtomicU64;
pub struct ReadOnlyAtomicSlot {
    slot: Arc<AtomicSlot>,
}

impl ReadOnlyAtomicSlot {
    pub fn get(&self) -> Slot {
        // The expectation is that an instance `ReadOnlyAtomicSlot` is on a different thread than
        // BankForks *and* this instance is being accessed *without* locking BankForks first.
        // Thus, to ensure atomic ordering correctness, we must use Acquire-Release semantics.
        self.slot.load(Ordering::Acquire)
    }
}

#[derive(Debug, Default, Copy, Clone)]
struct SetRootMetrics {
    timings: SetRootTimings,
    total_parent_banks: i64,
    tx_count: i64,
    dropped_banks_len: i64,
    accounts_data_len: i64,
}

#[derive(Debug, Default, Copy, Clone)]
struct SetRootTimings {
    total_squash_time: SquashTiming,
    total_snapshot_ms: i64,
    prune_non_rooted_ms: i64,
    drop_parent_banks_ms: i64,
    prune_slots_ms: i64,
    prune_remove_ms: i64,
}

pub struct BankForks {
    banks: HashMap<Slot, BankWithScheduler>,
    descendants: HashMap<Slot, HashSet<Slot>>,
    root: Arc<AtomicSlot>,

    pub snapshot_config: Option<SnapshotConfig>,

    pub accounts_hash_interval_slots: Slot,
    last_accounts_hash_slot: Slot,
    in_vote_only_mode: Arc<AtomicBool>,
    highest_slot_at_startup: Slot,
    scheduler_pool: Option<InstalledSchedulerPoolArc>,
}

impl Index<u64> for BankForks {
    type Output = Arc<Bank>;
    fn index(&self, bank_slot: Slot) -> &Self::Output {
        &self.banks[&bank_slot]
    }
}

impl BankForks {
    pub fn new_rw_arc(root_bank: Bank) -> Arc<RwLock<Self>> {
        let root_bank = Arc::new(root_bank);
        let root_slot = root_bank.slot();

        let mut banks = HashMap::new();
        banks.insert(
            root_slot,
            BankWithScheduler::new_without_scheduler(root_bank.clone()),
        );

        let parents = root_bank.parents();
        for parent in parents {
            if banks
                .insert(
                    parent.slot(),
                    BankWithScheduler::new_without_scheduler(parent.clone()),
                )
                .is_some()
            {
                // All ancestors have already been inserted by another fork
                break;
            }
        }

        let mut descendants = HashMap::<_, HashSet<_>>::new();
        descendants.entry(root_slot).or_default();
        for parent in root_bank.proper_ancestors() {
            descendants.entry(parent).or_default().insert(root_slot);
        }

        let bank_forks = Arc::new(RwLock::new(Self {
            root: Arc::new(AtomicSlot::new(root_slot)),
            banks,
            descendants,
            snapshot_config: None,
            accounts_hash_interval_slots: std::u64::MAX,
            last_accounts_hash_slot: root_slot,
            in_vote_only_mode: Arc::new(AtomicBool::new(false)),
            highest_slot_at_startup: 0,
            scheduler_pool: None,
        }));

        root_bank
            .loaded_programs_cache
            .write()
            .unwrap()
            .set_fork_graph(bank_forks.clone());

        bank_forks
    }

    pub fn banks(&self) -> &HashMap<Slot, BankWithScheduler> {
        &self.banks
    }

    pub fn get_vote_only_mode_signal(&self) -> Arc<AtomicBool> {
        self.in_vote_only_mode.clone()
    }

    pub fn len(&self) -> usize {
        self.banks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.banks.is_empty()
    }

    /// Create a map of bank slot id to the set of ancestors for the bank slot.
    pub fn ancestors(&self) -> HashMap<Slot, HashSet<Slot>> {
        let root = self.root();
        self.banks
            .iter()
            .map(|(slot, bank)| {
                let ancestors = bank.proper_ancestors().filter(|k| *k >= root);
                (*slot, ancestors.collect())
            })
            .collect()
    }

    /// Create a map of bank slot id to the set of all of its descendants
    pub fn descendants(&self) -> HashMap<Slot, HashSet<Slot>> {
        self.descendants.clone()
    }

    pub fn frozen_banks(&self) -> HashMap<Slot, Arc<Bank>> {
        self.banks
            .iter()
            .filter(|(_, b)| b.is_frozen())
            .map(|(&k, b)| (k, b.clone_without_scheduler()))
            .collect()
    }

    pub fn active_bank_slots(&self) -> Vec<Slot> {
        self.banks
            .iter()
            .filter(|(_, v)| !v.is_frozen())
            .map(|(k, _v)| *k)
            .collect()
    }

    pub fn get_with_scheduler(&self, bank_slot: Slot) -> Option<BankWithScheduler> {
        self.banks.get(&bank_slot).map(|b| b.clone_with_scheduler())
    }

    pub fn get(&self, bank_slot: Slot) -> Option<Arc<Bank>> {
        self.get_with_scheduler(bank_slot)
            .map(|b| b.clone_without_scheduler())
    }

    pub fn get_with_checked_hash(
        &self,
        (bank_slot, expected_hash): (Slot, Hash),
    ) -> Option<Arc<Bank>> {
        let maybe_bank = self.get(bank_slot);
        if let Some(bank) = &maybe_bank {
            assert_eq!(bank.hash(), expected_hash);
        }
        maybe_bank
    }

    pub fn bank_hash(&self, slot: Slot) -> Option<Hash> {
        self.get(slot).map(|bank| bank.hash())
    }

    pub fn root_bank(&self) -> Arc<Bank> {
        self[self.root()].clone()
    }

    pub fn install_scheduler_pool(&mut self, pool: InstalledSchedulerPoolArc) {
        info!("Installed new scheduler_pool into bank_forks: {:?}", pool);
        assert!(
            self.scheduler_pool.replace(pool).is_none(),
            "Reinstalling scheduler pool isn't supported"
        );
    }

    pub fn insert(&mut self, mut bank: Bank) -> BankWithScheduler {
        bank.check_program_modification_slot =
            self.root.load(Ordering::Relaxed) < self.highest_slot_at_startup;

        let bank = Arc::new(bank);
        let bank = if let Some(scheduler_pool) = &self.scheduler_pool {
            let context = SchedulingContext::new(bank.clone());
            let scheduler = scheduler_pool.take_scheduler(context);
            BankWithScheduler::new(bank, Some(scheduler))
        } else {
            BankWithScheduler::new_without_scheduler(bank)
        };
        let prev = self.banks.insert(bank.slot(), bank.clone_with_scheduler());
        assert!(prev.is_none());
        let slot = bank.slot();
        self.descendants.entry(slot).or_default();
        for parent in bank.proper_ancestors() {
            self.descendants.entry(parent).or_default().insert(slot);
        }
        bank
    }

    pub fn insert_from_ledger(&mut self, bank: Bank) -> BankWithScheduler {
        self.highest_slot_at_startup = std::cmp::max(self.highest_slot_at_startup, bank.slot());
        self.insert(bank)
    }

    pub fn remove(&mut self, slot: Slot) -> Option<Arc<Bank>> {
        let bank = self.banks.remove(&slot)?;
        for parent in bank.proper_ancestors() {
            let Entry::Occupied(mut entry) = self.descendants.entry(parent) else {
                panic!("this should not happen!");
            };
            entry.get_mut().remove(&slot);
            if entry.get().is_empty() && !self.banks.contains_key(&parent) {
                entry.remove_entry();
            }
        }
        let Entry::Occupied(entry) = self.descendants.entry(slot) else {
            panic!("this should not happen!");
        };
        if entry.get().is_empty() {
            entry.remove_entry();
        }
        Some(bank.clone_without_scheduler())
    }

    pub fn highest_slot(&self) -> Slot {
        self.banks.values().map(|bank| bank.slot()).max().unwrap()
    }

    pub fn working_bank(&self) -> Arc<Bank> {
        self[self.highest_slot()].clone()
    }

    pub fn working_bank_with_scheduler(&self) -> &BankWithScheduler {
        &self.banks[&self.highest_slot()]
    }

    fn do_set_root_return_metrics(
        &mut self,
        root: Slot,
        accounts_background_request_sender: &AbsRequestSender,
        highest_super_majority_root: Option<Slot>,
    ) -> (Vec<Arc<Bank>>, SetRootMetrics) {
        let old_epoch = self.root_bank().epoch();
        // To support `RootBankCache` (via `ReadOnlyAtomicSlot`) accessing `root` *without* locking
        // BankForks first *and* from a different thread, this store *must* be at least Release to
        // ensure atomic ordering correctness.
        self.root.store(root, Ordering::Release);

        let root_bank = &self
            .get(root)
            .expect("root bank didn't exist in bank_forks");
        let new_epoch = root_bank.epoch();
        if old_epoch != new_epoch {
            info!(
                "Root entering
                    epoch: {},
                    next_epoch_start_slot: {},
                    epoch_stakes: {:#?}",
                new_epoch,
                root_bank
                    .epoch_schedule()
                    .get_first_slot_in_epoch(new_epoch + 1),
                root_bank
                    .epoch_stakes(new_epoch)
                    .unwrap()
                    .node_id_to_vote_accounts()
            );
        }
        let root_tx_count = root_bank
            .parents()
            .last()
            .map(|bank| bank.transaction_count())
            .unwrap_or(0);
        // Calculate the accounts hash at a fixed interval
        let mut is_root_bank_squashed = false;
        let mut banks = vec![root_bank];
        let parents = root_bank.parents();
        banks.extend(parents.iter());
        let total_parent_banks = banks.len();
        let mut squash_timing = SquashTiming::default();
        let mut total_snapshot_ms = 0;

        // handle epoch accounts hash
        // go through all the banks, oldest first
        // find the newest bank where we should do EAH
        // NOTE: Instead of filter-collect-assert, `.find()` could be used instead.  Once
        // sufficient testing guarantees only one bank will ever request an EAH, change to
        // `.find()`.
        let eah_banks: Vec<_> = banks
            .iter()
            .filter(|&&bank| self.should_request_epoch_accounts_hash(bank))
            .collect();
        assert!(
            eah_banks.len() <= 1,
            "At most one bank should request an epoch accounts hash calculation! num banks: {}, bank slots: {:?}",
            eah_banks.len(),
            eah_banks.iter().map(|bank| bank.slot()).collect::<Vec<_>>(),
        );
        if let Some(eah_bank) = eah_banks.first() {
            debug!(
                "sending epoch accounts hash request, slot: {}",
                eah_bank.slot()
            );

            self.last_accounts_hash_slot = eah_bank.slot();
            squash_timing += eah_bank.squash();
            is_root_bank_squashed = eah_bank.slot() == root;

            eah_bank
                .rc
                .accounts
                .accounts_db
                .epoch_accounts_hash_manager
                .set_in_flight(eah_bank.slot());
            accounts_background_request_sender
                .send_snapshot_request(SnapshotRequest {
                    snapshot_root_bank: Arc::clone(eah_bank),
                    status_cache_slot_deltas: Vec::default(),
                    request_kind: SnapshotRequestKind::EpochAccountsHash,
                    enqueued: Instant::now(),
                })
                .expect("send epoch accounts hash request");
        }
        drop(eah_banks);

        // After checking for EAH requests, also check for regular snapshot requests.
        //
        // This is needed when a snapshot request occurs in a slot after an EAH request, and is
        // part of the same set of `banks` in a single `set_root()` invocation.  While (very)
        // unlikely for a validator with default snapshot intervals (and accounts hash verifier
        // intervals), it *is* possible, and there are tests to exercise this possibility.
        if let Some(bank) = banks.iter().find(|bank| {
            bank.slot() > self.last_accounts_hash_slot
                && bank.block_height() % self.accounts_hash_interval_slots == 0
        }) {
            let bank_slot = bank.slot();
            self.last_accounts_hash_slot = bank_slot;
            squash_timing += bank.squash();

            is_root_bank_squashed = bank_slot == root;

            let mut snapshot_time = Measure::start("squash::snapshot_time");
            if self.snapshot_config.is_some()
                && accounts_background_request_sender.is_snapshot_creation_enabled()
            {
                if bank.is_startup_verification_complete() {
                    // Save off the status cache because these may get pruned if another
                    // `set_root()` is called before the snapshots package can be generated
                    let status_cache_slot_deltas =
                        bank.status_cache.read().unwrap().root_slot_deltas();
                    if let Err(e) =
                        accounts_background_request_sender.send_snapshot_request(SnapshotRequest {
                            snapshot_root_bank: Arc::clone(bank),
                            status_cache_slot_deltas,
                            request_kind: SnapshotRequestKind::Snapshot,
                            enqueued: Instant::now(),
                        })
                    {
                        warn!(
                            "Error sending snapshot request for bank: {}, err: {:?}",
                            bank_slot, e
                        );
                    }
                } else {
                    info!("Not sending snapshot request for bank: {}, startup verification is incomplete", bank_slot);
                }
            }
            snapshot_time.stop();
            total_snapshot_ms += snapshot_time.as_ms() as i64;
        }

        if !is_root_bank_squashed {
            squash_timing += root_bank.squash();
        }
        let new_tx_count = root_bank.transaction_count();
        let accounts_data_len = root_bank.load_accounts_data_size() as i64;
        let mut prune_time = Measure::start("set_root::prune");
        let (removed_banks, prune_slots_ms, prune_remove_ms) =
            self.prune_non_rooted(root, highest_super_majority_root);
        prune_time.stop();
        let dropped_banks_len = removed_banks.len();

        let mut drop_parent_banks_time = Measure::start("set_root::drop_banks");
        drop(parents);
        drop_parent_banks_time.stop();

        (
            removed_banks,
            SetRootMetrics {
                timings: SetRootTimings {
                    total_squash_time: squash_timing,
                    total_snapshot_ms,
                    prune_non_rooted_ms: prune_time.as_ms() as i64,
                    drop_parent_banks_ms: drop_parent_banks_time.as_ms() as i64,
                    prune_slots_ms: prune_slots_ms as i64,
                    prune_remove_ms: prune_remove_ms as i64,
                },
                total_parent_banks: total_parent_banks as i64,
                tx_count: (new_tx_count - root_tx_count) as i64,
                dropped_banks_len: dropped_banks_len as i64,
                accounts_data_len,
            },
        )
    }

    pub fn prune_program_cache(&self, root: Slot) {
        if let Some(root_bank) = self.banks.get(&root) {
            root_bank
                .loaded_programs_cache
                .write()
                .unwrap()
                .prune(root, root_bank.epoch());
        }
    }

    pub fn set_root(
        &mut self,
        root: Slot,
        accounts_background_request_sender: &AbsRequestSender,
        highest_super_majority_root: Option<Slot>,
    ) -> Vec<Arc<Bank>> {
        let program_cache_prune_start = Instant::now();
        let set_root_start = Instant::now();
        let (removed_banks, set_root_metrics) = self.do_set_root_return_metrics(
            root,
            accounts_background_request_sender,
            highest_super_majority_root,
        );
        datapoint_info!(
            "bank-forks_set_root",
            (
                "elapsed_ms",
                timing::duration_as_ms(&set_root_start.elapsed()) as usize,
                i64
            ),
            ("slot", root, i64),
            (
                "total_parent_banks",
                set_root_metrics.total_parent_banks,
                i64
            ),
            ("total_banks", self.banks.len(), i64),
            (
                "total_squash_cache_ms",
                set_root_metrics.timings.total_squash_time.squash_cache_ms,
                i64
            ),
            (
                "total_squash_accounts_ms",
                set_root_metrics
                    .timings
                    .total_squash_time
                    .squash_accounts_ms,
                i64
            ),
            (
                "total_squash_accounts_index_ms",
                set_root_metrics
                    .timings
                    .total_squash_time
                    .squash_accounts_index_ms,
                i64
            ),
            (
                "total_squash_accounts_cache_ms",
                set_root_metrics
                    .timings
                    .total_squash_time
                    .squash_accounts_cache_ms,
                i64
            ),
            (
                "total_squash_accounts_store_ms",
                set_root_metrics
                    .timings
                    .total_squash_time
                    .squash_accounts_store_ms,
                i64
            ),
            (
                "total_snapshot_ms",
                set_root_metrics.timings.total_snapshot_ms,
                i64
            ),
            ("tx_count", set_root_metrics.tx_count, i64),
            (
                "prune_non_rooted_ms",
                set_root_metrics.timings.prune_non_rooted_ms,
                i64
            ),
            (
                "drop_parent_banks_ms",
                set_root_metrics.timings.drop_parent_banks_ms,
                i64
            ),
            (
                "prune_slots_ms",
                set_root_metrics.timings.prune_slots_ms,
                i64
            ),
            (
                "prune_remove_ms",
                set_root_metrics.timings.prune_remove_ms,
                i64
            ),
            (
                "program_cache_prune_ms",
                timing::duration_as_ms(&program_cache_prune_start.elapsed()),
                i64
            ),
            ("dropped_banks_len", set_root_metrics.dropped_banks_len, i64),
            ("accounts_data_len", set_root_metrics.accounts_data_len, i64),
        );
        removed_banks
    }

    pub fn root(&self) -> Slot {
        self.root.load(Ordering::Relaxed)
    }

    /// Gets a read-only wrapper to an atomic slot holding the root slot.
    pub fn get_atomic_root(&self) -> ReadOnlyAtomicSlot {
        ReadOnlyAtomicSlot {
            slot: self.root.clone(),
        }
    }

    /// After setting a new root, prune the banks that are no longer on rooted paths
    ///
    /// Given the following banks and slots...
    ///
    /// ```text
    /// slot 6                   * (G)
    ///                         /
    /// slot 5        (F)  *   /
    ///                    |  /
    /// slot 4    (E) *    | /
    ///               |    |/
    /// slot 3        |    * (D) <-- root, from set_root()
    ///               |    |
    /// slot 2    (C) *    |
    ///                \   |
    /// slot 1          \  * (B)
    ///                  \ |
    /// slot 0             * (A)  <-- highest confirmed root [1]
    /// ```
    ///
    /// ...where (D) is set as root, clean up (C) and (E), since they are not rooted.
    ///
    /// (A) is kept because it is greater-than-or-equal-to the highest confirmed root, and (D) is
    ///     one of its descendants
    /// (B) is kept for the same reason as (A)
    /// (C) is pruned since it is a lower slot than (D), but (D) is _not_ one of its descendants
    /// (D) is kept since it is the root
    /// (E) is pruned since it is not a descendant of (D)
    /// (F) is kept since it is a descendant of (D)
    /// (G) is kept for the same reason as (F)
    ///
    /// and in table form...
    ///
    /// ```text
    ///       |          |  is root a  | is a descendant ||
    ///  slot | is root? | descendant? |    of root?     || keep?
    /// ------+----------+-------------+-----------------++-------
    ///   (A) |     N    |      Y      |        N        ||   Y
    ///   (B) |     N    |      Y      |        N        ||   Y
    ///   (C) |     N    |      N      |        N        ||   N
    ///   (D) |     Y    |      N      |        N        ||   Y
    ///   (E) |     N    |      N      |        N        ||   N
    ///   (F) |     N    |      N      |        Y        ||   Y
    ///   (G) |     N    |      N      |        Y        ||   Y
    /// ```
    ///
    /// [1] RPC has the concept of commitment level, which is based on the highest confirmed root,
    /// i.e. the cluster-confirmed root.  This commitment is stronger than the local node's root.
    /// So (A) and (B) are kept to facilitate RPC at different commitment levels.  Everything below
    /// the highest confirmed root can be pruned.
    fn prune_non_rooted(
        &mut self,
        root: Slot,
        highest_super_majority_root: Option<Slot>,
    ) -> (Vec<Arc<Bank>>, u64, u64) {
        // Clippy doesn't like separating the two collects below,
        // but we want to collect timing separately, and the 2nd requires
        // a unique borrow to self which is already borrowed by self.banks
        #![allow(clippy::needless_collect)]
        let mut prune_slots_time = Measure::start("prune_slots");
        let highest_super_majority_root = highest_super_majority_root.unwrap_or(root);
        let prune_slots: Vec<_> = self
            .banks
            .keys()
            .copied()
            .filter(|slot| {
                let keep = *slot == root
                    || self.descendants[&root].contains(slot)
                    || (*slot < root
                        && *slot >= highest_super_majority_root
                        && self.descendants[slot].contains(&root));
                !keep
            })
            .collect();
        prune_slots_time.stop();

        let mut prune_remove_time = Measure::start("prune_slots");
        let removed_banks = prune_slots
            .into_iter()
            .filter_map(|slot| self.remove(slot))
            .collect();
        prune_remove_time.stop();

        (
            removed_banks,
            prune_slots_time.as_ms(),
            prune_remove_time.as_ms(),
        )
    }

    pub fn set_snapshot_config(&mut self, snapshot_config: Option<SnapshotConfig>) {
        self.snapshot_config = snapshot_config;
    }

    pub fn set_accounts_hash_interval_slots(&mut self, accounts_interval_slots: u64) {
        self.accounts_hash_interval_slots = accounts_interval_slots;
    }

    /// Determine if this bank should request an epoch accounts hash
    #[must_use]
    fn should_request_epoch_accounts_hash(&self, bank: &Bank) -> bool {
        if !epoch_accounts_hash_utils::is_enabled_this_epoch(bank) {
            return false;
        }

        let start_slot = epoch_accounts_hash_utils::calculation_start(bank);
        bank.slot() > self.last_accounts_hash_slot
            && bank.parent_slot() < start_slot
            && bank.slot() >= start_slot
    }
}

impl ForkGraph for BankForks {
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation {
        let known_slot_range = self.root()..=self.highest_slot();
        (known_slot_range.contains(&a) && known_slot_range.contains(&b))
            .then(|| {
                (a == b)
                    .then_some(BlockRelation::Equal)
                    .or_else(|| {
                        self.banks.get(&b).and_then(|bank| {
                            bank.ancestors
                                .contains_key(&a)
                                .then_some(BlockRelation::Ancestor)
                        })
                    })
                    .or_else(|| {
                        self.descendants.get(&b).and_then(|slots| {
                            slots.contains(&a).then_some(BlockRelation::Descendant)
                        })
                    })
                    .unwrap_or(BlockRelation::Unrelated)
            })
            .unwrap_or(BlockRelation::Unknown)
    }

    fn slot_epoch(&self, slot: Slot) -> Option<Epoch> {
        self.banks.get(&slot).map(|bank| bank.epoch())
    }
}
