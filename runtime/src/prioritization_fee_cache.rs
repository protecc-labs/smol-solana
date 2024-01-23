use {
    crate::{
        bank::Bank, prioritization_fee::*,
        transaction_priority_details::GetTransactionPriorityDetails,
    },
    crossbeam_channel::{unbounded, Receiver, Sender},
    dashmap::DashMap,
    log::*,
    lru::LruCache,
    solana_measure::measure,
    solana_sdk::{
        clock::{BankId, Slot},
        pubkey::Pubkey,
        transaction::SanitizedTransaction,
    },
    std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, RwLock,
        },
        thread::{Builder, JoinHandle},
    },
};

/// The maximum number of blocks to keep in `PrioritizationFeeCache`, ie.
/// the amount of history generally desired to estimate the prioritization fee needed to
/// land a transaction in the current block.
const MAX_NUM_RECENT_BLOCKS: u64 = 150;

#[derive(Debug, Default)]
struct PrioritizationFeeCacheMetrics {
    // Count of transactions that successfully updated each slot's prioritization fee cache.
    successful_transaction_update_count: AtomicU64,

    // Count of duplicated banks being purged
    purged_duplicated_bank_count: AtomicU64,

    // Accumulated time spent on tracking prioritization fee for each slot.
    total_update_elapsed_us: AtomicU64,

    // Accumulated time spent on acquiring cache write lock.
    total_cache_lock_elapsed_us: AtomicU64,

    // Accumulated time spent on updating block prioritization fees.
    total_entry_update_elapsed_us: AtomicU64,

    // Accumulated time spent on finalizing block prioritization fees.
    total_block_finalize_elapsed_us: AtomicU64,
}

impl PrioritizationFeeCacheMetrics {
    fn accumulate_successful_transaction_update_count(&self, val: u64) {
        self.successful_transaction_update_count
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_purged_duplicated_bank_count(&self, val: u64) {
        self.purged_duplicated_bank_count
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_update_elapsed_us(&self, val: u64) {
        self.total_update_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_cache_lock_elapsed_us(&self, val: u64) {
        self.total_cache_lock_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_entry_update_elapsed_us(&self, val: u64) {
        self.total_entry_update_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn accumulate_total_block_finalize_elapsed_us(&self, val: u64) {
        self.total_block_finalize_elapsed_us
            .fetch_add(val, Ordering::Relaxed);
    }

    fn report(&self, slot: Slot) {
        datapoint_info!(
            "block_prioritization_fee_counters",
            ("slot", slot as i64, i64),
            (
                "successful_transaction_update_count",
                self.successful_transaction_update_count
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "purged_duplicated_bank_count",
                self.purged_duplicated_bank_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_update_elapsed_us",
                self.total_update_elapsed_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_cache_lock_elapsed_us",
                self.total_cache_lock_elapsed_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_entry_update_elapsed_us",
                self.total_entry_update_elapsed_us
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_block_finalize_elapsed_us",
                self.total_block_finalize_elapsed_us
                    .swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );
    }
}

enum CacheServiceUpdate {
    TransactionUpdate {
        slot: Slot,
        bank_id: BankId,
        transaction_fee: u64,
        writable_accounts: Arc<Vec<Pubkey>>,
    },
    BankFinalized {
        slot: Slot,
        bank_id: BankId,
    },
    Exit,
}

/// Potentially there are more than one bank that updates Prioritization Fee
/// for a slot. The updates are tracked and finalized by bank_id.
type SlotPrioritizationFee = DashMap<BankId, PrioritizationFee>;

/// Stores up to MAX_NUM_RECENT_BLOCKS recent block's prioritization fee,
/// A separate internal thread `service_thread` handles additional tasks when a bank is frozen,
/// and collecting stats and reporting metrics.
#[derive(Debug)]
pub struct PrioritizationFeeCache {
    cache: Arc<RwLock<LruCache<Slot, Arc<SlotPrioritizationFee>>>>,
    service_thread: Option<JoinHandle<()>>,
    sender: Sender<CacheServiceUpdate>,
    metrics: Arc<PrioritizationFeeCacheMetrics>,
}

impl Default for PrioritizationFeeCache {
    fn default() -> Self {
        Self::new(MAX_NUM_RECENT_BLOCKS)
    }
}

impl Drop for PrioritizationFeeCache {
    fn drop(&mut self) {
        let _ = self.sender.send(CacheServiceUpdate::Exit);
        self.service_thread
            .take()
            .unwrap()
            .join()
            .expect("Prioritization fee cache servicing thread failed to join");
    }
}

impl PrioritizationFeeCache {
    pub fn new(capacity: u64) -> Self {
        let metrics = Arc::new(PrioritizationFeeCacheMetrics::default());
        let (sender, receiver) = unbounded();
        let cache = Arc::new(RwLock::new(LruCache::new(capacity as usize)));

        let cache_clone = cache.clone();
        let metrics_clone = metrics.clone();
        let service_thread = Some(
            Builder::new()
                .name("solPrFeeCachSvc".to_string())
                .spawn(move || {
                    Self::service_loop(cache_clone, receiver, metrics_clone);
                })
                .unwrap(),
        );

        PrioritizationFeeCache {
            cache,
            service_thread,
            sender,
            metrics,
        }
    }

    /// Get prioritization fee entry, create new entry if necessary
    fn get_prioritization_fee(
        cache: Arc<RwLock<LruCache<Slot, Arc<SlotPrioritizationFee>>>>,
        slot: &Slot,
    ) -> Arc<SlotPrioritizationFee> {
        let mut cache = cache.write().unwrap();
        match cache.get(slot) {
            Some(entry) => Arc::clone(entry),
            None => {
                let entry = Arc::new(SlotPrioritizationFee::default());
                cache.put(*slot, Arc::clone(&entry));
                entry
            }
        }
    }

    /// Update with a list of non-vote transactions' tx_priority_details and tx_account_locks; Only
    /// transactions have both valid priority_detail and account_locks will be used to update
    /// fee_cache asynchronously.
    pub fn update<'a>(&self, bank: &Bank, txs: impl Iterator<Item = &'a SanitizedTransaction>) {
        let (_, send_updates_time) = measure!(
            {
                for sanitized_transaction in txs {
                    // Vote transactions are not prioritized, therefore they are excluded from
                    // updating fee_cache.
                    if sanitized_transaction.is_simple_vote_transaction() {
                        continue;
                    }

                    let round_compute_unit_price_enabled = false; // TODO: bank.feture_set.is_active(round_compute_unit_price)
                    let priority_details = sanitized_transaction
                        .get_transaction_priority_details(round_compute_unit_price_enabled);
                    let account_locks = sanitized_transaction
                        .get_account_locks(bank.get_transaction_account_lock_limit());

                    if priority_details.is_none() || account_locks.is_err() {
                        continue;
                    }
                    let priority_details = priority_details.unwrap();

                    // filter out any transaction that requests zero compute_unit_limit
                    // since its priority fee amount is not instructive
                    if priority_details.compute_unit_limit == 0 {
                        continue;
                    }

                    let writable_accounts = Arc::new(
                        account_locks
                            .unwrap()
                            .writable
                            .iter()
                            .map(|key| **key)
                            .collect::<Vec<_>>(),
                    );

                    self.sender
                        .send(CacheServiceUpdate::TransactionUpdate {
                            slot: bank.slot(),
                            bank_id: bank.bank_id(),
                            transaction_fee: priority_details.priority,
                            writable_accounts,
                        })
                        .unwrap_or_else(|err| {
                            warn!(
                                "prioritization fee cache transaction updates failed: {:?}",
                                err
                            );
                        });
                }
            },
            "send_updates",
        );

        self.metrics
            .accumulate_total_update_elapsed_us(send_updates_time.as_us());
    }

    /// Finalize prioritization fee when it's bank is completely replayed from blockstore,
    /// by pruning irrelevant accounts to save space, and marking its availability for queries.
    pub fn finalize_priority_fee(&self, slot: Slot, bank_id: BankId) {
        self.sender
            .send(CacheServiceUpdate::BankFinalized { slot, bank_id })
            .unwrap_or_else(|err| {
                warn!(
                    "prioritization fee cache signalling bank frozen failed: {:?}",
                    err
                )
            });
    }

    /// Internal function is invoked by worker thread to update slot's minimum prioritization fee,
    /// Cache lock contends here.
    fn update_cache(
        cache: Arc<RwLock<LruCache<Slot, Arc<SlotPrioritizationFee>>>>,
        slot: &Slot,
        bank_id: &BankId,
        transaction_fee: u64,
        writable_accounts: Arc<Vec<Pubkey>>,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        let (slot_prioritization_fee, cache_lock_time) =
            measure!(Self::get_prioritization_fee(cache, slot), "cache_lock_time");

        let (_, entry_update_time) = measure!(
            {
                let mut block_prioritization_fee = slot_prioritization_fee
                    .entry(*bank_id)
                    .or_insert(PrioritizationFee::default());
                block_prioritization_fee.update(transaction_fee, &writable_accounts)
            },
            "entry_update_time"
        );
        metrics.accumulate_total_cache_lock_elapsed_us(cache_lock_time.as_us());
        metrics.accumulate_total_entry_update_elapsed_us(entry_update_time.as_us());
        metrics.accumulate_successful_transaction_update_count(1);
    }

    fn finalize_slot(
        cache: Arc<RwLock<LruCache<Slot, Arc<SlotPrioritizationFee>>>>,
        slot: &Slot,
        bank_id: &BankId,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        let (slot_prioritization_fee, cache_lock_time) =
            measure!(Self::get_prioritization_fee(cache, slot), "cache_lock_time");

        // prune cache by evicting write account entry from prioritization fee if its fee is less
        // or equal to block's minimum transaction fee, because they are irrelevant in calculating
        // block minimum fee.
        let (result, slot_finalize_time) = measure!(
            {
                // Only retain priority fee reported from optimistically confirmed bank
                let pre_purge_bank_count = slot_prioritization_fee.len() as u64;
                slot_prioritization_fee.retain(|id, _| id == bank_id);
                let post_purge_bank_count = slot_prioritization_fee.len() as u64;
                metrics.accumulate_total_purged_duplicated_bank_count(
                    pre_purge_bank_count.saturating_sub(post_purge_bank_count),
                );
                // It should be rare that optimistically confirmed bank had no prioritized
                // transactions, but duplicated and unconfirmed bank had.
                if pre_purge_bank_count > 0 && post_purge_bank_count == 0 {
                    warn!("Finalized bank has empty prioritization fee cache. slot {slot} bank id {bank_id}");
                }

                let mut block_prioritization_fee = slot_prioritization_fee
                    .entry(*bank_id)
                    .or_insert(PrioritizationFee::default());
                let result = block_prioritization_fee.mark_block_completed();
                block_prioritization_fee.report_metrics(*slot);
                result
            },
            "slot_finalize_time"
        );
        metrics.accumulate_total_cache_lock_elapsed_us(cache_lock_time.as_us());
        metrics.accumulate_total_block_finalize_elapsed_us(slot_finalize_time.as_us());

        if let Err(err) = result {
            error!(
                "Unsuccessful finalizing slot {slot}, bank ID {bank_id}: {:?}",
                err
            );
        }
    }

    fn service_loop(
        cache: Arc<RwLock<LruCache<Slot, Arc<SlotPrioritizationFee>>>>,
        receiver: Receiver<CacheServiceUpdate>,
        metrics: Arc<PrioritizationFeeCacheMetrics>,
    ) {
        for update in receiver.iter() {
            match update {
                CacheServiceUpdate::TransactionUpdate {
                    slot,
                    bank_id,
                    transaction_fee,
                    writable_accounts,
                } => Self::update_cache(
                    cache.clone(),
                    &slot,
                    &bank_id,
                    transaction_fee,
                    writable_accounts,
                    metrics.clone(),
                ),
                CacheServiceUpdate::BankFinalized { slot, bank_id } => {
                    Self::finalize_slot(cache.clone(), &slot, &bank_id, metrics.clone());

                    metrics.report(slot);
                }
                CacheServiceUpdate::Exit => {
                    break;
                }
            }
        }
    }

    /// Returns number of blocks that have finalized minimum fees collection
    pub fn available_block_count(&self) -> usize {
        self.cache
            .read()
            .unwrap()
            .iter()
            .filter(|(_slot, slot_prioritization_fee)| {
                slot_prioritization_fee
                    .iter()
                    .any(|prioritization_fee| prioritization_fee.is_finalized())
            })
            .count()
    }

    pub fn get_prioritization_fees(&self, account_keys: &[Pubkey]) -> HashMap<Slot, u64> {
        self.cache
            .read()
            .unwrap()
            .iter()
            .filter_map(|(slot, slot_prioritization_fee)| {
                slot_prioritization_fee
                    .iter()
                    .find_map(|prioritization_fee| {
                        prioritization_fee.is_finalized().then(|| {
                            let mut fee = prioritization_fee
                                .get_min_transaction_fee()
                                .unwrap_or_default();
                            for account_key in account_keys {
                                if let Some(account_fee) =
                                    prioritization_fee.get_writable_account_fee(account_key)
                                {
                                    fee = std::cmp::max(fee, account_fee);
                                }
                            }
                            Some((*slot, fee))
                        })
                    })
            })
            .flatten()
            .collect()
    }
}
