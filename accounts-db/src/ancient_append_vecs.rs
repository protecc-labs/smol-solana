//! helpers for squashing append vecs into ancient append vecs
//! an ancient append vec is:
//! 1. a slot that is older than an epoch old
//! 2. multiple 'slots' squashed into a single older (ie. ancient) slot for convenience and performance
//! Otherwise, an ancient append vec is the same as any other append vec
use {
    crate::{
        account_storage::{meta::StoredAccountMeta, ShrinkInProgress},
        accounts_db::{
            AccountStorageEntry, AccountsDb, AliveAccounts, GetUniqueAccountsResult, ShrinkCollect,
            ShrinkCollectAliveSeparatedByRefs, ShrinkStatsSub, StoreReclaims,
        },
        accounts_file::AccountsFile,
        accounts_hash::AccountHash,
        accounts_index::{AccountsIndexScanResult, ZeroLamport},
        active_stats::ActiveStatItem,
        append_vec::aligned_stored_size,
        storable_accounts::{StorableAccounts, StorableAccountsBySlot},
    },
    rand::{thread_rng, Rng},
    rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
    solana_measure::measure_us,
    solana_sdk::{account::ReadableAccount, clock::Slot, saturating_add_assign},
    std::{
        collections::HashMap,
        num::NonZeroU64,
        sync::{atomic::Ordering, Arc, Mutex},
    },
};

/// ancient packing algorithm tuning per pass
#[derive(Debug)]
struct PackedAncientStorageTuning {
    /// shrink enough of these ancient append vecs to realize this% of the total dead data that needs to be shrunk
    /// Doing too much burns too much time and disk i/o.
    /// Doing too little could cause us to never catch up and have old data accumulate.
    percent_of_alive_shrunk_data: u64,
    /// number of ancient slots we should aim to have. If we have more than this, combine further.
    max_ancient_slots: usize,
    /// # of bytes in an ideal ancient storage size
    ideal_storage_size: NonZeroU64,
    /// true if storages can be randomly shrunk even if they aren't eligible
    can_randomly_shrink: bool,
}

/// info about a storage eligible to be combined into an ancient append vec.
/// Useful to help sort vecs of storages.
#[derive(Debug)]
struct SlotInfo {
    storage: Arc<AccountStorageEntry>,
    /// slot of storage
    slot: Slot,
    /// total capacity of storage
    capacity: u64,
    /// # alive bytes in storage
    alive_bytes: u64,
    /// true if this should be shrunk due to ratio
    should_shrink: bool,
}

/// info for all storages in ancient slots
/// 'all_infos' contains all slots and storages that are ancient
#[derive(Default, Debug)]
struct AncientSlotInfos {
    /// info on all ancient storages
    all_infos: Vec<SlotInfo>,
    /// indexes to 'all_info' for storages that should be shrunk because alive ratio is too low.
    /// subset of all_infos
    shrink_indexes: Vec<usize>,
    /// total alive bytes across contents of 'shrink_indexes'
    total_alive_bytes_shrink: u64,
    /// total alive bytes across all slots
    total_alive_bytes: u64,
}

impl AncientSlotInfos {
    /// add info for 'storage'
    /// return true if item was randomly shrunk
    fn add(
        &mut self,
        slot: Slot,
        storage: Arc<AccountStorageEntry>,
        can_randomly_shrink: bool,
    ) -> bool {
        let mut was_randomly_shrunk = false;
        let alive_bytes = storage.alive_bytes() as u64;
        if alive_bytes > 0 {
            let capacity = storage.accounts.capacity();
            let should_shrink = if capacity > 0 {
                let alive_ratio = alive_bytes * 100 / capacity;
                alive_ratio < 90
                    || if can_randomly_shrink && thread_rng().gen_range(0..10000) == 0 {
                        was_randomly_shrunk = true;
                        true
                    } else {
                        false
                    }
            } else {
                false
            };
            // two criteria we're shrinking by later:
            // 1. alive ratio so that we don't consume too much disk space with dead accounts
            // 2. # of active ancient roots, so that we don't consume too many open file handles

            if should_shrink {
                // alive ratio is too low, so prioritize combining this slot with others
                // to reduce disk space used
                saturating_add_assign!(self.total_alive_bytes_shrink, alive_bytes);
                self.shrink_indexes.push(self.all_infos.len());
            }
            self.all_infos.push(SlotInfo {
                slot,
                capacity,
                storage,
                alive_bytes,
                should_shrink,
            });
            saturating_add_assign!(self.total_alive_bytes, alive_bytes);
        }
        was_randomly_shrunk
    }

    /// modify 'self' to contain only the slot infos for the slots that should be combined
    /// (and in this process effectively shrunk)
    fn filter_ancient_slots(&mut self, tuning: &PackedAncientStorageTuning) {
        // figure out which slots to combine
        // 1. should_shrink: largest bytes saved above some cutoff of ratio
        self.choose_storages_to_shrink(tuning.percent_of_alive_shrunk_data);
        // 2. smallest files so we get the largest number of files to remove
        self.filter_by_smallest_capacity(tuning.max_ancient_slots, tuning.ideal_storage_size);
    }

    // sort 'shrink_indexes' by most bytes saved, highest to lowest
    fn sort_shrink_indexes_by_bytes_saved(&mut self) {
        self.shrink_indexes.sort_unstable_by(|l, r| {
            let amount_shrunk = |index: &usize| {
                let item = &self.all_infos[*index];
                item.capacity - item.alive_bytes
            };
            amount_shrunk(r).cmp(&amount_shrunk(l))
        });
    }

    /// clear 'should_shrink' for storages after a cutoff to limit how many storages we shrink
    fn clear_should_shrink_after_cutoff(&mut self, percent_of_alive_shrunk_data: u64) {
        let mut bytes_to_shrink_due_to_ratio = 0;
        // shrink enough slots to write 'percent_of_alive_shrunk_data'% of the total alive data
        // from slots that exceeded the shrink threshold.
        // The goal is to limit overall i/o in this pass while making progress.
        let threshold_bytes = self.total_alive_bytes_shrink * percent_of_alive_shrunk_data / 100;
        for info_index in &self.shrink_indexes {
            let info = &mut self.all_infos[*info_index];
            if bytes_to_shrink_due_to_ratio >= threshold_bytes {
                // we exceeded the amount to shrink due to alive ratio, so don't shrink this one just due to 'should_shrink'
                // It MAY be shrunk based on total capacity still.
                // Mark it as false for 'should_shrink' so it gets evaluated solely based on # of files.
                info.should_shrink = false;
            } else {
                saturating_add_assign!(bytes_to_shrink_due_to_ratio, info.alive_bytes);
            }
        }
    }

    /// after this function, only slots that were chosen to shrink are marked with
    /// 'should_shrink'
    /// There are likely more candidates to shrink than will be chosen.
    fn choose_storages_to_shrink(&mut self, percent_of_alive_shrunk_data: u64) {
        // sort the shrink_ratio_slots by most bytes saved to fewest
        // most bytes saved is more valuable to shrink
        self.sort_shrink_indexes_by_bytes_saved();

        self.clear_should_shrink_after_cutoff(percent_of_alive_shrunk_data);
    }

    /// truncate 'all_infos' such that when the remaining entries in
    /// 'all_infos' are combined, the total number of storages <= 'max_storages'
    /// The idea is that 'all_infos' is sorted from smallest capacity to largest,
    /// but that isn't required for this function to be 'correct'.
    fn truncate_to_max_storages(&mut self, max_storages: usize, ideal_storage_size: NonZeroU64) {
        // these indexes into 'all_infos' are useless once we truncate 'all_infos', so make sure they're cleared out to avoid any issues
        self.shrink_indexes.clear();
        let total_storages = self.all_infos.len();
        let mut cumulative_bytes = 0u64;
        let low_threshold = max_storages * 50 / 100;
        for (i, info) in self.all_infos.iter().enumerate() {
            saturating_add_assign!(cumulative_bytes, info.alive_bytes);
            let ancient_storages_required = (cumulative_bytes / ideal_storage_size + 1) as usize;
            let storages_remaining = total_storages - i - 1;

            // if the remaining uncombined storages and the # of resulting
            // combined ancient storages is less than the threshold, then
            // we've gone too far, so get rid of this entry and all after it.
            // Every storage after this one is larger.
            if storages_remaining + ancient_storages_required < low_threshold {
                self.all_infos.truncate(i);
                break;
            }
        }
    }

    /// remove entries from 'all_infos' such that combining
    /// the remaining entries into storages of 'ideal_storage_size'
    /// will get us below 'max_storages'
    /// The entires that are removed will be reconsidered the next time around.
    /// Combining too many storages costs i/o and cpu so the goal is to find the sweet spot so
    /// that we make progress in cleaning/shrinking/combining but that we don't cause unnecessary
    /// churn.
    fn filter_by_smallest_capacity(&mut self, max_storages: usize, ideal_storage_size: NonZeroU64) {
        let total_storages = self.all_infos.len();
        if total_storages <= max_storages {
            // currently fewer storages than max, so nothing to shrink
            self.shrink_indexes.clear();
            self.all_infos.clear();
            return;
        }

        // sort by 'should_shrink' then smallest capacity to largest
        self.all_infos.sort_unstable_by(|l, r| {
            r.should_shrink
                .cmp(&l.should_shrink)
                .then_with(|| l.capacity.cmp(&r.capacity))
        });

        // remove any storages we don't need to combine this pass to achieve
        // # resulting storages <= 'max_storages'
        self.truncate_to_max_storages(max_storages, ideal_storage_size);
    }
}

/// Used to hold the result of writing a single ancient storage
/// and results of writing multiple ancient storages
#[derive(Debug, Default)]
struct WriteAncientAccounts<'a> {
    /// 'ShrinkInProgress' instances created by starting a shrink operation
    shrinks_in_progress: HashMap<Slot, ShrinkInProgress<'a>>,

    metrics: ShrinkStatsSub,
}

impl AccountsDb {
    /// Combine account data from storages in 'sorted_slots' into packed storages.
    /// This keeps us from accumulating storages for each slot older than an epoch.
    /// After this function the number of alive roots is <= # alive roots when it was called.
    /// In practice, the # of alive roots after will be significantly less than # alive roots when called.
    /// Trying to reduce # roots and storages (one per root) required to store all the data in ancient slots
    pub(crate) fn combine_ancient_slots_packed(
        &self,
        sorted_slots: Vec<Slot>,
        can_randomly_shrink: bool,
    ) {
        let tuning = PackedAncientStorageTuning {
            // only allow 10k slots old enough to be ancient
            max_ancient_slots: 10_000,
            // re-combine/shrink 55% of the data savings this pass
            percent_of_alive_shrunk_data: 55,
            ideal_storage_size: NonZeroU64::new(get_ancient_append_vec_capacity()).unwrap(),
            can_randomly_shrink,
        };

        let _guard = self.active_stats.activate(ActiveStatItem::SquashAncient);

        let mut stats_sub = ShrinkStatsSub::default();

        let (_, total_us) = measure_us!(self.combine_ancient_slots_packed_internal(
            sorted_slots,
            tuning,
            &mut stats_sub
        ));

        Self::update_shrink_stats(&self.shrink_ancient_stats.shrink_stats, stats_sub, false);
        self.shrink_ancient_stats
            .total_us
            .fetch_add(total_us, Ordering::Relaxed);

        self.shrink_ancient_stats.report();
    }

    /// return false if `many_refs_newest` accounts cannot be moved into `target_slots_sorted`.
    /// The slot # would be violated.
    /// accounts in `many_refs_newest` must be moved a slot >= each account's current slot.
    /// If that can be done, this fn returns true
    fn many_ref_accounts_can_be_moved(
        many_refs_newest: &[AliveAccounts<'_>],
        target_slots_sorted: &[Slot],
        tuning: &PackedAncientStorageTuning,
    ) -> bool {
        let alive_bytes = many_refs_newest
            .iter()
            .map(|alive| alive.bytes)
            .sum::<usize>();
        let required_ideal_packed = (alive_bytes as u64 / tuning.ideal_storage_size + 1) as usize;
        if alive_bytes == 0 {
            // nothing required, so no problem moving nothing
            return true;
        }
        if target_slots_sorted.len() < required_ideal_packed {
            return false;
        }
        let i_last = target_slots_sorted
            .len()
            .saturating_sub(required_ideal_packed);

        let highest_slot = target_slots_sorted[i_last];
        many_refs_newest
            .iter()
            .all(|many| many.slot <= highest_slot)
    }

    fn combine_ancient_slots_packed_internal(
        &self,
        sorted_slots: Vec<Slot>,
        tuning: PackedAncientStorageTuning,
        metrics: &mut ShrinkStatsSub,
    ) {
        self.shrink_ancient_stats
            .slots_considered
            .fetch_add(sorted_slots.len() as u64, Ordering::Relaxed);
        let ancient_slot_infos = self.collect_sort_filter_ancient_slots(sorted_slots, &tuning);

        if ancient_slot_infos.all_infos.is_empty() {
            return; // nothing to do
        }
        let accounts_per_storage = self
            .get_unique_accounts_from_storage_for_combining_ancient_slots(
                &ancient_slot_infos.all_infos[..],
            );

        let mut accounts_to_combine = self.calc_accounts_to_combine(&accounts_per_storage);
        metrics.unpackable_slots_count += accounts_to_combine.unpackable_slots_count;

        let mut many_refs_newest = accounts_to_combine
            .accounts_to_combine
            .iter_mut()
            .filter_map(|alive| {
                let newest_alive =
                    std::mem::take(&mut alive.alive_accounts.many_refs_this_is_newest_alive);
                (!newest_alive.accounts.is_empty()).then_some(newest_alive)
            })
            .collect::<Vec<_>>();

        // Sort highest slot to lowest slot. This way, we will put the multi ref accounts with the highest slots in the highest
        // packed slot.
        many_refs_newest.sort_unstable_by(|a, b| b.slot.cmp(&a.slot));
        metrics.newest_alive_packed_count += many_refs_newest.len();

        if !Self::many_ref_accounts_can_be_moved(
            &many_refs_newest,
            &accounts_to_combine.target_slots_sorted,
            &tuning,
        ) {
            datapoint_info!("shrink_ancient_stats", ("high_slot", 1, i64));
            log::info!(
                "unable to ancient pack: highest available slot: {:?}, lowest required slot: {:?}",
                accounts_to_combine.target_slots_sorted.last(),
                many_refs_newest.last().map(|accounts| accounts.slot)
            );
            self.addref_accounts_failed_to_shrink_ancient(accounts_to_combine);
            return;
        }

        // pack the accounts with 1 ref or refs > 1 but the slot we're packing is the highest alive slot for the pubkey.
        // Note the `chain` below combining the 2 types of refs.
        let pack = PackedAncientStorage::pack(
            many_refs_newest.iter().chain(
                accounts_to_combine
                    .accounts_to_combine
                    .iter()
                    .map(|shrink_collect| &shrink_collect.alive_accounts.one_ref),
            ),
            tuning.ideal_storage_size,
        );

        if pack.len() > accounts_to_combine.target_slots_sorted.len() {
            // Not enough slots to contain the accounts we are trying to pack.
            // `shrink_collect` previously unref'd some accounts. We need to addref them
            // to restore the correct state since we failed to combine anything.
            self.addref_accounts_failed_to_shrink_ancient(accounts_to_combine);
            return;
        }

        let write_ancient_accounts = self.write_packed_storages(&accounts_to_combine, pack);

        self.finish_combine_ancient_slots_packed_internal(
            accounts_to_combine,
            write_ancient_accounts,
            metrics,
        );
    }

    /// for each account in `unrefed_pubkeys`, in each `accounts_to_combine`, addref
    fn addref_accounts_failed_to_shrink_ancient(&self, accounts_to_combine: AccountsToCombine) {
        self.thread_pool_clean.install(|| {
            accounts_to_combine
                .accounts_to_combine
                .into_par_iter()
                .for_each(|combine| {
                    self.accounts_index.scan(
                        combine.unrefed_pubkeys.into_iter(),
                        |_pubkey, _slots_refs, entry| {
                            if let Some(entry) = entry {
                                entry.addref();
                            }
                            AccountsIndexScanResult::OnlyKeepInMemoryIfDirty
                        },
                        None,
                        true,
                    );
                });
        });
    }

    /// calculate all storage info for the storages in slots
    /// Then, apply 'tuning' to filter out slots we do NOT want to combine.
    fn collect_sort_filter_ancient_slots(
        &self,
        slots: Vec<Slot>,
        tuning: &PackedAncientStorageTuning,
    ) -> AncientSlotInfos {
        let mut ancient_slot_infos = self.calc_ancient_slot_info(slots, tuning.can_randomly_shrink);

        ancient_slot_infos.filter_ancient_slots(tuning);
        ancient_slot_infos
    }

    /// create append vec of size 'bytes'
    /// write 'accounts_to_write' into it
    /// return shrink_in_progress and some metrics
    fn write_ancient_accounts<'a, 'b: 'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &'b self,
        bytes: u64,
        accounts_to_write: impl StorableAccounts<'a, T>,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        let target_slot = accounts_to_write.target_slot();
        let (shrink_in_progress, create_and_insert_store_elapsed_us) =
            measure_us!(self.get_store_for_shrink(target_slot, bytes));
        let (store_accounts_timing, rewrite_elapsed_us) = measure_us!(self.store_accounts_frozen(
            accounts_to_write,
            None::<Vec<AccountHash>>,
            shrink_in_progress.new_storage(),
            None,
            StoreReclaims::Ignore,
        ));

        write_ancient_accounts.metrics.accumulate(&ShrinkStatsSub {
            store_accounts_timing,
            rewrite_elapsed_us,
            create_and_insert_store_elapsed_us,
            unpackable_slots_count: 0,
            newest_alive_packed_count: 0,
        });
        write_ancient_accounts
            .shrinks_in_progress
            .insert(target_slot, shrink_in_progress);
    }
    /// go through all slots and populate 'SlotInfo', per slot
    /// This provides the list of possible ancient slots to sort, filter, and then combine.
    fn calc_ancient_slot_info(
        &self,
        slots: Vec<Slot>,
        can_randomly_shrink: bool,
    ) -> AncientSlotInfos {
        let len = slots.len();
        let mut infos = AncientSlotInfos {
            shrink_indexes: Vec::with_capacity(len),
            all_infos: Vec::with_capacity(len),
            ..AncientSlotInfos::default()
        };
        let mut randoms = 0;

        for slot in &slots {
            if let Some(storage) = self.storage.get_slot_storage_entry(*slot) {
                if infos.add(*slot, storage, can_randomly_shrink) {
                    randoms += 1;
                }
            }
        }
        if randoms > 0 {
            self.shrink_ancient_stats
                .random_shrink
                .fetch_add(randoms, Ordering::Relaxed);
        }
        infos
    }

    /// write packed storages as described in 'accounts_to_combine'
    /// and 'packed_contents'
    fn write_packed_storages<'a, 'b>(
        &'a self,
        accounts_to_combine: &'b AccountsToCombine<'b>,
        packed_contents: Vec<PackedAncientStorage<'b>>,
    ) -> WriteAncientAccounts<'a> {
        let write_ancient_accounts = Mutex::new(WriteAncientAccounts::default());

        // ok if we have more slots, but NOT ok if we have fewer slots than we have contents
        assert!(accounts_to_combine.target_slots_sorted.len() >= packed_contents.len());
        // write packed storages containing contents from many original slots
        // iterate slots in highest to lowest
        let packer = accounts_to_combine
            .target_slots_sorted
            .iter()
            .rev()
            .zip(packed_contents)
            .collect::<Vec<_>>();

        // keep track of how many slots were shrunk away
        self.shrink_ancient_stats
            .ancient_append_vecs_shrunk
            .fetch_add(
                accounts_to_combine
                    .target_slots_sorted
                    .len()
                    .saturating_sub(packer.len()) as u64,
                Ordering::Relaxed,
            );

        self.thread_pool_clean.install(|| {
            packer.par_iter().for_each(|(target_slot, pack)| {
                let mut write_ancient_accounts_local = WriteAncientAccounts::default();
                self.shrink_ancient_stats
                    .bytes_ancient_created
                    .fetch_add(pack.bytes, Ordering::Relaxed);
                self.write_one_packed_storage(
                    pack,
                    **target_slot,
                    &mut write_ancient_accounts_local,
                );
                let mut write = write_ancient_accounts.lock().unwrap();
                write
                    .shrinks_in_progress
                    .extend(write_ancient_accounts_local.shrinks_in_progress);
                write
                    .metrics
                    .accumulate(&write_ancient_accounts_local.metrics);
            });
        });

        let mut write_ancient_accounts = write_ancient_accounts.into_inner().unwrap();

        // write new storages where contents were unable to move because ref_count > 1
        self.write_ancient_accounts_to_same_slot_multiple_refs(
            accounts_to_combine.accounts_keep_slots.values(),
            &mut write_ancient_accounts,
        );
        write_ancient_accounts
    }

    /// for each slot in 'ancient_slots', collect all accounts in that slot
    /// return the collection of accounts by slot
    fn get_unique_accounts_from_storage_for_combining_ancient_slots<'a>(
        &self,
        ancient_slots: &'a [SlotInfo],
    ) -> Vec<(&'a SlotInfo, GetUniqueAccountsResult<'a>)> {
        let mut accounts_to_combine = Vec::with_capacity(ancient_slots.len());

        for info in ancient_slots {
            let unique_accounts = self.get_unique_accounts_from_storage_for_shrink(
                &info.storage,
                &self.shrink_ancient_stats.shrink_stats,
            );
            accounts_to_combine.push((info, unique_accounts));
        }

        accounts_to_combine
    }

    /// finish shrink operation on slots where a new storage was created
    /// drop root and storage for all original slots whose contents were combined into other storages
    fn finish_combine_ancient_slots_packed_internal(
        &self,
        accounts_to_combine: AccountsToCombine<'_>,
        mut write_ancient_accounts: WriteAncientAccounts,
        metrics: &mut ShrinkStatsSub,
    ) {
        let mut dropped_roots = Vec::with_capacity(accounts_to_combine.accounts_to_combine.len());
        for shrink_collect in accounts_to_combine.accounts_to_combine {
            let slot = shrink_collect.slot;

            let shrink_in_progress = write_ancient_accounts.shrinks_in_progress.remove(&slot);
            if shrink_in_progress.is_none() {
                dropped_roots.push(slot);
            }
            self.remove_old_stores_shrink(
                &shrink_collect,
                &self.shrink_ancient_stats.shrink_stats,
                shrink_in_progress,
                true,
            );

            // If the slot is dead, remove the need to shrink the storage as the storage entries will be purged.
            self.shrink_candidate_slots.lock().unwrap().remove(&slot);
        }
        self.handle_dropped_roots_for_ancient(dropped_roots.into_iter());
        metrics.accumulate(&write_ancient_accounts.metrics);
    }

    /// given all accounts per ancient slot, in slots that we want to combine together:
    /// 1. Look up each pubkey in the index
    /// 2. separate, by slot, into:
    /// 2a. pubkeys with refcount = 1. This means this pubkey exists NOWHERE else in accounts db.
    /// 2b. pubkeys with refcount > 1
    /// Note that the return value can contain fewer items than 'accounts_per_storage' if we find storages which won't be affected.
    /// 'accounts_per_storage' should be sorted by slot
    fn calc_accounts_to_combine<'a>(
        &self,
        accounts_per_storage: &'a Vec<(&'a SlotInfo, GetUniqueAccountsResult<'a>)>,
    ) -> AccountsToCombine<'a> {
        let mut accounts_keep_slots = HashMap::default();
        let len = accounts_per_storage.len();
        let mut target_slots_sorted = Vec::with_capacity(len);

        // `shrink_collect` all accounts in the append vecs we want to combine.
        // This also unrefs all dead accounts in those append vecs.
        let mut accounts_to_combine = self.thread_pool_clean.install(|| {
            accounts_per_storage
                .par_iter()
                .map(|(info, unique_accounts)| {
                    self.shrink_collect::<ShrinkCollectAliveSeparatedByRefs<'_>>(
                        &info.storage,
                        unique_accounts,
                        &self.shrink_ancient_stats.shrink_stats,
                    )
                })
                .collect::<Vec<_>>()
        });

        let mut remove = Vec::default();
        for (i, (shrink_collect, (info, _unique_accounts))) in accounts_to_combine
            .iter_mut()
            .zip(accounts_per_storage.iter())
            .enumerate()
        {
            let many_refs_old_alive = &mut shrink_collect.alive_accounts.many_refs_old_alive;
            if !many_refs_old_alive.accounts.is_empty() {
                many_refs_old_alive.accounts.iter().for_each(|account| {
                    // these accounts could indicate clean bugs or low memory conditions where we are forced to flush non-roots
                    log::info!(
                        "ancient append vec: found unpackable account: {}, {}",
                        many_refs_old_alive.slot,
                        account.pubkey()
                    );
                });
                // There are alive accounts with ref_count > 1, where the entry for the account in the index is NOT the highest slot. (`many_refs_old_alive`)
                // This means this account must remain IN this slot. There could be alive or dead references to this same account in any older slot.
                // Moving it to a lower slot could move it before an alive or dead entry to this same account.
                // Moving it to a higher slot could move it ahead of other slots where this account is also alive. We know a higher slot exists that contains this account.
                // So, moving this account to a different slot could result in the moved account being before or after other instances of this account newer or older.
                // This would fail the invariant that the highest slot # where an account exists defines the most recent account.
                // It could be a clean error or a transient condition that will resolve if we encounter this situation.
                // The count of these accounts per call will be reported by metrics in `unpackable_slots_count`
                if shrink_collect.unrefed_pubkeys.is_empty()
                    && shrink_collect.alive_accounts.one_ref.accounts.is_empty()
                    && shrink_collect
                        .alive_accounts
                        .many_refs_this_is_newest_alive
                        .accounts
                        .is_empty()
                {
                    // all accounts in this append vec are alive and have > 1 ref, so nothing to be done for this append vec
                    remove.push(i);
                    continue;
                }
                accounts_keep_slots.insert(info.slot, std::mem::take(many_refs_old_alive));
            } else {
                // No alive accounts in this slot have a ref_count > 1. So, ALL alive accounts in this slot can be written to any other slot
                // we find convenient. There is NO other instance of any account to conflict with.
                target_slots_sorted.push(info.slot);
            }
        }
        let unpackable_slots_count = remove.len();
        remove.into_iter().rev().for_each(|i| {
            accounts_to_combine.remove(i);
        });
        target_slots_sorted.sort_unstable();
        AccountsToCombine {
            accounts_to_combine,
            accounts_keep_slots,
            target_slots_sorted,
            unpackable_slots_count,
        }
    }

    /// create packed storage and write contents of 'packed' to it.
    /// accumulate results in 'write_ancient_accounts'
    fn write_one_packed_storage<'a, 'b: 'a>(
        &'b self,
        packed: &'a PackedAncientStorage<'a>,
        target_slot: Slot,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        let PackedAncientStorage {
            bytes: bytes_total,
            accounts: accounts_to_write,
        } = packed;
        let accounts_to_write = StorableAccountsBySlot::new(target_slot, accounts_to_write);

        self.shrink_ancient_stats
            .bytes_ancient_created
            .fetch_add(packed.bytes, Ordering::Relaxed);
        self.shrink_ancient_stats
            .shrink_stats
            .num_slots_shrunk
            .fetch_add(1, Ordering::Relaxed);
        self.write_ancient_accounts(*bytes_total, accounts_to_write, write_ancient_accounts)
    }

    /// For each slot and alive accounts in 'accounts_to_combine'
    /// create a PackedAncientStorage that only contains the given alive accounts.
    /// This will represent only the accounts with ref_count > 1 from the original storage.
    /// These accounts need to be rewritten in their same slot, Ideally with no other accounts in the slot.
    /// Other accounts would have ref_count = 1.
    /// ref_count = 1 accounts will be combined together with other slots into larger append vecs elsewhere.
    fn write_ancient_accounts_to_same_slot_multiple_refs<'a, 'b: 'a>(
        &'b self,
        accounts_to_combine: impl Iterator<Item = &'a AliveAccounts<'a>>,
        write_ancient_accounts: &mut WriteAncientAccounts<'b>,
    ) {
        for alive_accounts in accounts_to_combine {
            let packed = PackedAncientStorage {
                bytes: alive_accounts.bytes as u64,
                accounts: vec![(alive_accounts.slot, &alive_accounts.accounts[..])],
            };

            self.write_one_packed_storage(&packed, alive_accounts.slot, write_ancient_accounts);
        }
    }
}

/// hold all alive accounts to be shrunk and/or combined
#[derive(Debug, Default)]
struct AccountsToCombine<'a> {
    /// slots and alive accounts that must remain in the slot they are currently in
    /// because the account exists in more than 1 slot in accounts db
    /// This hashmap contains an entry for each slot that contains at least one account with ref_count > 1.
    /// The value of the entry is all alive accounts in that slot whose ref_count > 1.
    /// Any OTHER accounts in that slot whose ref_count = 1 are in 'accounts_to_combine' because they can be moved
    /// to any slot.
    /// We want to keep the ref_count > 1 accounts by themselves, expecting the multiple ref_counts will be resolved
    /// soon and we can clean the duplicates up (which maybe THIS one).
    accounts_keep_slots: HashMap<Slot, AliveAccounts<'a>>,
    /// all the rest of alive accounts that can move slots and should be combined
    /// This includes all accounts with ref_count = 1 from the slots in 'accounts_keep_slots'.
    /// There is one entry here for each storage we are processing. Even if all accounts are in 'accounts_keep_slots'.
    accounts_to_combine: Vec<ShrinkCollect<'a, ShrinkCollectAliveSeparatedByRefs<'a>>>,
    /// slots that contain alive accounts that can move into ANY other ancient slot
    /// these slots will NOT be in 'accounts_keep_slots'
    /// Some of these slots will have ancient append vecs created at them to contain everything in 'accounts_to_combine'
    /// The rest will become dead slots with no accounts in them.
    /// Sort order is lowest to highest.
    target_slots_sorted: Vec<Slot>,
    /// when scanning, this many slots contained accounts that could not be packed because accounts with ref_count > 1 existed.
    unpackable_slots_count: usize,
}

#[derive(Default)]
/// intended contents of a packed ancient storage
struct PackedAncientStorage<'a> {
    /// accounts to move into this storage, along with the slot the accounts are currently stored in
    accounts: Vec<(Slot, &'a [&'a StoredAccountMeta<'a>])>,
    /// total bytes required to hold 'accounts'
    bytes: u64,
}

impl<'a> PackedAncientStorage<'a> {
    /// return a minimal set of 'PackedAncientStorage's to contain all 'accounts_to_combine' with
    /// the new storages having a size guided by 'ideal_size'
    fn pack(
        mut accounts_to_combine: impl Iterator<Item = &'a AliveAccounts<'a>>,
        ideal_size: NonZeroU64,
    ) -> Vec<PackedAncientStorage<'a>> {
        let mut result = Vec::default();
        let ideal_size: u64 = ideal_size.into();
        let ideal_size = ideal_size as usize;
        let mut current_alive_accounts = accounts_to_combine.next();
        // starting at first entry in current_alive_accounts
        let mut partial_inner_index = 0;
        // 0 bytes written so far from the current set of accounts
        let mut partial_bytes_written = 0;
        // pack a new storage each iteration of this outer loop
        loop {
            let mut bytes_total = 0usize;
            let mut accounts_to_write = Vec::default();

            // walk through each set of alive accounts to pack the current new storage up to ideal_size
            let mut full = false;
            while !full && current_alive_accounts.is_some() {
                let alive_accounts = current_alive_accounts.unwrap();
                if partial_inner_index >= alive_accounts.accounts.len() {
                    // current_alive_accounts have all been written, so advance to next set from accounts_to_combine
                    current_alive_accounts = accounts_to_combine.next();
                    // reset partial progress since we're starting over with a new set of alive accounts
                    partial_inner_index = 0;
                    partial_bytes_written = 0;
                    continue;
                }
                let bytes_remaining_this_slot =
                    alive_accounts.bytes.saturating_sub(partial_bytes_written);
                let bytes_total_with_this_slot =
                    bytes_total.saturating_add(bytes_remaining_this_slot);
                let mut partial_inner_index_max_exclusive;
                if bytes_total_with_this_slot <= ideal_size {
                    partial_inner_index_max_exclusive = alive_accounts.accounts.len();
                    bytes_total = bytes_total_with_this_slot;
                } else {
                    partial_inner_index_max_exclusive = partial_inner_index;
                    // adding all the alive accounts in this storage would exceed the ideal size, so we have to break these accounts up
                    // look at each account and stop when we exceed the ideal size
                    while partial_inner_index_max_exclusive < alive_accounts.accounts.len() {
                        let account = alive_accounts.accounts[partial_inner_index_max_exclusive];
                        let account_size = aligned_stored_size(account.data().len());
                        let new_size = bytes_total.saturating_add(account_size);
                        if new_size > ideal_size && bytes_total > 0 {
                            full = true;
                            // partial_inner_index_max_exclusive is the index of the first account that puts us over the ideal size
                            // so, save it for next time
                            break;
                        }
                        // this account fits
                        saturating_add_assign!(partial_bytes_written, account_size);
                        bytes_total = new_size;
                        partial_inner_index_max_exclusive += 1;
                    }
                }

                if partial_inner_index < partial_inner_index_max_exclusive {
                    // these accounts belong in the current packed storage we're working on
                    accounts_to_write.push((
                        alive_accounts.slot,
                        // maybe all alive accounts from the current or could be partial
                        &alive_accounts.accounts
                            [partial_inner_index..partial_inner_index_max_exclusive],
                    ));
                }
                // start next storage with the account we ended with
                // this could be the end of the current alive accounts or could be anywhere within that vec
                partial_inner_index = partial_inner_index_max_exclusive;
            }
            if accounts_to_write.is_empty() {
                // if we returned without any accounts to write, then we have exhausted source data and have packaged all the storages we need
                break;
            }
            // we know the full contents of this packed storage now
            result.push(PackedAncientStorage {
                bytes: bytes_total as u64,
                accounts: accounts_to_write,
            });
        }
        result
    }
}

/// a set of accounts need to be stored.
/// If there are too many to fit in 'Primary', the rest are put in 'Overflow'
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StorageSelector {
    Primary,
    Overflow,
}

/// reference a set of accounts to store
/// The accounts may have to be split between 2 storages (primary and overflow) if there is not enough room in the primary storage.
/// The 'store' functions need data stored in a slice of specific type.
/// We need 1-2 of these slices constructed based on available bytes and individual account sizes.
/// The slice arithmetic across both hashes and account data gets messy. So, this struct abstracts that.
pub struct AccountsToStore<'a> {
    accounts: &'a [&'a StoredAccountMeta<'a>],
    /// if 'accounts' contains more items than can be contained in the primary storage, then we have to split these accounts.
    /// 'index_first_item_overflow' specifies the index of the first item in 'accounts' that will go into the overflow storage
    index_first_item_overflow: usize,
    slot: Slot,
    /// bytes required to store primary accounts
    bytes_primary: usize,
    /// bytes required to store overflow accounts
    bytes_overflow: usize,
}

impl<'a> AccountsToStore<'a> {
    /// break 'stored_accounts' into primary and overflow
    /// available_bytes: how many bytes remain in the primary storage. Excess accounts will be directed to an overflow storage
    pub fn new(
        mut available_bytes: u64,
        accounts: &'a [&'a StoredAccountMeta<'a>],
        alive_total_bytes: usize,
        slot: Slot,
    ) -> Self {
        let num_accounts = accounts.len();
        let mut bytes_primary = alive_total_bytes;
        let mut bytes_overflow = 0;
        // index of the first account that doesn't fit in the current append vec
        let mut index_first_item_overflow = num_accounts; // assume all fit
        let initial_available_bytes = available_bytes as usize;
        if alive_total_bytes > available_bytes as usize {
            // not all the alive bytes fit, so we have to find how many accounts fit within available_bytes
            for (i, account) in accounts.iter().enumerate() {
                let account_size = account.stored_size() as u64;
                if available_bytes >= account_size {
                    available_bytes = available_bytes.saturating_sub(account_size);
                } else if index_first_item_overflow == num_accounts {
                    // the # of accounts we have so far seen is the most that will fit in the current ancient append vec
                    index_first_item_overflow = i;
                    bytes_primary =
                        initial_available_bytes.saturating_sub(available_bytes as usize);
                    bytes_overflow = alive_total_bytes.saturating_sub(bytes_primary);
                    break;
                }
            }
        }
        Self {
            accounts,
            index_first_item_overflow,
            slot,
            bytes_primary,
            bytes_overflow,
        }
    }

    /// true if a request to 'get' 'Overflow' would return accounts & hashes
    pub fn has_overflow(&self) -> bool {
        self.index_first_item_overflow < self.accounts.len()
    }

    /// return # required bytes for the given selector
    pub fn get_bytes(&self, selector: StorageSelector) -> usize {
        match selector {
            StorageSelector::Primary => self.bytes_primary,
            StorageSelector::Overflow => self.bytes_overflow,
        }
    }

    /// get the accounts to store in the given 'storage'
    pub fn get(&self, storage: StorageSelector) -> &[&'a StoredAccountMeta<'a>] {
        let range = match storage {
            StorageSelector::Primary => 0..self.index_first_item_overflow,
            StorageSelector::Overflow => self.index_first_item_overflow..self.accounts.len(),
        };
        &self.accounts[range]
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }
}

/// capacity of an ancient append vec
#[allow(clippy::assertions_on_constants, dead_code)]
pub const fn get_ancient_append_vec_capacity() -> u64 {
    // There is a trade-off for selecting the ancient append vec size. Smaller non-ancient append vec are getting
    // combined into large ancient append vec. Too small size of ancient append vec will result in too many ancient append vec
    // memory mapped files. Too big size will make it difficult to clean and shrink them. Hence, we choose approximately
    // 128MB for the ancient append vec size.
    const RESULT: u64 = 128 * 1024 * 1024;

    use crate::append_vec::MAXIMUM_APPEND_VEC_FILE_SIZE;
    const _: () = assert!(
        RESULT < MAXIMUM_APPEND_VEC_FILE_SIZE,
        "ancient append vec size should be less than the maximum append vec size"
    );
    const PAGE_SIZE: u64 = 4 * 1024;
    const _: () = assert!(
        RESULT % PAGE_SIZE == 0,
        "ancient append vec size should be a multiple of PAGE_SIZE"
    );

    RESULT
}

/// is this a max-size append vec designed to be used as an ancient append vec?
pub fn is_ancient(storage: &AccountsFile) -> bool {
    match storage {
        AccountsFile::AppendVec(storage) => storage.capacity() >= get_ancient_append_vec_capacity(),
    }
}
