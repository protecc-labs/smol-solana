//! Used to create minimal snapshots - separated here to keep accounts_db simpler

use {
    crate::{bank::Bank, builtins::BUILTINS, static_ids},
    dashmap::DashSet,
    log::info,
    rayon::{
        iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator},
        prelude::ParallelSlice,
    },
    solana_accounts_db::{
        accounts_db::{
            AccountStorageEntry, AccountsDb, GetUniqueAccountsResult, PurgeStats, StoreReclaims,
        },
        accounts_partition,
    },
    solana_measure::measure,
    solana_sdk::{
        account::ReadableAccount,
        account_utils::StateMut,
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        clock::Slot,
        pubkey::Pubkey,
        sdk_ids,
    },
    std::{
        collections::HashSet,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

/// Used to modify bank and accounts_db to create a minimized snapshot
pub struct SnapshotMinimizer<'a> {
    bank: &'a Bank,
    starting_slot: Slot,
    ending_slot: Slot,
    minimized_account_set: DashSet<Pubkey>,
}

impl<'a> SnapshotMinimizer<'a> {
    /// Removes all accounts not necessary for replaying slots in the range [starting_slot, ending_slot].
    /// `transaction_account_set` should contain accounts used in transactions in the slot range [starting_slot, ending_slot].
    /// This function will accumulate other accounts (rent collection, builtins, etc) necessary to replay transactions.
    ///
    /// This function will modify accounts_db by removing accounts not needed to replay [starting_slot, ending_slot],
    /// and update the bank's capitalization.
    pub fn minimize(
        bank: &'a Bank,
        starting_slot: Slot,
        ending_slot: Slot,
        transaction_account_set: DashSet<Pubkey>,
    ) {
        let minimizer = SnapshotMinimizer {
            bank,
            starting_slot,
            ending_slot,
            minimized_account_set: transaction_account_set,
        };

        minimizer.add_accounts(Self::get_active_bank_features, "active bank features");
        minimizer.add_accounts(Self::get_inactive_bank_features, "inactive bank features");
        minimizer.add_accounts(Self::get_builtins, "builtin accounts");
        minimizer.add_accounts(Self::get_static_runtime_accounts, "static runtime accounts");
        minimizer.add_accounts(Self::get_sdk_accounts, "sdk accounts");

        minimizer.add_accounts(
            Self::get_rent_collection_accounts,
            "rent collection accounts",
        );
        minimizer.add_accounts(Self::get_vote_accounts, "vote accounts");
        minimizer.add_accounts(Self::get_stake_accounts, "stake accounts");
        minimizer.add_accounts(Self::get_owner_accounts, "owner accounts");
        minimizer.add_accounts(Self::get_programdata_accounts, "programdata accounts");

        minimizer.minimize_accounts_db();

        // Update accounts_cache and capitalization
        minimizer.bank.force_flush_accounts_cache();
        minimizer.bank.set_capitalization();
    }

    /// Helper function to measure time and number of accounts added
    fn add_accounts<F>(&self, add_accounts_fn: F, name: &'static str)
    where
        F: Fn(&SnapshotMinimizer<'a>),
    {
        let initial_accounts_len = self.minimized_account_set.len();
        let (_, measure) = measure!(add_accounts_fn(self), name);
        let total_accounts_len = self.minimized_account_set.len();
        let added_accounts = total_accounts_len - initial_accounts_len;

        info!(
            "Added {added_accounts} {name} for total of {total_accounts_len} accounts. get {measure}"
        );
    }

    /// Used to get active bank feature accounts in `minimize`.
    fn get_active_bank_features(&self) {
        self.bank.feature_set.active.iter().for_each(|(pubkey, _)| {
            self.minimized_account_set.insert(*pubkey);
        });
    }

    /// Used to get inactive bank feature accounts in `minimize`
    fn get_inactive_bank_features(&self) {
        self.bank.feature_set.inactive.iter().for_each(|pubkey| {
            self.minimized_account_set.insert(*pubkey);
        });
    }

    /// Used to get builtin accounts in `minimize`
    fn get_builtins(&self) {
        BUILTINS.iter().for_each(|e| {
            self.minimized_account_set.insert(e.program_id);
        });
    }

    /// Used to get static runtime accounts in `minimize`
    fn get_static_runtime_accounts(&self) {
        static_ids::STATIC_IDS.iter().for_each(|pubkey| {
            self.minimized_account_set.insert(*pubkey);
        });
    }

    /// Used to get sdk accounts in `minimize`
    fn get_sdk_accounts(&self) {
        sdk_ids::SDK_IDS.iter().for_each(|pubkey| {
            self.minimized_account_set.insert(*pubkey);
        });
    }

    /// Used to get rent collection accounts in `minimize`
    /// Add all pubkeys we would collect rent from or rewrite to `minimized_account_set`.
    /// related to Bank::rent_collection_partitions
    fn get_rent_collection_accounts(&self) {
        let partitions = if !self.bank.use_fixed_collection_cycle() {
            self.bank
                .variable_cycle_partitions_between_slots(self.starting_slot, self.ending_slot)
        } else {
            self.bank
                .fixed_cycle_partitions_between_slots(self.starting_slot, self.ending_slot)
        };

        partitions.into_iter().for_each(|partition| {
            let subrange = accounts_partition::pubkey_range_from_partition(partition);
            // This may be overkill since we just need the pubkeys and don't need to actually load the accounts.
            // Leaving it for now as this is only used by ledger-tool. If used in runtime, we will need to instead use
            // some of the guts of `load_to_collect_rent_eagerly`.
            self.bank
                .accounts()
                .load_to_collect_rent_eagerly(&self.bank.ancestors, subrange)
                .into_par_iter()
                .for_each(|(pubkey, ..)| {
                    self.minimized_account_set.insert(pubkey);
                })
        });
    }

    /// Used to get vote and node pubkeys in `minimize`
    /// Add all pubkeys from vote accounts and nodes to `minimized_account_set`
    fn get_vote_accounts(&self) {
        self.bank
            .vote_accounts()
            .par_iter()
            .for_each(|(pubkey, (_stake, vote_account))| {
                self.minimized_account_set.insert(*pubkey);
                if let Ok(vote_state) = vote_account.vote_state().as_ref() {
                    self.minimized_account_set.insert(vote_state.node_pubkey);
                }
            });
    }

    /// Used to get stake accounts in `minimize`
    /// Add all pubkeys from stake accounts to `minimized_account_set`
    fn get_stake_accounts(&self) {
        self.bank.get_stake_accounts(&self.minimized_account_set);
    }

    /// Used to get owner accounts in `minimize`
    /// For each account in `minimized_account_set` adds the owner account's pubkey to `minimized_account_set`.
    fn get_owner_accounts(&self) {
        let owner_accounts: HashSet<_> = self
            .minimized_account_set
            .par_iter()
            .filter_map(|pubkey| self.bank.get_account(&pubkey))
            .map(|account| *account.owner())
            .collect();
        owner_accounts.into_par_iter().for_each(|pubkey| {
            self.minimized_account_set.insert(pubkey);
        });
    }

    /// Used to get program data accounts in `minimize`
    /// For each upgradable bpf program, adds the programdata account pubkey to `minimized_account_set`
    fn get_programdata_accounts(&self) {
        let programdata_accounts: HashSet<_> = self
            .minimized_account_set
            .par_iter()
            .filter_map(|pubkey| self.bank.get_account(&pubkey))
            .filter(|account| account.executable())
            .filter(|account| bpf_loader_upgradeable::check_id(account.owner()))
            .filter_map(|account| {
                if let Ok(UpgradeableLoaderState::Program {
                    programdata_address,
                }) = account.state()
                {
                    Some(programdata_address)
                } else {
                    None
                }
            })
            .collect();
        programdata_accounts.into_par_iter().for_each(|pubkey| {
            self.minimized_account_set.insert(pubkey);
        });
    }

    /// Remove accounts not in `minimized_accoun_set` from accounts_db
    fn minimize_accounts_db(&self) {
        let (minimized_slot_set, minimized_slot_set_measure) =
            measure!(self.get_minimized_slot_set(), "generate minimized slot set");
        info!("{minimized_slot_set_measure}");

        let ((dead_slots, dead_storages), process_snapshot_storages_measure) = measure!(
            self.process_snapshot_storages(minimized_slot_set),
            "process snapshot storages"
        );
        info!("{process_snapshot_storages_measure}");

        // Avoid excessive logging
        self.accounts_db()
            .log_dead_slots
            .store(false, Ordering::Relaxed);

        let (_, purge_dead_slots_measure) =
            measure!(self.purge_dead_slots(dead_slots), "purge dead slots");
        info!("{purge_dead_slots_measure}");

        let (_, drop_or_recycle_stores_measure) = measure!(
            self.accounts_db()
                .drop_or_recycle_stores(dead_storages, &self.accounts_db().shrink_stats),
            "drop or recycle stores"
        );
        info!("{drop_or_recycle_stores_measure}");

        // Turn logging back on after minimization
        self.accounts_db()
            .log_dead_slots
            .store(true, Ordering::Relaxed);
    }

    /// Determines minimum set of slots that accounts in `minimized_account_set` are in
    fn get_minimized_slot_set(&self) -> DashSet<Slot> {
        let minimized_slot_set = DashSet::new();
        self.minimized_account_set.par_iter().for_each(|pubkey| {
            if let Some(read_entry) = self
                .accounts_db()
                .accounts_index
                .get_account_read_entry(&pubkey)
            {
                if let Some(max_slot) = read_entry.slot_list().iter().map(|(slot, _)| *slot).max() {
                    minimized_slot_set.insert(max_slot);
                }
            }
        });
        minimized_slot_set
    }

    /// Process all snapshot storages to during `minimize`
    fn process_snapshot_storages(
        &self,
        minimized_slot_set: DashSet<Slot>,
    ) -> (Vec<Slot>, Vec<Arc<AccountStorageEntry>>) {
        let snapshot_storages = self
            .accounts_db()
            .get_snapshot_storages(..=self.starting_slot)
            .0;

        let dead_slots = Mutex::new(Vec::new());
        let dead_storages = Mutex::new(Vec::new());

        snapshot_storages.into_par_iter().for_each(|storage| {
            let slot = storage.slot();
            if slot != self.starting_slot {
                if minimized_slot_set.contains(&slot) {
                    self.filter_storage(&storage, &dead_storages);
                } else {
                    dead_slots.lock().unwrap().push(slot);
                }
            }
        });

        let dead_slots = dead_slots.into_inner().unwrap();
        let dead_storages = dead_storages.into_inner().unwrap();
        (dead_slots, dead_storages)
    }

    /// Creates new storage replacing `storages` that contains only accounts in `minimized_account_set`.
    fn filter_storage(
        &self,
        storage: &Arc<AccountStorageEntry>,
        dead_storages: &Mutex<Vec<Arc<AccountStorageEntry>>>,
    ) {
        let slot = storage.slot();
        let GetUniqueAccountsResult {
            stored_accounts, ..
        } = self.accounts_db().get_unique_accounts_from_storage(storage);

        let keep_accounts_collect = Mutex::new(Vec::with_capacity(stored_accounts.len()));
        let purge_pubkeys_collect = Mutex::new(Vec::with_capacity(stored_accounts.len()));
        let total_bytes_collect = AtomicUsize::new(0);
        const CHUNK_SIZE: usize = 50;
        stored_accounts.par_chunks(CHUNK_SIZE).for_each(|chunk| {
            let mut chunk_bytes = 0;
            let mut keep_accounts = Vec::with_capacity(CHUNK_SIZE);
            let mut purge_pubkeys = Vec::with_capacity(CHUNK_SIZE);
            chunk.iter().for_each(|account| {
                if self.minimized_account_set.contains(account.pubkey()) {
                    chunk_bytes += account.stored_size();
                    keep_accounts.push(account);
                } else if self
                    .accounts_db()
                    .accounts_index
                    .get_account_read_entry(account.pubkey())
                    .is_some()
                {
                    purge_pubkeys.push(account.pubkey());
                }
            });

            keep_accounts_collect
                .lock()
                .unwrap()
                .append(&mut keep_accounts);
            purge_pubkeys_collect
                .lock()
                .unwrap()
                .append(&mut purge_pubkeys);
            total_bytes_collect.fetch_add(chunk_bytes, Ordering::Relaxed);
        });

        let keep_accounts = keep_accounts_collect.into_inner().unwrap();
        let remove_pubkeys = purge_pubkeys_collect.into_inner().unwrap();
        let total_bytes = total_bytes_collect.load(Ordering::Relaxed);

        let purge_pubkeys: Vec<_> = remove_pubkeys
            .into_iter()
            .map(|pubkey| (*pubkey, slot))
            .collect();
        let _ = self.accounts_db().purge_keys_exact(purge_pubkeys.iter());

        let aligned_total: u64 = AccountsDb::page_align(total_bytes as u64);
        let mut shrink_in_progress = None;
        if aligned_total > 0 {
            let mut accounts = Vec::with_capacity(keep_accounts.len());
            let mut hashes = Vec::with_capacity(keep_accounts.len());
            let mut write_versions = Vec::with_capacity(keep_accounts.len());

            for alive_account in keep_accounts {
                accounts.push(alive_account);
                hashes.push(alive_account.hash());
                write_versions.push(alive_account.write_version());
            }

            shrink_in_progress = Some(self.accounts_db().get_store_for_shrink(slot, aligned_total));
            let new_storage = shrink_in_progress.as_ref().unwrap().new_storage();
            self.accounts_db().store_accounts_frozen(
                (slot, &accounts[..]),
                Some(hashes),
                new_storage,
                Some(Box::new(write_versions.into_iter())),
                StoreReclaims::Ignore,
            );

            new_storage.flush().unwrap();
        }

        let mut dead_storages_this_time = self.accounts_db().mark_dirty_dead_stores(
            slot,
            true, // add_dirty_stores
            shrink_in_progress,
            false,
        );
        dead_storages
            .lock()
            .unwrap()
            .append(&mut dead_storages_this_time);
    }

    /// Purge dead slots from storage and cache
    fn purge_dead_slots(&self, dead_slots: Vec<Slot>) {
        let stats = PurgeStats::default();
        self.accounts_db()
            .purge_slots_from_cache_and_store(dead_slots.iter(), &stats, false);
    }

    /// Convenience function for getting accounts_db
    fn accounts_db(&self) -> &AccountsDb {
        &self.bank.rc.accounts.accounts_db
    }
}
