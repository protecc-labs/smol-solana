use {
    crate::{
        account_storage::meta::{StoredAccountMeta, StoredMeta},
        accounts_db::AccountsDb,
    },
    solana_measure::measure::Measure,
    solana_metrics::*,
    solana_sdk::{
        account::AccountSharedData, clock::Slot, pubkey::Pubkey, transaction::SanitizedTransaction,
    },
    std::collections::{HashMap, HashSet},
};

#[derive(Default)]
pub struct GeyserPluginNotifyAtSnapshotRestoreStats {
    pub total_accounts: usize,
    pub skipped_accounts: usize,
    pub notified_accounts: usize,
    pub elapsed_filtering_us: usize,
    pub total_pure_notify: usize,
    pub total_pure_bookeeping: usize,
    pub elapsed_notifying_us: usize,
}

impl GeyserPluginNotifyAtSnapshotRestoreStats {
    pub fn report(&self) {
        datapoint_info!(
            "accountsdb_plugin_notify_account_restore_from_snapshot_summary",
            ("total_accounts", self.total_accounts, i64),
            ("skipped_accounts", self.skipped_accounts, i64),
            ("notified_accounts", self.notified_accounts, i64),
            ("elapsed_filtering_us", self.elapsed_filtering_us, i64),
            ("elapsed_notifying_us", self.elapsed_notifying_us, i64),
            ("total_pure_notify_us", self.total_pure_notify, i64),
            ("total_pure_bookeeping_us", self.total_pure_bookeeping, i64),
        );
    }
}

impl AccountsDb {
    /// Notify the plugins of of account data when AccountsDb is restored from a snapshot. The data is streamed
    /// in the reverse order of the slots so that an account is only streamed once. At a slot, if the accounts is updated
    /// multiple times only the last write (with highest write_version) is notified.
    pub fn notify_account_restore_from_snapshot(&self) {
        if self.accounts_update_notifier.is_none() {
            return;
        }

        let mut slots = self.storage.all_slots();
        let mut notified_accounts: HashSet<Pubkey> = HashSet::default();
        let mut notify_stats = GeyserPluginNotifyAtSnapshotRestoreStats::default();

        slots.sort_by(|a, b| b.cmp(a));
        for slot in slots {
            self.notify_accounts_in_slot(slot, &mut notified_accounts, &mut notify_stats);
        }

        let accounts_update_notifier = self.accounts_update_notifier.as_ref().unwrap();
        accounts_update_notifier.notify_end_of_restore_from_snapshot();
        notify_stats.report();
    }

    pub fn notify_account_at_accounts_update<P>(
        &self,
        slot: Slot,
        account: &AccountSharedData,
        txn: &Option<&SanitizedTransaction>,
        pubkey: &Pubkey,
        write_version_producer: &mut P,
    ) where
        P: Iterator<Item = u64>,
    {
        if let Some(accounts_update_notifier) = &self.accounts_update_notifier {
            accounts_update_notifier.notify_account_update(
                slot,
                account,
                txn,
                pubkey,
                write_version_producer.next().unwrap(),
            );
        }
    }

    fn notify_accounts_in_slot(
        &self,
        slot: Slot,
        notified_accounts: &mut HashSet<Pubkey>,
        notify_stats: &mut GeyserPluginNotifyAtSnapshotRestoreStats,
    ) {
        let storage_entry = self.storage.get_slot_storage_entry(slot).unwrap();

        let mut accounts_to_stream: HashMap<Pubkey, StoredAccountMeta> = HashMap::default();
        let mut measure_filter = Measure::start("accountsdb-plugin-filtering-accounts");
        let accounts = storage_entry.accounts.account_iter();
        let mut account_len = 0;
        accounts.for_each(|account| {
            account_len += 1;
            if notified_accounts.contains(account.pubkey()) {
                notify_stats.skipped_accounts += 1;
                return;
            }

            // later entries in the same slot are more recent and override earlier accounts for the same pubkey
            // We can pass an incrementing number here for write_version in the future, if the storage does not have a write_version.
            // As long as all accounts for this slot are in 1 append vec that can be itereated olest to newest.
            accounts_to_stream.insert(*account.pubkey(), account);
        });
        notify_stats.total_accounts += account_len;
        measure_filter.stop();
        notify_stats.elapsed_filtering_us += measure_filter.as_us() as usize;

        self.notify_filtered_accounts(slot, notified_accounts, accounts_to_stream, notify_stats);
    }

    fn notify_filtered_accounts(
        &self,
        slot: Slot,
        notified_accounts: &mut HashSet<Pubkey>,
        mut accounts_to_stream: HashMap<Pubkey, StoredAccountMeta>,
        notify_stats: &mut GeyserPluginNotifyAtSnapshotRestoreStats,
    ) {
        let notifier = self.accounts_update_notifier.as_ref().unwrap();
        let mut measure_notify = Measure::start("accountsdb-plugin-notifying-accounts");
        let local_write_version = 0;
        for (_, mut account) in accounts_to_stream.drain() {
            // We do not need to rely on the specific write_version read from the append vec.
            // So, overwrite the write_version with something that works.
            // 'accounts_to_stream' is already a hashmap, so there is already only entry per pubkey.
            // write_version is only used to order multiple entries with the same pubkey, so it doesn't matter what value it gets here.
            // Passing 0 for everyone's write_version is sufficiently correct.
            let meta = StoredMeta {
                write_version_obsolete: local_write_version,
                ..*account.meta()
            };
            account.set_meta(&meta);
            let mut measure_pure_notify = Measure::start("accountsdb-plugin-notifying-accounts");
            notifier.notify_account_restore_from_snapshot(slot, &account);
            measure_pure_notify.stop();

            notify_stats.total_pure_notify += measure_pure_notify.as_us() as usize;

            let mut measure_bookkeep = Measure::start("accountsdb-plugin-notifying-bookeeeping");
            notified_accounts.insert(*account.pubkey());
            measure_bookkeep.stop();
            notify_stats.total_pure_bookeeping += measure_bookkeep.as_us() as usize;
        }
        notify_stats.notified_accounts += accounts_to_stream.len();
        measure_notify.stop();
        notify_stats.elapsed_notifying_us += measure_notify.as_us() as usize;
    }
}
