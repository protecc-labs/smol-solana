use {
    crate::{
        accounts_db::{
            AccountsAddRootTiming, AccountsDb, LoadHint, LoadedAccount, ScanStorageResult,
            VerifyAccountsHashAndLamportsConfig,
        },
        accounts_index::{IndexKey, ScanConfig, ScanError, ScanResult, ZeroLamport},
        ancestors::Ancestors,
        nonce_info::{NonceFull, NonceInfo},
        rent_collector::RentCollector,
        rent_debits::RentDebits,
        storable_accounts::StorableAccounts,
        transaction_results::TransactionExecutionResult,
    },
    dashmap::DashMap,
    log::*,
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        account_utils::StateMut,
        address_lookup_table::{self, error::AddressLookupError, state::AddressLookupTable},
        clock::{BankId, Slot},
        message::v0::{LoadedAddresses, MessageAddressTableLookup},
        nonce::{
            state::{DurableNonce, Versions as NonceVersions},
            State as NonceState,
        },
        pubkey::Pubkey,
        slot_hashes::SlotHashes,
        transaction::{Result, SanitizedTransaction, TransactionAccountLocks, TransactionError},
        transaction_context::{IndexOfAccount, TransactionAccount},
    },
    std::{
        cmp::Reverse,
        collections::{
            hash_map::{self},
            BinaryHeap, HashMap, HashSet,
        },
        ops::RangeBounds,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    },
};

pub type PubkeyAccountSlot = (Pubkey, AccountSharedData, Slot);

#[derive(Debug, Default, AbiExample)]
pub struct AccountLocks {
    write_locks: HashSet<Pubkey>,
    readonly_locks: HashMap<Pubkey, u64>,
}

impl AccountLocks {
    fn is_locked_readonly(&self, key: &Pubkey) -> bool {
        self.readonly_locks
            .get(key)
            .map_or(false, |count| *count > 0)
    }

    fn is_locked_write(&self, key: &Pubkey) -> bool {
        self.write_locks.contains(key)
    }

    fn insert_new_readonly(&mut self, key: &Pubkey) {
        assert!(self.readonly_locks.insert(*key, 1).is_none());
    }

    fn lock_readonly(&mut self, key: &Pubkey) -> bool {
        self.readonly_locks.get_mut(key).map_or(false, |count| {
            *count += 1;
            true
        })
    }

    fn unlock_readonly(&mut self, key: &Pubkey) {
        if let hash_map::Entry::Occupied(mut occupied_entry) = self.readonly_locks.entry(*key) {
            let count = occupied_entry.get_mut();
            *count -= 1;
            if *count == 0 {
                occupied_entry.remove_entry();
            }
        }
    }

    fn unlock_write(&mut self, key: &Pubkey) {
        self.write_locks.remove(key);
    }
}

/// This structure handles synchronization for db
#[derive(Debug, AbiExample)]
pub struct Accounts {
    /// Single global AccountsDb
    pub accounts_db: Arc<AccountsDb>,

    /// set of read-only and writable accounts which are currently
    /// being processed by banking/replay threads
    pub(crate) account_locks: Mutex<AccountLocks>,
}

// for the load instructions
pub type TransactionRent = u64;
pub type TransactionProgramIndices = Vec<Vec<IndexOfAccount>>;
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct LoadedTransaction {
    pub accounts: Vec<TransactionAccount>,
    pub program_indices: TransactionProgramIndices,
    pub rent: TransactionRent,
    pub rent_debits: RentDebits,
}

pub type TransactionLoadResult = (Result<LoadedTransaction>, Option<NonceFull>);

pub enum AccountAddressFilter {
    Exclude, // exclude all addresses matching the filter
    Include, // only include addresses matching the filter
}

impl Accounts {
    pub fn new(accounts_db: Arc<AccountsDb>) -> Self {
        Self {
            accounts_db,
            account_locks: Mutex::new(AccountLocks::default()),
        }
    }

    pub fn load_lookup_table_addresses(
        &self,
        ancestors: &Ancestors,
        address_table_lookup: &MessageAddressTableLookup,
        slot_hashes: &SlotHashes,
    ) -> std::result::Result<LoadedAddresses, AddressLookupError> {
        let table_account = self
            .accounts_db
            .load_with_fixed_root(ancestors, &address_table_lookup.account_key)
            .map(|(account, _rent)| account)
            .ok_or(AddressLookupError::LookupTableAccountNotFound)?;

        if table_account.owner() == &address_lookup_table::program::id() {
            let current_slot = ancestors.max_slot();
            let lookup_table = AddressLookupTable::deserialize(table_account.data())
                .map_err(|_ix_err| AddressLookupError::InvalidAccountData)?;

            Ok(LoadedAddresses {
                writable: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.writable_indexes,
                    slot_hashes,
                )?,
                readonly: lookup_table.lookup(
                    current_slot,
                    &address_table_lookup.readonly_indexes,
                    slot_hashes,
                )?,
            })
        } else {
            Err(AddressLookupError::InvalidAccountOwner)
        }
    }

    /// Slow because lock is held for 1 operation instead of many
    /// This always returns None for zero-lamport accounts.
    fn load_slow(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
        load_hint: LoadHint,
    ) -> Option<(AccountSharedData, Slot)> {
        self.accounts_db.load(ancestors, pubkey, load_hint)
    }

    pub fn load_with_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::FixedMaxRoot)
    }

    pub fn load_without_fixed_root(
        &self,
        ancestors: &Ancestors,
        pubkey: &Pubkey,
    ) -> Option<(AccountSharedData, Slot)> {
        self.load_slow(ancestors, pubkey, LoadHint::Unspecified)
    }

    /// scans underlying accounts_db for this delta (slot) with a map function
    ///   from LoadedAccount to B
    /// returns only the latest/current version of B for this slot
    pub fn scan_slot<F, B>(&self, slot: Slot, func: F) -> Vec<B>
    where
        F: Fn(LoadedAccount) -> Option<B> + Send + Sync,
        B: Sync + Send + Default + std::cmp::Eq,
    {
        let scan_result = self.accounts_db.scan_account_storage(
            slot,
            |loaded_account: LoadedAccount| {
                // Cache only has one version per key, don't need to worry about versioning
                func(loaded_account)
            },
            |accum: &DashMap<Pubkey, B>, loaded_account: LoadedAccount| {
                let loaded_account_pubkey = *loaded_account.pubkey();
                if let Some(val) = func(loaded_account) {
                    accum.insert(loaded_account_pubkey, val);
                }
            },
        );

        match scan_result {
            ScanStorageResult::Cached(cached_result) => cached_result,
            ScanStorageResult::Stored(stored_result) => stored_result
                .into_iter()
                .map(|(_pubkey, val)| val)
                .collect(),
        }
    }

    /// Returns all the accounts from `slot`
    ///
    /// If `program_id` is `Some`, filter the results to those whose owner matches `program_id`
    pub fn load_by_program_slot(
        &self,
        slot: Slot,
        program_id: Option<&Pubkey>,
    ) -> Vec<TransactionAccount> {
        self.scan_slot(slot, |stored_account| {
            program_id
                .map(|program_id| program_id == stored_account.owner())
                .unwrap_or(true)
                .then(|| (*stored_account.pubkey(), stored_account.take_account()))
        })
    }

    pub fn load_largest_accounts(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        num: usize,
        filter_by_address: &HashSet<Pubkey>,
        filter: AccountAddressFilter,
    ) -> ScanResult<Vec<(Pubkey, u64)>> {
        if num == 0 {
            return Ok(vec![]);
        }
        let mut account_balances = BinaryHeap::new();
        self.accounts_db.scan_accounts(
            ancestors,
            bank_id,
            |option| {
                if let Some((pubkey, account, _slot)) = option {
                    if account.lamports() == 0 {
                        return;
                    }
                    let contains_address = filter_by_address.contains(pubkey);
                    let collect = match filter {
                        AccountAddressFilter::Exclude => !contains_address,
                        AccountAddressFilter::Include => contains_address,
                    };
                    if !collect {
                        return;
                    }
                    if account_balances.len() == num {
                        let Reverse(entry) = account_balances
                            .peek()
                            .expect("BinaryHeap::peek should succeed when len > 0");
                        if *entry >= (account.lamports(), *pubkey) {
                            return;
                        }
                        account_balances.pop();
                    }
                    account_balances.push(Reverse((account.lamports(), *pubkey)));
                }
            },
            &ScanConfig::default(),
        )?;
        Ok(account_balances
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((balance, pubkey))| (pubkey, balance))
            .collect())
    }

    /// Only called from startup or test code.
    #[must_use]
    pub fn verify_accounts_hash_and_lamports(
        &self,
        slot: Slot,
        total_lamports: u64,
        base: Option<(Slot, /*capitalization*/ u64)>,
        config: VerifyAccountsHashAndLamportsConfig,
    ) -> bool {
        if let Err(err) =
            self.accounts_db
                .verify_accounts_hash_and_lamports(slot, total_lamports, base, config)
        {
            warn!("verify_accounts_hash failed: {err:?}, slot: {slot}");
            false
        } else {
            true
        }
    }

    pub fn is_loadable(lamports: u64) -> bool {
        // Don't ever load zero lamport accounts into runtime because
        // the existence of zero-lamport accounts are never deterministic!!
        lamports > 0
    }

    fn load_while_filtering<F: Fn(&AccountSharedData) -> bool>(
        collector: &mut Vec<TransactionAccount>,
        some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>,
        filter: F,
    ) {
        if let Some(mapped_account_tuple) = some_account_tuple
            .filter(|(_, account, _)| Self::is_loadable(account.lamports()) && filter(account))
            .map(|(pubkey, account, _slot)| (*pubkey, account))
        {
            collector.push(mapped_account_tuple)
        }
    }

    fn load_with_slot(
        collector: &mut Vec<PubkeyAccountSlot>,
        some_account_tuple: Option<(&Pubkey, AccountSharedData, Slot)>,
    ) {
        if let Some(mapped_account_tuple) = some_account_tuple
            .filter(|(_, account, _)| Self::is_loadable(account.lamports()))
            .map(|(pubkey, account, slot)| (*pubkey, account, slot))
        {
            collector.push(mapped_account_tuple)
        }
    }

    pub fn load_by_program(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
                        account.owner() == program_id
                    })
                },
                config,
            )
            .map(|_| collector)
    }

    pub fn load_by_program_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        program_id: &Pubkey,
        filter: F,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
                        account.owner() == program_id && filter(account)
                    })
                },
                config,
            )
            .map(|_| collector)
    }

    fn calc_scan_result_size(account: &AccountSharedData) -> usize {
        account.data().len()
            + std::mem::size_of::<AccountSharedData>()
            + std::mem::size_of::<Pubkey>()
    }

    /// Accumulate size of (pubkey + account) into sum.
    /// Return true iff sum > 'byte_limit_for_scan'
    fn accumulate_and_check_scan_result_size(
        sum: &AtomicUsize,
        account: &AccountSharedData,
        byte_limit_for_scan: &Option<usize>,
    ) -> bool {
        if let Some(byte_limit_for_scan) = byte_limit_for_scan.as_ref() {
            let added = Self::calc_scan_result_size(account);
            sum.fetch_add(added, Ordering::Relaxed)
                .saturating_add(added)
                > *byte_limit_for_scan
        } else {
            false
        }
    }

    fn maybe_abort_scan(
        result: ScanResult<Vec<TransactionAccount>>,
        config: &ScanConfig,
    ) -> ScanResult<Vec<TransactionAccount>> {
        if config.is_aborted() {
            ScanResult::Err(ScanError::Aborted(
                "The accumulated scan results exceeded the limit".to_string(),
            ))
        } else {
            result
        }
    }

    pub fn load_by_index_key_with_filter<F: Fn(&AccountSharedData) -> bool>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        index_key: &IndexKey,
        filter: F,
        config: &ScanConfig,
        byte_limit_for_scan: Option<usize>,
    ) -> ScanResult<Vec<TransactionAccount>> {
        let sum = AtomicUsize::default();
        let config = config.recreate_with_abort();
        let mut collector = Vec::new();
        let result = self
            .accounts_db
            .index_scan_accounts(
                ancestors,
                bank_id,
                *index_key,
                |some_account_tuple| {
                    Self::load_while_filtering(&mut collector, some_account_tuple, |account| {
                        let use_account = filter(account);
                        if use_account
                            && Self::accumulate_and_check_scan_result_size(
                                &sum,
                                account,
                                &byte_limit_for_scan,
                            )
                        {
                            // total size of results exceeds size limit, so abort scan
                            config.abort();
                        }
                        use_account
                    });
                },
                &config,
            )
            .map(|_| collector);
        Self::maybe_abort_scan(result, &config)
    }

    pub fn account_indexes_include_key(&self, key: &Pubkey) -> bool {
        self.accounts_db.account_indexes.include_key(key)
    }

    pub fn load_all(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
    ) -> ScanResult<Vec<PubkeyAccountSlot>> {
        let mut collector = Vec::new();
        self.accounts_db
            .scan_accounts(
                ancestors,
                bank_id,
                |some_account_tuple| {
                    if let Some((pubkey, account, slot)) = some_account_tuple
                        .filter(|(_, account, _)| Self::is_loadable(account.lamports()))
                    {
                        collector.push((*pubkey, account, slot))
                    }
                },
                &ScanConfig::default(),
            )
            .map(|_| collector)
    }

    pub fn scan_all<F>(
        &self,
        ancestors: &Ancestors,
        bank_id: BankId,
        scan_func: F,
    ) -> ScanResult<()>
    where
        F: FnMut(Option<(&Pubkey, AccountSharedData, Slot)>),
    {
        self.accounts_db
            .scan_accounts(ancestors, bank_id, scan_func, &ScanConfig::default())
    }

    pub fn hold_range_in_memory<R>(
        &self,
        range: &R,
        start_holding: bool,
        thread_pool: &rayon::ThreadPool,
    ) where
        R: RangeBounds<Pubkey> + std::fmt::Debug + Sync,
    {
        self.accounts_db
            .accounts_index
            .hold_range_in_memory(range, start_holding, thread_pool)
    }

    pub fn load_to_collect_rent_eagerly<R: RangeBounds<Pubkey> + std::fmt::Debug>(
        &self,
        ancestors: &Ancestors,
        range: R,
    ) -> Vec<PubkeyAccountSlot> {
        let mut collector = Vec::new();
        self.accounts_db.range_scan_accounts(
            "", // disable logging of this. We now parallelize it and this results in multiple parallel logs
            ancestors,
            range,
            &ScanConfig::new(true),
            |option| Self::load_with_slot(&mut collector, option),
        );
        collector
    }

    /// Slow because lock is held for 1 operation instead of many.
    /// WARNING: This noncached version is only to be used for tests/benchmarking
    /// as bypassing the cache in general is not supported
    pub fn store_slow_uncached(&self, slot: Slot, pubkey: &Pubkey, account: &AccountSharedData) {
        self.accounts_db.store_uncached(slot, &[(pubkey, account)]);
    }

    fn lock_account(
        &self,
        account_locks: &mut AccountLocks,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
    ) -> Result<()> {
        for k in writable_keys.iter() {
            if account_locks.is_locked_write(k) || account_locks.is_locked_readonly(k) {
                debug!("Writable account in use: {:?}", k);
                return Err(TransactionError::AccountInUse);
            }
        }
        for k in readonly_keys.iter() {
            if account_locks.is_locked_write(k) {
                debug!("Read-only account in use: {:?}", k);
                return Err(TransactionError::AccountInUse);
            }
        }

        for k in writable_keys {
            account_locks.write_locks.insert(*k);
        }

        for k in readonly_keys {
            if !account_locks.lock_readonly(k) {
                account_locks.insert_new_readonly(k);
            }
        }

        Ok(())
    }

    fn unlock_account(
        &self,
        account_locks: &mut AccountLocks,
        writable_keys: Vec<&Pubkey>,
        readonly_keys: Vec<&Pubkey>,
    ) {
        for k in writable_keys {
            account_locks.unlock_write(k);
        }
        for k in readonly_keys {
            account_locks.unlock_readonly(k);
        }
    }

    /// This function will prevent multiple threads from modifying the same account state at the
    /// same time
    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        tx_account_lock_limit: usize,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> = txs
            .map(|tx| tx.get_account_locks(tx_account_lock_limit))
            .collect();
        self.lock_accounts_inner(tx_account_locks_results)
    }

    #[must_use]
    #[allow(clippy::needless_collect)]
    pub fn lock_accounts_with_results<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        results: impl Iterator<Item = Result<()>>,
        tx_account_lock_limit: usize,
    ) -> Vec<Result<()>> {
        let tx_account_locks_results: Vec<Result<_>> = txs
            .zip(results)
            .map(|(tx, result)| match result {
                Ok(()) => tx.get_account_locks(tx_account_lock_limit),
                Err(err) => Err(err),
            })
            .collect();
        self.lock_accounts_inner(tx_account_locks_results)
    }

    #[must_use]
    fn lock_accounts_inner(
        &self,
        tx_account_locks_results: Vec<Result<TransactionAccountLocks>>,
    ) -> Vec<Result<()>> {
        let account_locks = &mut self.account_locks.lock().unwrap();
        tx_account_locks_results
            .into_iter()
            .map(|tx_account_locks_result| match tx_account_locks_result {
                Ok(tx_account_locks) => self.lock_account(
                    account_locks,
                    tx_account_locks.writable,
                    tx_account_locks.readonly,
                ),
                Err(err) => Err(err),
            })
            .collect()
    }

    /// Once accounts are unlocked, new transactions that modify that state can enter the pipeline
    #[allow(clippy::needless_collect)]
    pub fn unlock_accounts<'a>(
        &self,
        txs: impl Iterator<Item = &'a SanitizedTransaction>,
        results: &[Result<()>],
    ) {
        let keys: Vec<_> = txs
            .zip(results)
            .filter(|(_, res)| res.is_ok())
            .map(|(tx, _)| tx.get_account_locks_unchecked())
            .collect();
        let mut account_locks = self.account_locks.lock().unwrap();
        debug!("bank unlock accounts");
        keys.into_iter().for_each(|keys| {
            self.unlock_account(&mut account_locks, keys.writable, keys.readonly);
        });
    }

    /// Store the accounts into the DB
    // allow(clippy) needed for various gating flags
    #[allow(clippy::too_many_arguments)]
    pub fn store_cached(
        &self,
        slot: Slot,
        txs: &[SanitizedTransaction],
        res: &[TransactionExecutionResult],
        loaded: &mut [TransactionLoadResult],
        rent_collector: &RentCollector,
        durable_nonce: &DurableNonce,
        lamports_per_signature: u64,
    ) {
        let (accounts_to_store, transactions) = self.collect_accounts_to_store(
            txs,
            res,
            loaded,
            rent_collector,
            durable_nonce,
            lamports_per_signature,
        );
        self.accounts_db
            .store_cached_inline_update_index((slot, &accounts_to_store[..]), Some(&transactions));
    }

    pub fn store_accounts_cached<'a, T: ReadableAccount + Sync + ZeroLamport + 'a>(
        &self,
        accounts: impl StorableAccounts<'a, T>,
    ) {
        self.accounts_db.store_cached(accounts, None)
    }

    /// Add a slot to root.  Root slots cannot be purged
    pub fn add_root(&self, slot: Slot) -> AccountsAddRootTiming {
        self.accounts_db.add_root(slot)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_accounts_to_store<'a>(
        &self,
        txs: &'a [SanitizedTransaction],
        execution_results: &'a [TransactionExecutionResult],
        load_results: &'a mut [TransactionLoadResult],
        _rent_collector: &RentCollector,
        durable_nonce: &DurableNonce,
        lamports_per_signature: u64,
    ) -> (
        Vec<(&'a Pubkey, &'a AccountSharedData)>,
        Vec<Option<&'a SanitizedTransaction>>,
    ) {
        let mut accounts = Vec::with_capacity(load_results.len());
        let mut transactions = Vec::with_capacity(load_results.len());
        for (i, ((tx_load_result, nonce), tx)) in load_results.iter_mut().zip(txs).enumerate() {
            if tx_load_result.is_err() {
                // Don't store any accounts if tx failed to load
                continue;
            }

            let execution_status = match &execution_results[i] {
                TransactionExecutionResult::Executed { details, .. } => &details.status,
                // Don't store any accounts if tx wasn't executed
                TransactionExecutionResult::NotExecuted(_) => continue,
            };

            let maybe_nonce = match (execution_status, &*nonce) {
                (Ok(_), _) => None, // Success, don't do any additional nonce processing
                (Err(_), Some(nonce)) => {
                    Some((nonce, true /* rollback */))
                }
                (Err(_), None) => {
                    // Fees for failed transactions which don't use durable nonces are
                    // deducted in Bank::filter_program_errors_and_collect_fee
                    continue;
                }
            };

            let message = tx.message();
            let loaded_transaction = tx_load_result.as_mut().unwrap();
            let mut fee_payer_index = None;
            for (i, (address, account)) in (0..message.account_keys().len())
                .zip(loaded_transaction.accounts.iter_mut())
                .filter(|(i, _)| message.is_non_loader_key(*i))
            {
                if fee_payer_index.is_none() {
                    fee_payer_index = Some(i);
                }
                let is_fee_payer = Some(i) == fee_payer_index;
                if message.is_writable(i) {
                    let is_nonce_account = prepare_if_nonce_account(
                        address,
                        account,
                        execution_status,
                        is_fee_payer,
                        maybe_nonce,
                        durable_nonce,
                        lamports_per_signature,
                    );

                    if execution_status.is_ok() || is_nonce_account || is_fee_payer {
                        // Add to the accounts to store
                        accounts.push((&*address, &*account));
                        transactions.push(Some(tx));
                    }
                }
            }
        }
        (accounts, transactions)
    }
}

fn prepare_if_nonce_account(
    address: &Pubkey,
    account: &mut AccountSharedData,
    execution_result: &Result<()>,
    is_fee_payer: bool,
    maybe_nonce: Option<(&NonceFull, bool)>,
    &durable_nonce: &DurableNonce,
    lamports_per_signature: u64,
) -> bool {
    if let Some((nonce, rollback)) = maybe_nonce {
        if address == nonce.address() {
            if rollback {
                // The transaction failed which would normally drop the account
                // processing changes, since this account is now being included
                // in the accounts written back to the db, roll it back to
                // pre-processing state.
                *account = nonce.account().clone();
            }

            // Advance the stored blockhash to prevent fee theft by someone
            // replaying nonce transactions that have failed with an
            // `InstructionError`.
            //
            // Since we know we are dealing with a valid nonce account,
            // unwrap is safe here
            let nonce_versions = StateMut::<NonceVersions>::state(nonce.account()).unwrap();
            if let NonceState::Initialized(ref data) = nonce_versions.state() {
                let nonce_state = NonceState::new_initialized(
                    &data.authority,
                    durable_nonce,
                    lamports_per_signature,
                );
                let nonce_versions = NonceVersions::new(nonce_state);
                account.set_state(&nonce_versions).unwrap();
            }
            true
        } else {
            if execution_result.is_err() && is_fee_payer {
                if let Some(fee_payer_account) = nonce.fee_payer_account() {
                    // Instruction error and fee-payer for this nonce tx is not
                    // the nonce account itself, rollback the fee payer to the
                    // fee-paid original state.
                    *account = fee_payer_account.clone();
                }
            }

            false
        }
    } else {
        false
    }
}
