pub mod account_rent_state;

use {
    crate::{
        accounts::account_rent_state::{check_rent_state_with_account, RentState},
        bank::RewardInterval,
    },
    itertools::Itertools,
    log::warn,
    solana_accounts_db::{
        account_overrides::AccountOverrides,
        accounts::{LoadedTransaction, TransactionLoadResult, TransactionRent},
        accounts_db::AccountsDb,
        ancestors::Ancestors,
        blockhash_queue::BlockhashQueue,
        nonce_info::{NonceFull, NonceInfo},
        rent_collector::{RentCollector, RENT_EXEMPT_RENT_EPOCH},
        rent_debits::RentDebits,
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_results::TransactionCheckResult,
    },
    solana_program_runtime::{
        compute_budget_processor::process_compute_budget_instructions,
        loaded_programs::LoadedProgramsForTxBatch,
    },
    solana_sdk::{
        account::{
            create_executable_meta, is_builtin, is_executable, Account, AccountSharedData,
            ReadableAccount, WritableAccount,
        },
        feature_set::{include_loaded_accounts_data_size_in_fee_calculation, FeatureSet},
        fee::FeeStructure,
        message::SanitizedMessage,
        native_loader,
        nonce::State as NonceState,
        pubkey::Pubkey,
        rent::RentDue,
        saturating_add_assign,
        sysvar::{self, instructions::construct_instructions_data},
        transaction::{Result, SanitizedTransaction, TransactionError},
        transaction_context::IndexOfAccount,
    },
    solana_system_program::{get_system_account_kind, SystemAccountKind},
    std::{collections::HashMap, num::NonZeroUsize},
};

#[allow(clippy::too_many_arguments)]
pub(super) fn load_accounts(
    accounts_db: &AccountsDb,
    ancestors: &Ancestors,
    txs: &[SanitizedTransaction],
    lock_results: Vec<TransactionCheckResult>,
    hash_queue: &BlockhashQueue,
    error_counters: &mut TransactionErrorMetrics,
    rent_collector: &RentCollector,
    feature_set: &FeatureSet,
    fee_structure: &FeeStructure,
    account_overrides: Option<&AccountOverrides>,
    in_reward_interval: RewardInterval,
    program_accounts: &HashMap<Pubkey, (&Pubkey, u64)>,
    loaded_programs: &LoadedProgramsForTxBatch,
    should_collect_rent: bool,
) -> Vec<TransactionLoadResult> {
    txs.iter()
        .zip(lock_results)
        .map(|etx| match etx {
            (tx, (Ok(()), nonce)) => {
                let lamports_per_signature = nonce
                    .as_ref()
                    .map(|nonce| nonce.lamports_per_signature())
                    .unwrap_or_else(|| {
                        hash_queue.get_lamports_per_signature(tx.message().recent_blockhash())
                    });
                let fee = if let Some(lamports_per_signature) = lamports_per_signature {
                    fee_structure.calculate_fee(
                        tx.message(),
                        lamports_per_signature,
                        &process_compute_budget_instructions(
                            tx.message().program_instructions_iter(),
                        )
                        .unwrap_or_default()
                        .into(),
                        feature_set
                            .is_active(&include_loaded_accounts_data_size_in_fee_calculation::id()),
                    )
                } else {
                    return (Err(TransactionError::BlockhashNotFound), None);
                };

                // load transactions
                let loaded_transaction = match load_transaction_accounts(
                    accounts_db,
                    ancestors,
                    tx,
                    fee,
                    error_counters,
                    rent_collector,
                    feature_set,
                    account_overrides,
                    in_reward_interval,
                    program_accounts,
                    loaded_programs,
                    should_collect_rent,
                ) {
                    Ok(loaded_transaction) => loaded_transaction,
                    Err(e) => return (Err(e), None),
                };

                // Update nonce with fee-subtracted accounts
                let nonce = if let Some(nonce) = nonce {
                    match NonceFull::from_partial(
                        nonce,
                        tx.message(),
                        &loaded_transaction.accounts,
                        &loaded_transaction.rent_debits,
                    ) {
                        Ok(nonce) => Some(nonce),
                        Err(e) => return (Err(e), None),
                    }
                } else {
                    None
                };

                (Ok(loaded_transaction), nonce)
            }
            (_, (Err(e), _nonce)) => (Err(e), None),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn load_transaction_accounts(
    accounts_db: &AccountsDb,
    ancestors: &Ancestors,
    tx: &SanitizedTransaction,
    fee: u64,
    error_counters: &mut TransactionErrorMetrics,
    rent_collector: &RentCollector,
    feature_set: &FeatureSet,
    account_overrides: Option<&AccountOverrides>,
    reward_interval: RewardInterval,
    program_accounts: &HashMap<Pubkey, (&Pubkey, u64)>,
    loaded_programs: &LoadedProgramsForTxBatch,
    should_collect_rent: bool,
) -> Result<LoadedTransaction> {
    let in_reward_interval = reward_interval == RewardInterval::InsideInterval;

    // NOTE: this check will never fail because `tx` is sanitized
    if tx.signatures().is_empty() && fee != 0 {
        return Err(TransactionError::MissingSignatureForFee);
    }

    // There is no way to predict what program will execute without an error
    // If a fee can pay for execution then the program will be scheduled
    let mut validated_fee_payer = false;
    let mut tx_rent: TransactionRent = 0;
    let message = tx.message();
    let account_keys = message.account_keys();
    let mut accounts_found = Vec::with_capacity(account_keys.len());
    let mut account_deps = Vec::with_capacity(account_keys.len());
    let mut rent_debits = RentDebits::default();

    let set_exempt_rent_epoch_max =
        feature_set.is_active(&solana_sdk::feature_set::set_exempt_rent_epoch_max::id());

    let requested_loaded_accounts_data_size_limit =
        get_requested_loaded_accounts_data_size_limit(tx)?;
    let mut accumulated_accounts_data_size: usize = 0;

    let instruction_accounts = message
        .instructions()
        .iter()
        .flat_map(|instruction| &instruction.accounts)
        .unique()
        .collect::<Vec<&u8>>();

    let mut accounts = account_keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let mut account_found = true;
            #[allow(clippy::collapsible_else_if)]
            let account = if solana_sdk::sysvar::instructions::check_id(key) {
                construct_instructions_account(message)
            } else {
                let instruction_account = u8::try_from(i)
                    .map(|i| instruction_accounts.contains(&&i))
                    .unwrap_or(false);
                let (account_size, mut account, rent) = if let Some(account_override) =
                    account_overrides.and_then(|overrides| overrides.get(key))
                {
                    (account_override.data().len(), account_override.clone(), 0)
                } else if let Some(program) = (!instruction_account && !message.is_writable(i))
                    .then_some(())
                    .and_then(|_| loaded_programs.find(key))
                {
                    // Optimization to skip loading of accounts which are only used as
                    // programs in top-level instructions and not passed as instruction accounts.
                    account_shared_data_from_program(key, program_accounts)
                        .map(|program_account| (program.account_size, program_account, 0))?
                } else {
                    accounts_db
                        .load_with_fixed_root(ancestors, key)
                        .map(|(mut account, _)| {
                            if message.is_writable(i) {
                                if should_collect_rent {
                                    let rent_due = rent_collector
                                        .collect_from_existing_account(
                                            key,
                                            &mut account,
                                            set_exempt_rent_epoch_max,
                                        )
                                        .rent_amount;

                                    (account.data().len(), account, rent_due)
                                } else {
                                    // When rent fee collection is disabled, we won't collect rent for any account. If there
                                    // are any rent paying accounts, their `rent_epoch` won't change either. However, if the
                                    // account itself is rent-exempted but its `rent_epoch` is not u64::MAX, we will set its
                                    // `rent_epoch` to u64::MAX. In such case, the behavior stays the same as before.
                                    if set_exempt_rent_epoch_max
                                        && (account.rent_epoch() != RENT_EXEMPT_RENT_EPOCH
                                            && rent_collector.get_rent_due(&account)
                                                == RentDue::Exempt)
                                    {
                                        account.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
                                    }
                                    (account.data().len(), account, 0)
                                }
                            } else {
                                (account.data().len(), account, 0)
                            }
                        })
                        .unwrap_or_else(|| {
                            account_found = false;
                            let mut default_account = AccountSharedData::default();
                            if set_exempt_rent_epoch_max {
                                // All new accounts must be rent-exempt (enforced in Bank::execute_loaded_transaction).
                                // Currently, rent collection sets rent_epoch to u64::MAX, but initializing the account
                                // with this field already set would allow us to skip rent collection for these accounts.
                                default_account.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
                            }
                            (default_account.data().len(), default_account, 0)
                        })
                };
                accumulate_and_check_loaded_account_data_size(
                    &mut accumulated_accounts_data_size,
                    account_size,
                    requested_loaded_accounts_data_size_limit,
                    error_counters,
                )?;

                if !validated_fee_payer && message.is_non_loader_key(i) {
                    if i != 0 {
                        warn!("Payer index should be 0! {:?}", tx);
                    }

                    validate_fee_payer(
                        key,
                        &mut account,
                        i as IndexOfAccount,
                        error_counters,
                        rent_collector,
                        fee,
                    )?;

                    validated_fee_payer = true;
                }

                if in_reward_interval
                    && message.is_writable(i)
                    && solana_stake_program::check_id(account.owner())
                {
                    error_counters.program_execution_temporarily_restricted += 1;
                    return Err(TransactionError::ProgramExecutionTemporarilyRestricted {
                        account_index: i as u8,
                    });
                }

                tx_rent += rent;
                rent_debits.insert(key, rent, account.lamports());

                account
            };

            accounts_found.push(account_found);
            Ok((*key, account))
        })
        .collect::<Result<Vec<_>>>()?;

    if !validated_fee_payer {
        error_counters.account_not_found += 1;
        return Err(TransactionError::AccountNotFound);
    }

    // Appends the account_deps at the end of the accounts,
    // this way they can be accessed in a uniform way.
    // At places where only the accounts are needed,
    // the account_deps are truncated using e.g:
    // accounts.iter().take(message.account_keys.len())
    accounts.append(&mut account_deps);

    let builtins_start_index = accounts.len();
    let program_indices = message
        .instructions()
        .iter()
        .map(|instruction| {
            let mut account_indices = Vec::new();
            let mut program_index = instruction.program_id_index as usize;
            let (program_id, program_account) = accounts
                .get(program_index)
                .ok_or(TransactionError::ProgramAccountNotFound)?;
            if native_loader::check_id(program_id) {
                return Ok(account_indices);
            }

            let account_found = accounts_found.get(program_index).unwrap_or(&true);
            if !account_found {
                error_counters.account_not_found += 1;
                return Err(TransactionError::ProgramAccountNotFound);
            }

            if !(is_builtin(program_account) || is_executable(program_account, feature_set)) {
                error_counters.invalid_program_for_execution += 1;
                return Err(TransactionError::InvalidProgramForExecution);
            }
            account_indices.insert(0, program_index as IndexOfAccount);
            let owner_id = program_account.owner();
            if native_loader::check_id(owner_id) {
                return Ok(account_indices);
            }
            program_index = if let Some(owner_index) = accounts
                .get(builtins_start_index..)
                .ok_or(TransactionError::ProgramAccountNotFound)?
                .iter()
                .position(|(key, _)| key == owner_id)
            {
                builtins_start_index.saturating_add(owner_index)
            } else {
                let owner_index = accounts.len();
                if let Some((owner_account, _)) =
                    accounts_db.load_with_fixed_root(ancestors, owner_id)
                {
                    if !native_loader::check_id(owner_account.owner())
                        || !(is_builtin(&owner_account)
                            || is_executable(&owner_account, feature_set))
                    {
                        error_counters.invalid_program_for_execution += 1;
                        return Err(TransactionError::InvalidProgramForExecution);
                    }
                    accumulate_and_check_loaded_account_data_size(
                        &mut accumulated_accounts_data_size,
                        owner_account.data().len(),
                        requested_loaded_accounts_data_size_limit,
                        error_counters,
                    )?;
                    accounts.push((*owner_id, owner_account));
                } else {
                    error_counters.account_not_found += 1;
                    return Err(TransactionError::ProgramAccountNotFound);
                }
                owner_index
            };
            account_indices.insert(0, program_index as IndexOfAccount);
            Ok(account_indices)
        })
        .collect::<Result<Vec<Vec<IndexOfAccount>>>>()?;

    Ok(LoadedTransaction {
        accounts,
        program_indices,
        rent: tx_rent,
        rent_debits,
    })
}

/// Total accounts data a transaction can load is limited to
///   if `set_tx_loaded_accounts_data_size` instruction is not activated or not used, then
///     default value of 64MiB to not break anyone in Mainnet-beta today
///   else
///     user requested loaded accounts size.
///     Note, requesting zero bytes will result transaction error
fn get_requested_loaded_accounts_data_size_limit(
    tx: &SanitizedTransaction,
) -> Result<Option<NonZeroUsize>> {
    let compute_budget_limits =
        process_compute_budget_instructions(tx.message().program_instructions_iter())
            .unwrap_or_default();
    // sanitize against setting size limit to zero
    NonZeroUsize::new(
        usize::try_from(compute_budget_limits.loaded_accounts_bytes).unwrap_or_default(),
    )
    .map_or(
        Err(TransactionError::InvalidLoadedAccountsDataSizeLimit),
        |v| Ok(Some(v)),
    )
}

fn account_shared_data_from_program(
    key: &Pubkey,
    program_accounts: &HashMap<Pubkey, (&Pubkey, u64)>,
) -> Result<AccountSharedData> {
    // It's an executable program account. The program is already loaded in the cache.
    // So the account data is not needed. Return a dummy AccountSharedData with meta
    // information.
    let mut program_account = AccountSharedData::default();
    let (program_owner, _count) = program_accounts
        .get(key)
        .ok_or(TransactionError::AccountNotFound)?;
    program_account.set_owner(**program_owner);
    program_account.set_executable(true);
    program_account.set_data_from_slice(create_executable_meta(program_owner));
    Ok(program_account)
}

/// Accumulate loaded account data size into `accumulated_accounts_data_size`.
/// Returns TransactionErr::MaxLoadedAccountsDataSizeExceeded if
/// `requested_loaded_accounts_data_size_limit` is specified and
/// `accumulated_accounts_data_size` exceeds it.
fn accumulate_and_check_loaded_account_data_size(
    accumulated_loaded_accounts_data_size: &mut usize,
    account_data_size: usize,
    requested_loaded_accounts_data_size_limit: Option<NonZeroUsize>,
    error_counters: &mut TransactionErrorMetrics,
) -> Result<()> {
    if let Some(requested_loaded_accounts_data_size) = requested_loaded_accounts_data_size_limit {
        saturating_add_assign!(*accumulated_loaded_accounts_data_size, account_data_size);
        if *accumulated_loaded_accounts_data_size > requested_loaded_accounts_data_size.get() {
            error_counters.max_loaded_accounts_data_size_exceeded += 1;
            Err(TransactionError::MaxLoadedAccountsDataSizeExceeded)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

pub fn validate_fee_payer(
    payer_address: &Pubkey,
    payer_account: &mut AccountSharedData,
    payer_index: IndexOfAccount,
    error_counters: &mut TransactionErrorMetrics,
    rent_collector: &RentCollector,
    fee: u64,
) -> Result<()> {
    if payer_account.lamports() == 0 {
        error_counters.account_not_found += 1;
        return Err(TransactionError::AccountNotFound);
    }
    let system_account_kind = get_system_account_kind(payer_account).ok_or_else(|| {
        error_counters.invalid_account_for_fee += 1;
        TransactionError::InvalidAccountForFee
    })?;
    let min_balance = match system_account_kind {
        SystemAccountKind::System => 0,
        SystemAccountKind::Nonce => {
            // Should we ever allow a fees charge to zero a nonce account's
            // balance. The state MUST be set to uninitialized in that case
            rent_collector.rent.minimum_balance(NonceState::size())
        }
    };

    payer_account
        .lamports()
        .checked_sub(min_balance)
        .and_then(|v| v.checked_sub(fee))
        .ok_or_else(|| {
            error_counters.insufficient_funds += 1;
            TransactionError::InsufficientFundsForFee
        })?;

    let payer_pre_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
    payer_account
        .checked_sub_lamports(fee)
        .map_err(|_| TransactionError::InsufficientFundsForFee)?;

    let payer_post_rent_state = RentState::from_account(payer_account, &rent_collector.rent);
    check_rent_state_with_account(
        &payer_pre_rent_state,
        &payer_post_rent_state,
        payer_address,
        payer_account,
        payer_index,
    )
}

pub fn construct_instructions_account(message: &SanitizedMessage) -> AccountSharedData {
    AccountSharedData::from(Account {
        data: construct_instructions_data(&message.decompile_instructions()),
        owner: sysvar::id(),
        ..Account::default()
    })
}
