use {
    crate::{
        bank::{Bank, BankFieldsToDeserialize, BankSlotDelta},
        builtins::BuiltinPrototype,
        runtime_config::RuntimeConfig,
        serde_snapshot::{
            bank_from_streams, bank_to_stream, fields_from_streams,
            BankIncrementalSnapshotPersistence, SerdeStyle,
        },
        snapshot_archive_info::{
            FullSnapshotArchiveInfo, IncrementalSnapshotArchiveInfo, SnapshotArchiveInfoGetter,
        },
        snapshot_hash::SnapshotHash,
        snapshot_package::{AccountsPackage, AccountsPackageKind, SnapshotKind, SnapshotPackage},
        snapshot_utils::{
            self, archive_snapshot_package, deserialize_snapshot_data_file,
            deserialize_snapshot_data_files, get_bank_snapshot_dir, get_highest_bank_snapshot_post,
            get_highest_full_snapshot_archive_info, get_highest_incremental_snapshot_archive_info,
            get_snapshot_file_name, get_storages_to_serialize, hard_link_storages_to_snapshot,
            rebuild_storages_from_snapshot_dir, serialize_snapshot_data_file,
            verify_and_unarchive_snapshots, verify_unpacked_snapshots_dir_and_version,
            AddBankSnapshotError, ArchiveFormat, BankSnapshotInfo, BankSnapshotType, SnapshotError,
            SnapshotRootPaths, SnapshotVersion, StorageAndNextAppendVecId,
            UnpackedSnapshotsDirAndVersion, VerifySlotDeltasError,
        },
        status_cache,
    },
    bincode::{config::Options, serialize_into},
    log::*,
    solana_accounts_db::{
        accounts_db::{
            AccountShrinkThreshold, AccountStorageEntry, AccountsDbConfig, AtomicAppendVecId,
            CalcAccountsHashDataSource,
        },
        accounts_hash::AccountsHash,
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        utils::delete_contents_of_path,
    },
    solana_measure::{measure, measure::Measure},
    solana_sdk::{
        clock::Slot,
        feature_set,
        genesis_config::GenesisConfig,
        hash::Hash,
        pubkey::Pubkey,
        slot_history::{Check, SlotHistory},
    },
    std::{
        collections::HashSet,
        fs,
        io::{BufWriter, Write},
        num::NonZeroUsize,
        path::{Path, PathBuf},
        sync::{atomic::AtomicBool, Arc},
    },
    tempfile::TempDir,
};

pub const DEFAULT_FULL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 25_000;
pub const DEFAULT_INCREMENTAL_SNAPSHOT_ARCHIVE_INTERVAL_SLOTS: Slot = 100;
pub const DISABLED_SNAPSHOT_ARCHIVE_INTERVAL: Slot = Slot::MAX;

/// Serialize a bank to a snapshot
///
/// **DEVELOPER NOTE** Any error that is returned from this function may bring down the node!  This
/// function is called from AccountsBackgroundService to handle snapshot requests.  Since taking a
/// snapshot is not permitted to fail, any errors returned here will trigger the node to shutdown.
/// So, be careful whenever adding new code that may return errors.
pub fn add_bank_snapshot(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    snapshot_storages: &[Arc<AccountStorageEntry>],
    snapshot_version: SnapshotVersion,
    slot_deltas: Vec<BankSlotDelta>,
) -> snapshot_utils::Result<BankSnapshotInfo> {
    // this lambda function is to facilitate converting between
    // the AddBankSnapshotError and SnapshotError types
    let do_add_bank_snapshot = || {
        let mut measure_everything = Measure::start("");
        let slot = bank.slot();
        let bank_snapshot_dir = get_bank_snapshot_dir(&bank_snapshots_dir, slot);
        if bank_snapshot_dir.exists() {
            return Err(AddBankSnapshotError::SnapshotDirAlreadyExists(
                bank_snapshot_dir,
            ));
        }
        fs::create_dir_all(&bank_snapshot_dir).map_err(|err| {
            AddBankSnapshotError::CreateSnapshotDir(err, bank_snapshot_dir.clone())
        })?;

        // the bank snapshot is stored as bank_snapshots_dir/slot/slot.BANK_SNAPSHOT_PRE_FILENAME_EXTENSION
        let bank_snapshot_path = bank_snapshot_dir
            .join(get_snapshot_file_name(slot))
            .with_extension(snapshot_utils::BANK_SNAPSHOT_PRE_FILENAME_EXTENSION);

        info!(
            "Creating bank snapshot for slot {}, path: {}",
            slot,
            bank_snapshot_path.display(),
        );

        // We are constructing the snapshot directory to contain the full snapshot state information to allow
        // constructing a bank from this directory.  It acts like an archive to include the full state.
        // The set of the account storages files is the necessary part of this snapshot state.  Hard-link them
        // from the operational accounts/ directory to here.
        let (_, measure_hard_linking) =
            measure!(
                hard_link_storages_to_snapshot(&bank_snapshot_dir, slot, snapshot_storages)
                    .map_err(AddBankSnapshotError::HardLinkStorages)?
            );

        let bank_snapshot_serializer =
            move |stream: &mut BufWriter<std::fs::File>| -> snapshot_utils::Result<()> {
                let serde_style = match snapshot_version {
                    SnapshotVersion::V1_2_0 => SerdeStyle::Newer,
                };
                bank_to_stream(
                    serde_style,
                    stream.by_ref(),
                    bank,
                    &get_storages_to_serialize(snapshot_storages),
                )?;
                Ok(())
            };
        let (bank_snapshot_consumed_size, bank_serialize) = measure!(
            serialize_snapshot_data_file(&bank_snapshot_path, bank_snapshot_serializer)
                .map_err(|err| AddBankSnapshotError::SerializeBank(Box::new(err)))?,
            "bank serialize"
        );

        let status_cache_path =
            bank_snapshot_dir.join(snapshot_utils::SNAPSHOT_STATUS_CACHE_FILENAME);
        let (status_cache_consumed_size, status_cache_serialize) =
            measure!(serialize_status_cache(&slot_deltas, &status_cache_path)
                .map_err(|err| AddBankSnapshotError::SerializeStatusCache(Box::new(err)))?);

        let version_path = bank_snapshot_dir.join(snapshot_utils::SNAPSHOT_VERSION_FILENAME);
        let (_, measure_write_version_file) = measure!(fs::write(
            &version_path,
            snapshot_version.as_str().as_bytes(),
        )
        .map_err(|err| AddBankSnapshotError::WriteSnapshotVersionFile(err, version_path))?);

        // Mark this directory complete so it can be used.  Check this flag first before selecting for deserialization.
        let state_complete_path =
            bank_snapshot_dir.join(snapshot_utils::SNAPSHOT_STATE_COMPLETE_FILENAME);
        let (_, measure_write_state_complete_file) =
            measure!(fs::File::create(&state_complete_path).map_err(|err| {
                AddBankSnapshotError::CreateStateCompleteFile(err, state_complete_path)
            })?);

        measure_everything.stop();

        // Monitor sizes because they're capped to MAX_SNAPSHOT_DATA_FILE_SIZE
        datapoint_info!(
            "snapshot_bank",
            ("slot", slot, i64),
            ("bank_size", bank_snapshot_consumed_size, i64),
            ("status_cache_size", status_cache_consumed_size, i64),
            ("hard_link_storages_us", measure_hard_linking.as_us(), i64),
            ("bank_serialize_us", bank_serialize.as_us(), i64),
            (
                "status_cache_serialize_us",
                status_cache_serialize.as_us(),
                i64
            ),
            (
                "write_version_file_us",
                measure_write_version_file.as_us(),
                i64
            ),
            (
                "write_state_complete_file_us",
                measure_write_state_complete_file.as_us(),
                i64
            ),
            ("total_us", measure_everything.as_us(), i64),
        );

        info!(
            "{} for slot {} at {}",
            bank_serialize,
            slot,
            bank_snapshot_path.display(),
        );

        Ok(BankSnapshotInfo {
            slot,
            snapshot_type: BankSnapshotType::Pre,
            snapshot_dir: bank_snapshot_dir,
            snapshot_version,
        })
    };

    do_add_bank_snapshot().map_err(|err| SnapshotError::AddBankSnapshot(err, bank.slot()))
}

fn serialize_status_cache(
    slot_deltas: &[BankSlotDelta],
    status_cache_path: &Path,
) -> snapshot_utils::Result<u64> {
    serialize_snapshot_data_file(status_cache_path, |stream| {
        serialize_into(stream, slot_deltas)?;
        Ok(())
    })
}

#[derive(Debug)]
pub struct BankFromArchivesTimings {
    pub untar_full_snapshot_archive_us: u64,
    pub untar_incremental_snapshot_archive_us: u64,
    pub rebuild_bank_us: u64,
    pub verify_bank_us: u64,
}

#[derive(Debug)]
pub struct BankFromDirTimings {
    pub rebuild_storages_us: u64,
    pub rebuild_bank_us: u64,
}

/// Utility for parsing out bank specific information from a snapshot archive. This utility can be used
/// to parse out bank specific information like the leader schedule, epoch schedule, etc.
pub fn bank_fields_from_snapshot_archives(
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
) -> snapshot_utils::Result<BankFieldsToDeserialize> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir).ok_or_else(|| {
            SnapshotError::NoSnapshotArchives(full_snapshot_archives_dir.as_ref().to_path_buf())
        })?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    let temp_unpack_dir = TempDir::new()?;
    let temp_accounts_dir = TempDir::new()?;

    let account_paths = vec![temp_accounts_dir.path().to_path_buf()];

    let (unarchived_full_snapshot, unarchived_incremental_snapshot, _next_append_vec_id) =
        verify_and_unarchive_snapshots(
            &temp_unpack_dir,
            &full_snapshot_archive_info,
            incremental_snapshot_archive_info.as_ref(),
            &account_paths,
        )?;

    bank_fields_from_snapshots(
        &unarchived_full_snapshot.unpacked_snapshots_dir_and_version,
        unarchived_incremental_snapshot
            .as_ref()
            .map(|unarchive_preparation_result| {
                &unarchive_preparation_result.unpacked_snapshots_dir_and_version
            }),
    )
}

/// Rebuild bank from snapshot archives.  Handles either just a full snapshot, or both a full
/// snapshot and an incremental snapshot.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_snapshot_archives(
    account_paths: &[PathBuf],
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archive_info: &FullSnapshotArchiveInfo,
    incremental_snapshot_archive_info: Option<&IncrementalSnapshotArchiveInfo>,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    accounts_db_force_initial_clean: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(Bank, BankFromArchivesTimings)> {
    info!(
        "Loading bank from full snapshot archive: {}, and incremental snapshot archive: {:?}",
        full_snapshot_archive_info.path().display(),
        incremental_snapshot_archive_info
            .as_ref()
            .map(
                |incremental_snapshot_archive_info| incremental_snapshot_archive_info
                    .path()
                    .display()
            )
    );

    let (unarchived_full_snapshot, mut unarchived_incremental_snapshot, next_append_vec_id) =
        verify_and_unarchive_snapshots(
            bank_snapshots_dir,
            full_snapshot_archive_info,
            incremental_snapshot_archive_info,
            account_paths,
        )?;

    let mut storage = unarchived_full_snapshot.storage;
    if let Some(ref mut unarchive_preparation_result) = unarchived_incremental_snapshot {
        let incremental_snapshot_storages =
            std::mem::take(&mut unarchive_preparation_result.storage);
        storage.extend(incremental_snapshot_storages);
    }

    let storage_and_next_append_vec_id = StorageAndNextAppendVecId {
        storage,
        next_append_vec_id,
    };

    let mut measure_rebuild = Measure::start("rebuild bank from snapshots");
    let bank = rebuild_bank_from_unarchived_snapshots(
        &unarchived_full_snapshot.unpacked_snapshots_dir_and_version,
        unarchived_incremental_snapshot
            .as_ref()
            .map(|unarchive_preparation_result| {
                &unarchive_preparation_result.unpacked_snapshots_dir_and_version
            }),
        account_paths,
        storage_and_next_append_vec_id,
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;
    measure_rebuild.stop();
    info!("{}", measure_rebuild);

    let snapshot_archive_info = incremental_snapshot_archive_info.map_or_else(
        || full_snapshot_archive_info.snapshot_archive_info(),
        |incremental_snapshot_archive_info| {
            incremental_snapshot_archive_info.snapshot_archive_info()
        },
    );
    verify_bank_against_expected_slot_hash(
        &bank,
        snapshot_archive_info.slot,
        snapshot_archive_info.hash,
    )?;

    let base = (incremental_snapshot_archive_info.is_some()
        && bank
            .feature_set
            .is_active(&feature_set::incremental_snapshot_only_incremental_hash_calculation::id()))
    .then(|| {
        let base_slot = full_snapshot_archive_info.slot();
        let base_capitalization = bank
            .rc
            .accounts
            .accounts_db
            .get_accounts_hash(base_slot)
            .expect("accounts hash must exist at full snapshot's slot")
            .1;
        (base_slot, base_capitalization)
    });

    let mut measure_verify = Measure::start("verify");
    if !bank.verify_snapshot_bank(
        test_hash_calculation,
        accounts_db_skip_shrink || !full_snapshot_archive_info.is_remote(),
        accounts_db_force_initial_clean,
        full_snapshot_archive_info.slot(),
        base,
    ) && limit_load_slot_count_from_snapshot.is_none()
    {
        panic!("Snapshot bank for slot {} failed to verify", bank.slot());
    }
    measure_verify.stop();

    let timings = BankFromArchivesTimings {
        untar_full_snapshot_archive_us: unarchived_full_snapshot.measure_untar.as_us(),
        untar_incremental_snapshot_archive_us: unarchived_incremental_snapshot
            .map_or(0, |unarchive_preparation_result| {
                unarchive_preparation_result.measure_untar.as_us()
            }),
        rebuild_bank_us: measure_rebuild.as_us(),
        verify_bank_us: measure_verify.as_us(),
    };
    datapoint_info!(
        "bank_from_snapshot_archives",
        (
            "untar_full_snapshot_archive_us",
            timings.untar_full_snapshot_archive_us,
            i64
        ),
        (
            "untar_incremental_snapshot_archive_us",
            timings.untar_incremental_snapshot_archive_us,
            i64
        ),
        ("rebuild_bank_us", timings.rebuild_bank_us, i64),
        ("verify_bank_us", timings.verify_bank_us, i64),
    );
    Ok((bank, timings))
}

/// Rebuild bank from snapshot archives
///
/// This function searches `full_snapshot_archives_dir` and `incremental_snapshot_archives_dir` for
/// the highest full snapshot and highest corresponding incremental snapshot, then rebuilds the bank.
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_archives(
    bank_snapshots_dir: impl AsRef<Path>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    account_paths: &[PathBuf],
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    test_hash_calculation: bool,
    accounts_db_skip_shrink: bool,
    accounts_db_force_initial_clean: bool,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(
    Bank,
    FullSnapshotArchiveInfo,
    Option<IncrementalSnapshotArchiveInfo>,
)> {
    let full_snapshot_archive_info =
        get_highest_full_snapshot_archive_info(&full_snapshot_archives_dir).ok_or_else(|| {
            SnapshotError::NoSnapshotArchives(full_snapshot_archives_dir.as_ref().to_path_buf())
        })?;

    let incremental_snapshot_archive_info = get_highest_incremental_snapshot_archive_info(
        &incremental_snapshot_archives_dir,
        full_snapshot_archive_info.slot(),
    );

    let (bank, _) = bank_from_snapshot_archives(
        account_paths,
        bank_snapshots_dir.as_ref(),
        &full_snapshot_archive_info,
        incremental_snapshot_archive_info.as_ref(),
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        test_hash_calculation,
        accounts_db_skip_shrink,
        accounts_db_force_initial_clean,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;

    Ok((
        bank,
        full_snapshot_archive_info,
        incremental_snapshot_archive_info,
    ))
}

/// Build bank from a snapshot (a snapshot directory, not a snapshot archive)
#[allow(clippy::too_many_arguments)]
pub fn bank_from_snapshot_dir(
    account_paths: &[PathBuf],
    bank_snapshot: &BankSnapshotInfo,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<(Bank, BankFromDirTimings)> {
    info!(
        "Loading bank from snapshot dir: {}",
        bank_snapshot.snapshot_dir.display()
    );

    // Clear the contents of the account paths run directories.  When constructing the bank, the appendvec
    // files will be extracted from the snapshot hardlink directories into these run/ directories.
    for path in account_paths {
        delete_contents_of_path(path);
    }

    let next_append_vec_id = Arc::new(AtomicAppendVecId::new(0));

    let (storage, measure_rebuild_storages) = measure!(
        rebuild_storages_from_snapshot_dir(
            bank_snapshot,
            account_paths,
            next_append_vec_id.clone()
        )?,
        "rebuild storages from snapshot dir"
    );
    info!("{}", measure_rebuild_storages);

    let next_append_vec_id =
        Arc::try_unwrap(next_append_vec_id).expect("this is the only strong reference");
    let storage_and_next_append_vec_id = StorageAndNextAppendVecId {
        storage,
        next_append_vec_id,
    };
    let (bank, measure_rebuild_bank) = measure!(
        rebuild_bank_from_snapshot(
            bank_snapshot,
            account_paths,
            storage_and_next_append_vec_id,
            genesis_config,
            runtime_config,
            debug_keys,
            additional_builtins,
            account_secondary_indexes,
            limit_load_slot_count_from_snapshot,
            shrink_ratio,
            verify_index,
            accounts_db_config,
            accounts_update_notifier,
            exit,
        )?,
        "rebuild bank from snapshot"
    );
    info!("{}", measure_rebuild_bank);

    // Skip bank.verify_snapshot_bank.  Subsequent snapshot requests/accounts hash verification requests
    // will calculate and check the accounts hash, so we will still have safety/correctness there.
    bank.set_initial_accounts_hash_verification_completed();

    let timings = BankFromDirTimings {
        rebuild_storages_us: measure_rebuild_storages.as_us(),
        rebuild_bank_us: measure_rebuild_bank.as_us(),
    };
    datapoint_info!(
        "bank_from_snapshot_dir",
        ("rebuild_storages_us", timings.rebuild_storages_us, i64),
        ("rebuild_bank_us", timings.rebuild_bank_us, i64),
    );
    Ok((bank, timings))
}

/// follow the prototype of fn bank_from_latest_snapshot_archives, implement the from_dir case
#[allow(clippy::too_many_arguments)]
pub fn bank_from_latest_snapshot_dir(
    bank_snapshots_dir: impl AsRef<Path>,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    account_paths: &[PathBuf],
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    let bank_snapshot = get_highest_bank_snapshot_post(&bank_snapshots_dir).ok_or_else(|| {
        SnapshotError::NoSnapshotSlotDir(bank_snapshots_dir.as_ref().to_path_buf())
    })?;

    let (bank, _) = bank_from_snapshot_dir(
        account_paths,
        &bank_snapshot,
        genesis_config,
        runtime_config,
        debug_keys,
        additional_builtins,
        account_secondary_indexes,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
        exit,
    )?;

    Ok(bank)
}

/// Check to make sure the deserialized bank's slot and hash matches the snapshot archive's slot
/// and hash
fn verify_bank_against_expected_slot_hash(
    bank: &Bank,
    expected_slot: Slot,
    expected_hash: SnapshotHash,
) -> snapshot_utils::Result<()> {
    let bank_slot = bank.slot();
    let bank_hash = bank.get_snapshot_hash();

    if bank_slot != expected_slot || bank_hash != expected_hash {
        return Err(SnapshotError::MismatchedSlotHash(
            (bank_slot, bank_hash),
            (expected_slot, expected_hash),
        ));
    }

    Ok(())
}

fn bank_fields_from_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
) -> snapshot_utils::Result<BankFieldsToDeserialize> {
    let (full_snapshot_version, full_snapshot_root_paths) =
        verify_unpacked_snapshots_dir_and_version(
            full_snapshot_unpacked_snapshots_dir_and_version,
        )?;
    let (incremental_snapshot_version, incremental_snapshot_root_paths) =
        if let Some(snapshot_unpacked_snapshots_dir_and_version) =
            incremental_snapshot_unpacked_snapshots_dir_and_version
        {
            let (snapshot_version, bank_snapshot_info) = verify_unpacked_snapshots_dir_and_version(
                snapshot_unpacked_snapshots_dir_and_version,
            )?;
            (Some(snapshot_version), Some(bank_snapshot_info))
        } else {
            (None, None)
        };
    info!(
        "Loading bank from full snapshot {} and incremental snapshot {:?}",
        full_snapshot_root_paths.snapshot_path().display(),
        incremental_snapshot_root_paths
            .as_ref()
            .map(|paths| paths.snapshot_path()),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: full_snapshot_root_paths.snapshot_path(),
        incremental_snapshot_root_file_path: incremental_snapshot_root_paths
            .map(|root_paths| root_paths.snapshot_path()),
    };

    deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => fields_from_streams(SerdeStyle::Newer, snapshot_streams)
                    .map(|(bank_fields, _accountsdb_fields)| bank_fields.collapse_into()),
            }?,
        )
    })
}

fn deserialize_status_cache(
    status_cache_path: &Path,
) -> snapshot_utils::Result<Vec<BankSlotDelta>> {
    deserialize_snapshot_data_file(status_cache_path, |stream| {
        info!(
            "Rebuilding status cache from {}",
            status_cache_path.display()
        );
        let slot_delta: Vec<BankSlotDelta> = bincode::options()
            .with_limit(snapshot_utils::MAX_SNAPSHOT_DATA_FILE_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize_from(stream)?;
        Ok(slot_delta)
    })
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank_from_unarchived_snapshots(
    full_snapshot_unpacked_snapshots_dir_and_version: &UnpackedSnapshotsDirAndVersion,
    incremental_snapshot_unpacked_snapshots_dir_and_version: Option<
        &UnpackedSnapshotsDirAndVersion,
    >,
    account_paths: &[PathBuf],
    storage_and_next_append_vec_id: StorageAndNextAppendVecId,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    let (full_snapshot_version, full_snapshot_root_paths) =
        verify_unpacked_snapshots_dir_and_version(
            full_snapshot_unpacked_snapshots_dir_and_version,
        )?;
    let (incremental_snapshot_version, incremental_snapshot_root_paths) =
        if let Some(snapshot_unpacked_snapshots_dir_and_version) =
            incremental_snapshot_unpacked_snapshots_dir_and_version
        {
            Some(verify_unpacked_snapshots_dir_and_version(
                snapshot_unpacked_snapshots_dir_and_version,
            )?)
        } else {
            None
        }
        .unzip();
    info!(
        "Rebuilding bank from full snapshot {} and incremental snapshot {:?}",
        full_snapshot_root_paths.snapshot_path().display(),
        incremental_snapshot_root_paths
            .as_ref()
            .map(|paths| paths.snapshot_path()),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: full_snapshot_root_paths.snapshot_path(),
        incremental_snapshot_root_file_path: incremental_snapshot_root_paths
            .map(|root_paths| root_paths.snapshot_path()),
    };

    let bank = deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(
            match incremental_snapshot_version.unwrap_or(full_snapshot_version) {
                SnapshotVersion::V1_2_0 => bank_from_streams(
                    SerdeStyle::Newer,
                    snapshot_streams,
                    account_paths,
                    storage_and_next_append_vec_id,
                    genesis_config,
                    runtime_config,
                    debug_keys,
                    additional_builtins,
                    account_secondary_indexes,
                    limit_load_slot_count_from_snapshot,
                    shrink_ratio,
                    verify_index,
                    accounts_db_config,
                    accounts_update_notifier,
                    exit,
                ),
            }?,
        )
    })?;

    // The status cache is rebuilt from the latest snapshot.  So, if there's an incremental
    // snapshot, use that.  Otherwise use the full snapshot.
    let status_cache_path = incremental_snapshot_unpacked_snapshots_dir_and_version
        .map_or_else(
            || {
                full_snapshot_unpacked_snapshots_dir_and_version
                    .unpacked_snapshots_dir
                    .as_path()
            },
            |unpacked_snapshots_dir_and_version| {
                unpacked_snapshots_dir_and_version
                    .unpacked_snapshots_dir
                    .as_path()
            },
        )
        .join(snapshot_utils::SNAPSHOT_STATUS_CACHE_FILENAME);
    let slot_deltas = deserialize_status_cache(&status_cache_path)?;

    verify_slot_deltas(slot_deltas.as_slice(), &bank)?;

    bank.status_cache.write().unwrap().append(&slot_deltas);

    info!("Rebuilt bank for slot: {}", bank.slot());
    Ok(bank)
}

#[allow(clippy::too_many_arguments)]
fn rebuild_bank_from_snapshot(
    bank_snapshot: &BankSnapshotInfo,
    account_paths: &[PathBuf],
    storage_and_next_append_vec_id: StorageAndNextAppendVecId,
    genesis_config: &GenesisConfig,
    runtime_config: &RuntimeConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&[BuiltinPrototype]>,
    account_secondary_indexes: AccountSecondaryIndexes,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    exit: Arc<AtomicBool>,
) -> snapshot_utils::Result<Bank> {
    info!(
        "Rebuilding bank from snapshot {}",
        bank_snapshot.snapshot_dir.display(),
    );

    let snapshot_root_paths = SnapshotRootPaths {
        full_snapshot_root_file_path: bank_snapshot.snapshot_path(),
        incremental_snapshot_root_file_path: None,
    };

    let bank = deserialize_snapshot_data_files(&snapshot_root_paths, |snapshot_streams| {
        Ok(bank_from_streams(
            SerdeStyle::Newer,
            snapshot_streams,
            account_paths,
            storage_and_next_append_vec_id,
            genesis_config,
            runtime_config,
            debug_keys,
            additional_builtins,
            account_secondary_indexes,
            limit_load_slot_count_from_snapshot,
            shrink_ratio,
            verify_index,
            accounts_db_config,
            accounts_update_notifier,
            exit,
        )?)
    })?;

    let status_cache_path = bank_snapshot
        .snapshot_dir
        .join(snapshot_utils::SNAPSHOT_STATUS_CACHE_FILENAME);
    let slot_deltas = deserialize_status_cache(&status_cache_path)?;

    verify_slot_deltas(slot_deltas.as_slice(), &bank)?;

    bank.status_cache.write().unwrap().append(&slot_deltas);

    info!("Rebuilt bank for slot: {}", bank.slot());
    Ok(bank)
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
fn verify_slot_deltas(
    slot_deltas: &[BankSlotDelta],
    bank: &Bank,
) -> std::result::Result<(), VerifySlotDeltasError> {
    let info = verify_slot_deltas_structural(slot_deltas, bank.slot())?;
    verify_slot_deltas_with_history(&info.slots, &bank.get_slot_history(), bank.slot())
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
/// These checks are simple/structural
fn verify_slot_deltas_structural(
    slot_deltas: &[BankSlotDelta],
    bank_slot: Slot,
) -> std::result::Result<VerifySlotDeltasStructuralInfo, VerifySlotDeltasError> {
    // there should not be more entries than that status cache's max
    let num_entries = slot_deltas.len();
    if num_entries > status_cache::MAX_CACHE_ENTRIES {
        return Err(VerifySlotDeltasError::TooManyEntries(
            num_entries,
            status_cache::MAX_CACHE_ENTRIES,
        ));
    }

    let mut slots_seen_so_far = HashSet::new();
    for &(slot, is_root, ..) in slot_deltas {
        // all entries should be roots
        if !is_root {
            return Err(VerifySlotDeltasError::SlotIsNotRoot(slot));
        }

        // all entries should be for slots less than or equal to the bank's slot
        if slot > bank_slot {
            return Err(VerifySlotDeltasError::SlotGreaterThanMaxRoot(
                slot, bank_slot,
            ));
        }

        // there should only be one entry per slot
        let is_duplicate = !slots_seen_so_far.insert(slot);
        if is_duplicate {
            return Err(VerifySlotDeltasError::SlotHasMultipleEntries(slot));
        }
    }

    // detect serious logic error for future careless changes. :)
    assert_eq!(slots_seen_so_far.len(), slot_deltas.len());

    Ok(VerifySlotDeltasStructuralInfo {
        slots: slots_seen_so_far,
    })
}

/// Computed information from `verify_slot_deltas_structural()`, that may be reused/useful later.
#[derive(Debug, PartialEq, Eq)]
struct VerifySlotDeltasStructuralInfo {
    /// All the slots in the slot deltas
    slots: HashSet<Slot>,
}

/// Verify that the snapshot's slot deltas are not corrupt/invalid
/// These checks use the slot history for verification
fn verify_slot_deltas_with_history(
    slots_from_slot_deltas: &HashSet<Slot>,
    slot_history: &SlotHistory,
    bank_slot: Slot,
) -> std::result::Result<(), VerifySlotDeltasError> {
    // ensure the slot history is valid (as much as possible), since we're using it to verify the
    // slot deltas
    if slot_history.newest() != bank_slot {
        return Err(VerifySlotDeltasError::BadSlotHistory);
    }

    // all slots in the slot deltas should be in the bank's slot history
    let slot_missing_from_history = slots_from_slot_deltas
        .iter()
        .find(|slot| slot_history.check(**slot) != Check::Found);
    if let Some(slot) = slot_missing_from_history {
        return Err(VerifySlotDeltasError::SlotNotFoundInHistory(*slot));
    }

    // all slots in the history should be in the slot deltas (up to MAX_CACHE_ENTRIES)
    // this ensures nothing was removed from the status cache
    //
    // go through the slot history and make sure there's an entry for each slot
    // note: it's important to go highest-to-lowest since the status cache removes
    // older entries first
    // note: we already checked above that `bank_slot == slot_history.newest()`
    let slot_missing_from_deltas = (slot_history.oldest()..=slot_history.newest())
        .rev()
        .filter(|slot| slot_history.check(*slot) == Check::Found)
        .take(status_cache::MAX_CACHE_ENTRIES)
        .find(|slot| !slots_from_slot_deltas.contains(slot));
    if let Some(slot) = slot_missing_from_deltas {
        return Err(VerifySlotDeltasError::SlotNotFoundInDeltas(slot));
    }

    Ok(())
}

/// Get the snapshot storages for this bank
pub fn get_snapshot_storages(bank: &Bank) -> Vec<Arc<AccountStorageEntry>> {
    let mut measure_snapshot_storages = Measure::start("snapshot-storages");
    let snapshot_storages = bank.get_snapshot_storages(None);
    measure_snapshot_storages.stop();
    datapoint_info!(
        "get_snapshot_storages",
        (
            "snapshot-storages-time-ms",
            measure_snapshot_storages.as_ms(),
            i64
        ),
    );

    snapshot_storages
}

/// Convenience function to create a full snapshot archive out of any Bank, regardless of state.
/// The Bank will be frozen during the process.
/// This is only called from ledger-tool or tests. Warping is a special case as well.
///
/// Requires:
///     - `bank` is complete
pub fn bank_to_full_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    snapshot_version: Option<SnapshotVersion>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
    maximum_full_snapshot_archives_to_retain: NonZeroUsize,
    maximum_incremental_snapshot_archives_to_retain: NonZeroUsize,
) -> snapshot_utils::Result<FullSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();

    assert!(bank.is_complete());
    bank.squash(); // Bank may not be a root
    bank.force_flush_accounts_cache();
    bank.clean_accounts(Some(bank.slot()));
    bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);
    bank.rehash(); // Bank accounts may have been manually modified by the caller

    let temp_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    let snapshot_storages = bank.get_snapshot_storages(None);
    let slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let bank_snapshot_info = add_bank_snapshot(
        &temp_dir,
        bank,
        &snapshot_storages,
        snapshot_version,
        slot_deltas,
    )?;

    package_and_archive_full_snapshot(
        bank,
        &bank_snapshot_info,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
}

/// Convenience function to create an incremental snapshot archive out of any Bank, regardless of
/// state.  The Bank will be frozen during the process.
/// This is only called from ledger-tool or tests. Warping is a special case as well.
///
/// Requires:
///     - `bank` is complete
///     - `bank`'s slot is greater than `full_snapshot_slot`
pub fn bank_to_incremental_snapshot_archive(
    bank_snapshots_dir: impl AsRef<Path>,
    bank: &Bank,
    full_snapshot_slot: Slot,
    snapshot_version: Option<SnapshotVersion>,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    archive_format: ArchiveFormat,
    maximum_full_snapshot_archives_to_retain: NonZeroUsize,
    maximum_incremental_snapshot_archives_to_retain: NonZeroUsize,
) -> snapshot_utils::Result<IncrementalSnapshotArchiveInfo> {
    let snapshot_version = snapshot_version.unwrap_or_default();

    assert!(bank.is_complete());
    assert!(bank.slot() > full_snapshot_slot);
    bank.squash(); // Bank may not be a root
    bank.force_flush_accounts_cache();
    bank.clean_accounts(Some(full_snapshot_slot));
    if bank
        .feature_set
        .is_active(&feature_set::incremental_snapshot_only_incremental_hash_calculation::id())
    {
        bank.update_incremental_accounts_hash(full_snapshot_slot);
    } else {
        bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);
    }
    bank.rehash(); // Bank accounts may have been manually modified by the caller

    let temp_dir = tempfile::tempdir_in(bank_snapshots_dir)?;
    let snapshot_storages = bank.get_snapshot_storages(Some(full_snapshot_slot));
    let slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
    let bank_snapshot_info = add_bank_snapshot(
        &temp_dir,
        bank,
        &snapshot_storages,
        snapshot_version,
        slot_deltas,
    )?;

    package_and_archive_incremental_snapshot(
        bank,
        full_snapshot_slot,
        &bank_snapshot_info,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )
}

/// Helper function to hold shared code to package, process, and archive full snapshots
#[allow(clippy::too_many_arguments)]
pub fn package_and_archive_full_snapshot(
    bank: &Bank,
    bank_snapshot_info: &BankSnapshotInfo,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: Vec<Arc<AccountStorageEntry>>,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: NonZeroUsize,
    maximum_incremental_snapshot_archives_to_retain: NonZeroUsize,
) -> snapshot_utils::Result<FullSnapshotArchiveInfo> {
    let accounts_package = AccountsPackage::new_for_snapshot(
        AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot),
        bank,
        bank_snapshot_info,
        &full_snapshot_archives_dir,
        &incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
    );

    let accounts_hash = bank
        .get_accounts_hash()
        .expect("accounts hash is required for snapshot");
    crate::serde_snapshot::reserialize_bank_with_new_accounts_hash(
        accounts_package.bank_snapshot_dir(),
        accounts_package.slot,
        &accounts_hash,
        None,
    );

    let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash.into());
    archive_snapshot_package(
        &snapshot_package,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )?;

    Ok(FullSnapshotArchiveInfo::new(
        snapshot_package.snapshot_archive_info,
    ))
}

/// Helper function to hold shared code to package, process, and archive incremental snapshots
#[allow(clippy::too_many_arguments)]
pub fn package_and_archive_incremental_snapshot(
    bank: &Bank,
    incremental_snapshot_base_slot: Slot,
    bank_snapshot_info: &BankSnapshotInfo,
    full_snapshot_archives_dir: impl AsRef<Path>,
    incremental_snapshot_archives_dir: impl AsRef<Path>,
    snapshot_storages: Vec<Arc<AccountStorageEntry>>,
    archive_format: ArchiveFormat,
    snapshot_version: SnapshotVersion,
    maximum_full_snapshot_archives_to_retain: NonZeroUsize,
    maximum_incremental_snapshot_archives_to_retain: NonZeroUsize,
) -> snapshot_utils::Result<IncrementalSnapshotArchiveInfo> {
    let accounts_package = AccountsPackage::new_for_snapshot(
        AccountsPackageKind::Snapshot(SnapshotKind::IncrementalSnapshot(
            incremental_snapshot_base_slot,
        )),
        bank,
        bank_snapshot_info,
        &full_snapshot_archives_dir,
        &incremental_snapshot_archives_dir,
        snapshot_storages,
        archive_format,
        snapshot_version,
        None,
    );

    let (accounts_hash_kind, accounts_hash_for_reserialize, bank_incremental_snapshot_persistence) =
        if bank
            .feature_set
            .is_active(&feature_set::incremental_snapshot_only_incremental_hash_calculation::id())
        {
            let (base_accounts_hash, base_capitalization) = bank
                .rc
                .accounts
                .accounts_db
                .get_accounts_hash(incremental_snapshot_base_slot)
                .expect("base accounts hash is required for incremental snapshot");
            let (incremental_accounts_hash, incremental_capitalization) = bank
                .rc
                .accounts
                .accounts_db
                .get_incremental_accounts_hash(bank.slot())
                .expect("incremental accounts hash is required for incremental snapshot");
            let bank_incremental_snapshot_persistence = BankIncrementalSnapshotPersistence {
                full_slot: incremental_snapshot_base_slot,
                full_hash: base_accounts_hash.into(),
                full_capitalization: base_capitalization,
                incremental_hash: incremental_accounts_hash.into(),
                incremental_capitalization,
            };
            (
                incremental_accounts_hash.into(),
                AccountsHash(Hash::default()), // value does not matter; not used for incremental snapshots
                Some(bank_incremental_snapshot_persistence),
            )
        } else {
            let accounts_hash = bank
                .get_accounts_hash()
                .expect("accounts hash is required for snapshot");
            (accounts_hash.into(), accounts_hash, None)
        };

    crate::serde_snapshot::reserialize_bank_with_new_accounts_hash(
        accounts_package.bank_snapshot_dir(),
        accounts_package.slot,
        &accounts_hash_for_reserialize,
        bank_incremental_snapshot_persistence.as_ref(),
    );

    let snapshot_package = SnapshotPackage::new(accounts_package, accounts_hash_kind);
    archive_snapshot_package(
        &snapshot_package,
        full_snapshot_archives_dir,
        incremental_snapshot_archives_dir,
        maximum_full_snapshot_archives_to_retain,
        maximum_incremental_snapshot_archives_to_retain,
    )?;

    Ok(IncrementalSnapshotArchiveInfo::new(
        incremental_snapshot_base_slot,
        snapshot_package.snapshot_archive_info,
    ))
}

#[cfg(feature = "dev-context-only-utils")]
pub fn create_snapshot_dirs_for_tests(
    genesis_config: &GenesisConfig,
    bank_snapshots_dir: impl AsRef<Path>,
    num_total: usize,
    num_posts: usize,
) -> Bank {
    let mut bank = Arc::new(Bank::new_for_tests(genesis_config));

    let collecter_id = Pubkey::new_unique();
    let snapshot_version = SnapshotVersion::default();

    // loop to create the banks at slot 1 to num_total
    for _ in 0..num_total {
        // prepare the bank
        let slot = bank.slot() + 1;
        bank = Arc::new(Bank::new_from_parent(bank, &collecter_id, slot));
        bank.fill_bank_with_ticks_for_tests();
        bank.squash();
        bank.force_flush_accounts_cache();
        bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);

        let snapshot_storages = bank.get_snapshot_storages(None);
        let slot_deltas = bank.status_cache.read().unwrap().root_slot_deltas();
        let bank_snapshot_info = add_bank_snapshot(
            &bank_snapshots_dir,
            &bank,
            &snapshot_storages,
            snapshot_version,
            slot_deltas,
        )
        .unwrap();

        if bank.slot() as usize > num_posts {
            continue; // leave the snapshot dir at PRE stage
        }

        // Reserialize the snapshot dir to convert it from PRE to POST, because only the POST type can be used
        // to construct a bank.
        assert!(
            crate::serde_snapshot::reserialize_bank_with_new_accounts_hash(
                &bank_snapshot_info.snapshot_dir,
                bank.slot(),
                &bank.get_accounts_hash().unwrap(),
                None
            )
        );
    }

    Arc::try_unwrap(bank).unwrap()
}
