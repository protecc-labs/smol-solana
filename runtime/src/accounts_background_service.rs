//! Service to clean up dead slots in accounts_db
//!
//! This can be expensive since we have to walk the append vecs being cleaned up.

mod stats;
#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::{
        bank::{Bank, BankSlotDelta, DropCallback},
        bank_forks::BankForks,
        snapshot_bank_utils,
        snapshot_config::SnapshotConfig,
        snapshot_package::{self, AccountsPackage, AccountsPackageKind, SnapshotKind},
        snapshot_utils::{self, SnapshotError},
    },
    crossbeam_channel::{Receiver, SendError, Sender},
    log::*,
    rand::{thread_rng, Rng},
    rayon::iter::{IntoParallelIterator, ParallelIterator},
    solana_accounts_db::{
        accounts_db::CalcAccountsHashDataSource, accounts_hash::CalcAccountsHashConfig,
    },
    solana_measure::{measure::Measure, measure_us},
    solana_sdk::clock::{BankId, Slot},
    stats::StatsManager,
    std::{
        boxed::Box,
        fmt::{Debug, Formatter},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

const INTERVAL_MS: u64 = 100;
const CLEAN_INTERVAL_BLOCKS: u64 = 100;

// This value is chosen to spread the dropping cost over 3 expiration checks
// RecycleStores are fully populated almost all of its lifetime. So, otherwise
// this would drop MAX_RECYCLE_STORES mmaps at once in the worst case...
// (Anyway, the dropping part is outside the AccountsDb::recycle_stores lock
// and dropped in this AccountsBackgroundServe, so this shouldn't matter much)
const RECYCLE_STORE_EXPIRATION_INTERVAL_SECS: u64 =
    solana_accounts_db::accounts_db::EXPIRATION_TTL_SECONDS / 3;

pub type SnapshotRequestSender = Sender<SnapshotRequest>;
pub type SnapshotRequestReceiver = Receiver<SnapshotRequest>;
pub type DroppedSlotsSender = Sender<(Slot, BankId)>;
pub type DroppedSlotsReceiver = Receiver<(Slot, BankId)>;

/// interval to report bank_drop queue events: 60s
const BANK_DROP_SIGNAL_CHANNEL_REPORT_INTERVAL: u64 = 60_000;
/// maximum drop bank signal queue length
const MAX_DROP_BANK_SIGNAL_QUEUE_SIZE: usize = 10_000;

#[derive(Debug, Default)]
struct PrunedBankQueueLenReporter {
    last_report_time: AtomicU64,
}

impl PrunedBankQueueLenReporter {
    fn report(&self, q_len: usize) {
        let now = solana_sdk::timing::timestamp();
        let last_report_time = self.last_report_time.load(Ordering::Acquire);
        if q_len > MAX_DROP_BANK_SIGNAL_QUEUE_SIZE
            && now.saturating_sub(last_report_time) > BANK_DROP_SIGNAL_CHANNEL_REPORT_INTERVAL
        {
            datapoint_warn!("excessive_pruned_bank_channel_len", ("len", q_len, i64));
            self.last_report_time.store(now, Ordering::Release);
        }
    }
}

lazy_static! {
    static ref BANK_DROP_QUEUE_REPORTER: PrunedBankQueueLenReporter =
        PrunedBankQueueLenReporter::default();
}

#[derive(Clone)]
pub struct SendDroppedBankCallback {
    sender: DroppedSlotsSender,
}

impl DropCallback for SendDroppedBankCallback {
    fn callback(&self, bank: &Bank) {
        BANK_DROP_QUEUE_REPORTER.report(self.sender.len());
        if let Err(SendError(_)) = self.sender.send((bank.slot(), bank.bank_id())) {
            info!("bank DropCallback signal queue disconnected.");
        }
    }

    fn clone_box(&self) -> Box<dyn DropCallback + Send + Sync> {
        Box::new(self.clone())
    }
}

impl Debug for SendDroppedBankCallback {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "SendDroppedBankCallback({self:p})")
    }
}

impl SendDroppedBankCallback {
    pub fn new(sender: DroppedSlotsSender) -> Self {
        Self { sender }
    }
}

pub struct SnapshotRequest {
    pub snapshot_root_bank: Arc<Bank>,
    pub status_cache_slot_deltas: Vec<BankSlotDelta>,
    pub request_kind: SnapshotRequestKind,

    /// The instant this request was send to the queue.
    /// Used to track how long requests wait before processing.
    pub enqueued: Instant,
}

impl Debug for SnapshotRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotRequest")
            .field("request type", &self.request_kind)
            .field("bank slot", &self.snapshot_root_bank.slot())
            .finish()
    }
}

/// What kind of request is this?
///
/// The snapshot request has been expanded to support more than just snapshots.  This is
/// confusing, but can be resolved by renaming this type; or better, by creating an enum with
/// variants that wrap the fields-of-interest for each request.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SnapshotRequestKind {
    Snapshot,
    EpochAccountsHash,
}

pub struct SnapshotRequestHandler {
    pub snapshot_config: SnapshotConfig,
    pub snapshot_request_sender: SnapshotRequestSender,
    pub snapshot_request_receiver: SnapshotRequestReceiver,
    pub accounts_package_sender: Sender<AccountsPackage>,
}

impl SnapshotRequestHandler {
    // Returns the latest requested snapshot block height and storages
    #[allow(clippy::type_complexity)]
    pub fn handle_snapshot_requests(
        &self,
        test_hash_calculation: bool,
        non_snapshot_time_us: u128,
        last_full_snapshot_slot: &mut Option<Slot>,
        exit: &AtomicBool,
    ) -> Option<Result<u64, SnapshotError>> {
        let (
            snapshot_request,
            accounts_package_kind,
            num_outstanding_requests,
            num_re_enqueued_requests,
        ) = self.get_next_snapshot_request(*last_full_snapshot_slot)?;

        datapoint_info!(
            "handle_snapshot_requests",
            ("num_outstanding_requests", num_outstanding_requests, i64),
            ("num_re_enqueued_requests", num_re_enqueued_requests, i64),
            (
                "enqueued_time_us",
                snapshot_request.enqueued.elapsed().as_micros(),
                i64
            ),
        );

        Some(self.handle_snapshot_request(
            test_hash_calculation,
            non_snapshot_time_us,
            last_full_snapshot_slot,
            snapshot_request,
            accounts_package_kind,
            exit,
        ))
    }

    /// Get the next snapshot request to handle
    ///
    /// Look through the snapshot request channel to find the highest priority one to handle next.
    /// If there are no snapshot requests in the channel, return None.  Otherwise return the
    /// highest priority one.  Unhandled snapshot requests with slots GREATER-THAN the handled one
    /// will be re-enqueued.  The remaining will be dropped.
    ///
    /// Also return the number of snapshot requests initially in the channel, and the number of
    /// ones re-enqueued.
    fn get_next_snapshot_request(
        &self,
        last_full_snapshot_slot: Option<Slot>,
    ) -> Option<(
        SnapshotRequest,
        AccountsPackageKind,
        /*num outstanding snapshot requests*/ usize,
        /*num re-enqueued snapshot requests*/ usize,
    )> {
        let mut requests: Vec<_> = self
            .snapshot_request_receiver
            .try_iter()
            .map(|request| {
                let accounts_package_kind = new_accounts_package_kind(
                    &request,
                    &self.snapshot_config,
                    last_full_snapshot_slot,
                );
                (request, accounts_package_kind)
            })
            .collect();
        let requests_len = requests.len();
        debug!("outstanding snapshot requests ({requests_len}): {requests:?}");

        // NOTE: This code to select the next request is mirrored in AccountsHashVerifier.
        // Please ensure they stay in sync.
        match requests_len {
            0 => None,
            1 => {
                // SAFETY: We know the len is 1, so `pop` will return `Some`
                let (snapshot_request, accounts_package_kind) = requests.pop().unwrap();
                Some((snapshot_request, accounts_package_kind, 1, 0))
            }
            _ => {
                let num_eah_requests = requests
                    .iter()
                    .filter(|(_, account_package_kind)| {
                        *account_package_kind == AccountsPackageKind::EpochAccountsHash
                    })
                    .count();
                assert!(
                    num_eah_requests <= 1,
                    "Only a single EAH request is allowed at a time! count: {num_eah_requests}"
                );

                // Get the two highest priority requests, `y` and `z`.
                // By asking for the second-to-last element to be in its final sorted position, we
                // also ensure that the last element is also sorted.
                let (_, y, z) =
                    requests.select_nth_unstable_by(requests_len - 2, cmp_requests_by_priority);
                assert_eq!(z.len(), 1);
                let z = z.first().unwrap();
                let y: &_ = y; // reborrow to remove `mut`

                // If the highest priority request (`z`) is EpochAccountsHash, we need to check if
                // there's a FullSnapshot request with a lower slot in `y` that is about to be
                // dropped.  We do not want to drop a FullSnapshot request in this case because it
                // will cause subsequent IncrementalSnapshot requests to fail.
                //
                // So, if `z` is an EpochAccountsHash request, check `y`.  We know there can only
                // be at most one EpochAccountsHash request, so `y` is the only other request we
                // need to check.  If `y` is a FullSnapshot request *with a lower slot* than `z`,
                // then handle `y` first.
                let (snapshot_request, accounts_package_kind) = if z.1
                    == AccountsPackageKind::EpochAccountsHash
                    && y.1 == AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot)
                    && y.0.snapshot_root_bank.slot() < z.0.snapshot_root_bank.slot()
                {
                    // SAFETY: We know the len is > 1, so both `pop`s will return `Some`
                    let z = requests.pop().unwrap();
                    let y = requests.pop().unwrap();
                    requests.push(z);
                    y
                } else {
                    // SAFETY: We know the len is > 1, so `pop` will return `Some`
                    requests.pop().unwrap()
                };

                let handled_request_slot = snapshot_request.snapshot_root_bank.slot();
                // re-enqueue any remaining requests for slots GREATER-THAN the one that will be handled
                let num_re_enqueued_requests = requests
                    .into_iter()
                    .filter(|(snapshot_request, _)| {
                        snapshot_request.snapshot_root_bank.slot() > handled_request_slot
                    })
                    .map(|(snapshot_request, _)| {
                        self.snapshot_request_sender
                            .try_send(snapshot_request)
                            .expect("re-enqueue snapshot request")
                    })
                    .count();

                Some((
                    snapshot_request,
                    accounts_package_kind,
                    requests_len,
                    num_re_enqueued_requests,
                ))
            }
        }
    }

    fn handle_snapshot_request(
        &self,
        test_hash_calculation: bool,
        non_snapshot_time_us: u128,
        last_full_snapshot_slot: &mut Option<Slot>,
        snapshot_request: SnapshotRequest,
        accounts_package_kind: AccountsPackageKind,
        exit: &AtomicBool,
    ) -> Result<u64, SnapshotError> {
        debug!(
            "handling snapshot request: {:?}, {:?}",
            snapshot_request, accounts_package_kind
        );
        let mut total_time = Measure::start("snapshot_request_receiver_total_time");
        let SnapshotRequest {
            snapshot_root_bank,
            status_cache_slot_deltas,
            request_kind,
            enqueued: _,
        } = snapshot_request;

        // we should not rely on the state of this validator until startup verification is complete
        assert!(snapshot_root_bank.is_startup_verification_complete());

        if accounts_package_kind == AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot) {
            *last_full_snapshot_slot = Some(snapshot_root_bank.slot());
        }

        let previous_accounts_hash = test_hash_calculation.then(|| {
            // We have to use the index version here.
            // We cannot calculate the non-index way because cache has not been flushed and stores don't match reality.
            snapshot_root_bank.update_accounts_hash(
                CalcAccountsHashDataSource::IndexForTests,
                false,
                false,
            )
        });

        let mut flush_accounts_cache_time = Measure::start("flush_accounts_cache_time");
        // Forced cache flushing MUST flush all roots <= snapshot_root_bank.slot().
        // That's because `snapshot_root_bank.slot()` must be root at this point,
        // and contains relevant updates because each bank has at least 1 account update due
        // to sysvar maintenance. Otherwise, this would cause missing storages in the snapshot
        snapshot_root_bank.force_flush_accounts_cache();
        // Ensure all roots <= `self.slot()` have been flushed.
        // Note `max_flush_root` could be larger than self.slot() if there are
        // `> MAX_CACHE_SLOT` cached and rooted slots which triggered earlier flushes.
        assert!(
            snapshot_root_bank.slot()
                <= snapshot_root_bank
                    .rc
                    .accounts
                    .accounts_db
                    .accounts_cache
                    .fetch_max_flush_root()
        );
        flush_accounts_cache_time.stop();

        let accounts_hash_for_testing = previous_accounts_hash.map(|previous_accounts_hash| {
            let check_hash = false;

            let (this_accounts_hash, capitalization) = snapshot_root_bank
                .accounts()
                .accounts_db
                .calculate_accounts_hash(
                    CalcAccountsHashDataSource::Storages,
                    snapshot_root_bank.slot(),
                    &CalcAccountsHashConfig {
                        use_bg_thread_pool: true,
                        check_hash,
                        ancestors: None,
                        epoch_schedule: snapshot_root_bank.epoch_schedule(),
                        rent_collector: snapshot_root_bank.rent_collector(),
                        store_detailed_debug_info_on_failure: false,
                    },
                )
                .unwrap();
            assert_eq!(previous_accounts_hash, this_accounts_hash);
            assert_eq!(capitalization, snapshot_root_bank.capitalization());
            this_accounts_hash
        });

        let mut clean_time = Measure::start("clean_time");
        snapshot_root_bank.clean_accounts(*last_full_snapshot_slot);
        clean_time.stop();

        let (_, shrink_ancient_time_us) = measure_us!(snapshot_root_bank.shrink_ancient_slots());

        let mut shrink_time = Measure::start("shrink_time");
        snapshot_root_bank.shrink_candidate_slots();
        shrink_time.stop();

        // Snapshot the bank and send over an accounts package
        let mut snapshot_time = Measure::start("snapshot_time");
        let snapshot_storages = snapshot_bank_utils::get_snapshot_storages(&snapshot_root_bank);
        let accounts_package = match request_kind {
            SnapshotRequestKind::Snapshot => match &accounts_package_kind {
                AccountsPackageKind::Snapshot(_) => {
                    let bank_snapshot_info = snapshot_bank_utils::add_bank_snapshot(
                        &self.snapshot_config.bank_snapshots_dir,
                        &snapshot_root_bank,
                        &snapshot_storages,
                        self.snapshot_config.snapshot_version,
                        status_cache_slot_deltas,
                    )?;
                    AccountsPackage::new_for_snapshot(
                        accounts_package_kind,
                        &snapshot_root_bank,
                        &bank_snapshot_info,
                        &self.snapshot_config.full_snapshot_archives_dir,
                        &self.snapshot_config.incremental_snapshot_archives_dir,
                        snapshot_storages,
                        self.snapshot_config.archive_format,
                        self.snapshot_config.snapshot_version,
                        accounts_hash_for_testing,
                    )
                }
                AccountsPackageKind::AccountsHashVerifier => {
                    // skip the bank snapshot, just make an accounts package to send to AHV
                    AccountsPackage::new_for_accounts_hash_verifier(
                        accounts_package_kind,
                        &snapshot_root_bank,
                        snapshot_storages,
                        accounts_hash_for_testing,
                    )
                }
                AccountsPackageKind::EpochAccountsHash => panic!("Illegal account package type: EpochAccountsHash packages must be from an EpochAccountsHash request!"),
            },
            SnapshotRequestKind::EpochAccountsHash => {
                // skip the bank snapshot, just make an accounts package to send to AHV
                AccountsPackage::new_for_epoch_accounts_hash(
                    accounts_package_kind,
                    &snapshot_root_bank,
                    snapshot_storages,
                    accounts_hash_for_testing,
                )
            }
        };
        let send_result = self.accounts_package_sender.send(accounts_package);
        if let Err(err) = send_result {
            // Sending the accounts package should never fail *unless* we're shutting down.
            let accounts_package = &err.0;
            assert!(
                exit.load(Ordering::Relaxed),
                "Failed to send accounts package: {err}, {accounts_package:?}"
            );
        }
        snapshot_time.stop();
        info!(
            "Took bank snapshot. accounts package kind: {:?}, slot: {}, bank hash: {}",
            accounts_package_kind,
            snapshot_root_bank.slot(),
            snapshot_root_bank.hash(),
        );

        total_time.stop();

        datapoint_info!(
            "handle_snapshot_requests-timing",
            (
                "flush_accounts_cache_time",
                flush_accounts_cache_time.as_us(),
                i64
            ),
            ("shrink_time", shrink_time.as_us(), i64),
            ("clean_time", clean_time.as_us(), i64),
            ("snapshot_time", snapshot_time.as_us(), i64),
            ("total_us", total_time.as_us(), i64),
            ("non_snapshot_time_us", non_snapshot_time_us, i64),
            ("shrink_ancient_time_us", shrink_ancient_time_us, i64),
        );
        Ok(snapshot_root_bank.block_height())
    }
}

#[derive(Default, Clone)]
pub struct AbsRequestSender {
    snapshot_request_sender: Option<SnapshotRequestSender>,
}

impl AbsRequestSender {
    pub fn new(snapshot_request_sender: SnapshotRequestSender) -> Self {
        Self {
            snapshot_request_sender: Some(snapshot_request_sender),
        }
    }

    pub fn is_snapshot_creation_enabled(&self) -> bool {
        self.snapshot_request_sender.is_some()
    }

    pub fn send_snapshot_request(
        &self,
        snapshot_request: SnapshotRequest,
    ) -> Result<(), SendError<SnapshotRequest>> {
        if let Some(ref snapshot_request_sender) = self.snapshot_request_sender {
            snapshot_request_sender.send(snapshot_request)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct PrunedBanksRequestHandler {
    pub pruned_banks_receiver: DroppedSlotsReceiver,
}

impl PrunedBanksRequestHandler {
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn handle_request(&self, bank: &Bank) -> usize {
        let mut banks_to_purge: Vec<_> = self.pruned_banks_receiver.try_iter().collect();
        // We need a stable sort to ensure we purge banks—with the same slot—in the same order
        // they were sent into the channel.
        banks_to_purge.sort_by_key(|(slot, _id)| *slot);
        let num_banks_to_purge = banks_to_purge.len();

        // Group the banks into slices with the same slot
        let grouped_banks_to_purge: Vec<_> =
            GroupBy::new(banks_to_purge.as_slice(), |a, b| a.0 == b.0).collect();

        // Log whenever we need to handle banks with the same slot.  Purposely do this *before* we
        // call `purge_slot()` to ensure we get the datapoint (in case there's an assert/panic).
        let num_banks_with_same_slot =
            num_banks_to_purge.saturating_sub(grouped_banks_to_purge.len());
        if num_banks_with_same_slot > 0 {
            datapoint_info!(
                "pruned_banks_request_handler",
                ("num_pruned_banks", num_banks_to_purge, i64),
                ("num_banks_with_same_slot", num_banks_with_same_slot, i64),
            );
        }

        // Purge all the slots in parallel
        // Banks for the same slot are purged sequentially
        let accounts_db = bank.rc.accounts.accounts_db.as_ref();
        accounts_db.thread_pool_clean.install(|| {
            grouped_banks_to_purge.into_par_iter().for_each(|group| {
                group.iter().for_each(|(slot, bank_id)| {
                    accounts_db.purge_slot(*slot, *bank_id, true);
                })
            });
        });

        num_banks_to_purge
    }

    fn remove_dead_slots(
        &self,
        bank: &Bank,
        removed_slots_count: &mut usize,
        total_remove_slots_time: &mut u64,
    ) {
        let mut remove_slots_time = Measure::start("remove_slots_time");
        *removed_slots_count += self.handle_request(bank);
        remove_slots_time.stop();
        *total_remove_slots_time += remove_slots_time.as_us();

        if *removed_slots_count >= 100 {
            datapoint_info!(
                "remove_slots_timing",
                ("remove_slots_time", *total_remove_slots_time, i64),
                ("removed_slots_count", *removed_slots_count, i64),
            );
            *total_remove_slots_time = 0;
            *removed_slots_count = 0;
        }
    }
}

pub struct AbsRequestHandlers {
    pub snapshot_request_handler: SnapshotRequestHandler,
    pub pruned_banks_request_handler: PrunedBanksRequestHandler,
}

impl AbsRequestHandlers {
    // Returns the latest requested snapshot block height, if one exists
    #[allow(clippy::type_complexity)]
    pub fn handle_snapshot_requests(
        &self,
        test_hash_calculation: bool,
        non_snapshot_time_us: u128,
        last_full_snapshot_slot: &mut Option<Slot>,
        exit: &AtomicBool,
    ) -> Option<Result<u64, SnapshotError>> {
        self.snapshot_request_handler.handle_snapshot_requests(
            test_hash_calculation,
            non_snapshot_time_us,
            last_full_snapshot_slot,
            exit,
        )
    }
}

pub struct AccountsBackgroundService {
    t_background: JoinHandle<()>,
}

impl AccountsBackgroundService {
    pub fn new(
        bank_forks: Arc<RwLock<BankForks>>,
        exit: Arc<AtomicBool>,
        request_handlers: AbsRequestHandlers,
        test_hash_calculation: bool,
        mut last_full_snapshot_slot: Option<Slot>,
    ) -> Self {
        let mut last_cleaned_block_height = 0;
        let mut removed_slots_count = 0;
        let mut total_remove_slots_time = 0;
        let mut last_expiration_check_time = Instant::now();
        let t_background = Builder::new()
            .name("solBgAccounts".to_string())
            .spawn(move || {
                info!("AccountsBackgroundService has started");
                let mut stats = StatsManager::new();
                let mut last_snapshot_end_time = None;

                loop {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }
                    let start_time = Instant::now();

                    // Grab the current root bank
                    let bank = bank_forks.read().unwrap().root_bank();

                    // Purge accounts of any dead slots
                    request_handlers
                        .pruned_banks_request_handler
                        .remove_dead_slots(
                            &bank,
                            &mut removed_slots_count,
                            &mut total_remove_slots_time,
                        );

                    Self::expire_old_recycle_stores(&bank, &mut last_expiration_check_time);

                    let non_snapshot_time = last_snapshot_end_time
                        .map(|last_snapshot_end_time: Instant| {
                            last_snapshot_end_time.elapsed().as_micros()
                        })
                        .unwrap_or_default();

                    // Check to see if there were any requests for snapshotting banks
                    // < the current root bank `bank` above.

                    // Claim: Any snapshot request for slot `N` found here implies that the last cleanup
                    // slot `M` satisfies `M < N`
                    //
                    // Proof: Assume for contradiction that we find a snapshot request for slot `N` here,
                    // but cleanup has already happened on some slot `M >= N`. Because the call to
                    // `bank.clean_accounts(true)` (in the code below) implies we only clean slots `<= bank - 1`,
                    // then that means in some *previous* iteration of this loop, we must have gotten a root
                    // bank for slot some slot `R` where `R > N`, but did not see the snapshot for `N` in the
                    // snapshot request channel.
                    //
                    // However, this is impossible because BankForks.set_root() will always flush the snapshot
                    // request for `N` to the snapshot request channel before setting a root `R > N`, and
                    // snapshot_request_handler.handle_requests() will always look for the latest
                    // available snapshot in the channel.
                    //
                    // NOTE: We must wait for startup verification to complete before handling
                    // snapshot requests.  This is because startup verification and snapshot
                    // request handling can both kick off accounts hash calculations in background
                    // threads, and these must not happen concurrently.
                    let snapshot_handle_result = bank
                        .is_startup_verification_complete()
                        .then(|| {
                            request_handlers.handle_snapshot_requests(
                                test_hash_calculation,
                                non_snapshot_time,
                                &mut last_full_snapshot_slot,
                                &exit,
                            )
                        })
                        .flatten();
                    if snapshot_handle_result.is_some() {
                        last_snapshot_end_time = Some(Instant::now());
                    }

                    // Note that the flush will do an internal clean of the
                    // cache up to bank.slot(), so should be safe as long
                    // as any later snapshots that are taken are of
                    // slots >= bank.slot()
                    bank.flush_accounts_cache_if_needed();

                    if let Some(snapshot_handle_result) = snapshot_handle_result {
                        // Safe, see proof above

                        match snapshot_handle_result {
                            Ok(snapshot_block_height) => {
                                assert!(last_cleaned_block_height <= snapshot_block_height);
                                last_cleaned_block_height = snapshot_block_height;
                            }
                            Err(err) => {
                                error!("Stopping AccountsBackgroundService! Fatal error while handling snapshot requests: {err}");
                                exit.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    } else {
                        if bank.block_height() - last_cleaned_block_height
                            > (CLEAN_INTERVAL_BLOCKS + thread_rng().gen_range(0..10))
                        {
                            // Note that the flush will do an internal clean of the
                            // cache up to bank.slot(), so should be safe as long
                            // as any later snapshots that are taken are of
                            // slots >= bank.slot()
                            bank.force_flush_accounts_cache();
                            bank.clean_accounts(last_full_snapshot_slot);
                            last_cleaned_block_height = bank.block_height();
                            // See justification below for why we skip 'shrink' here.
                            if bank.is_startup_verification_complete() {
                                bank.shrink_ancient_slots();
                            }
                        }
                        // Do not 'shrink' until *after* the startup verification is complete.
                        // This is because startup verification needs to get the snapshot
                        // storages *as they existed at startup* (to calculate the accounts hash).
                        // If 'shrink' were to run, then it is possible startup verification
                        // (1) could race with 'shrink', and fail to assert that shrinking is not in
                        // progress, or (2) could get snapshot storages that were newer than what
                        // was in the snapshot itself.
                        if bank.is_startup_verification_complete() {
                            bank.shrink_candidate_slots();
                        }
                    }
                    stats.record_and_maybe_submit(start_time.elapsed());
                    sleep(Duration::from_millis(INTERVAL_MS));
                }
                info!("AccountsBackgroundService has stopped");
            })
            .unwrap();

        Self { t_background }
    }

    /// Should be called immediately after bank_fork_utils::load_bank_forks(), and as such, there
    /// should only be one bank, the root bank, in `bank_forks`
    /// All banks added to `bank_forks` will be descended from the root bank, and thus will inherit
    /// the bank drop callback.
    pub fn setup_bank_drop_callback(bank_forks: Arc<RwLock<BankForks>>) -> DroppedSlotsReceiver {
        assert_eq!(bank_forks.read().unwrap().banks().len(), 1);

        let (pruned_banks_sender, pruned_banks_receiver) = crossbeam_channel::unbounded();
        {
            let root_bank = bank_forks.read().unwrap().root_bank();

            root_bank
                .rc
                .accounts
                .accounts_db
                .enable_bank_drop_callback();
            root_bank.set_callback(Some(Box::new(SendDroppedBankCallback::new(
                pruned_banks_sender,
            ))));
        }
        pruned_banks_receiver
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_background.join()
    }

    fn expire_old_recycle_stores(bank: &Bank, last_expiration_check_time: &mut Instant) {
        let now = Instant::now();
        if now.duration_since(*last_expiration_check_time).as_secs()
            > RECYCLE_STORE_EXPIRATION_INTERVAL_SECS
        {
            bank.expire_old_recycle_stores();
            *last_expiration_check_time = now;
        }
    }
}

/// Get the AccountsPackageKind from a given SnapshotRequest
#[must_use]
fn new_accounts_package_kind(
    snapshot_request: &SnapshotRequest,
    snapshot_config: &SnapshotConfig,
    last_full_snapshot_slot: Option<Slot>,
) -> AccountsPackageKind {
    let block_height = snapshot_request.snapshot_root_bank.block_height();
    match snapshot_request.request_kind {
        SnapshotRequestKind::EpochAccountsHash => AccountsPackageKind::EpochAccountsHash,
        _ => {
            if snapshot_utils::should_take_full_snapshot(
                block_height,
                snapshot_config.full_snapshot_archive_interval_slots,
            ) {
                AccountsPackageKind::Snapshot(SnapshotKind::FullSnapshot)
            } else if snapshot_utils::should_take_incremental_snapshot(
                block_height,
                snapshot_config.incremental_snapshot_archive_interval_slots,
                last_full_snapshot_slot,
            ) {
                AccountsPackageKind::Snapshot(SnapshotKind::IncrementalSnapshot(
                    last_full_snapshot_slot.unwrap(),
                ))
            } else {
                AccountsPackageKind::AccountsHashVerifier
            }
        }
    }
}

/// Compare snapshot requests; used to pick the highest priority request to handle.
///
/// Priority, from highest to lowest:
/// - Epoch Accounts Hash
/// - Full Snapshot
/// - Incremental Snapshot
/// - Accounts Hash Verifier
///
/// If two requests of the same kind are being compared, their bank slots are the tiebreaker.
#[must_use]
fn cmp_requests_by_priority(
    a: &(SnapshotRequest, AccountsPackageKind),
    b: &(SnapshotRequest, AccountsPackageKind),
) -> std::cmp::Ordering {
    let (snapshot_request_a, accounts_package_kind_a) = a;
    let (snapshot_request_b, accounts_package_kind_b) = b;
    let slot_a = snapshot_request_a.snapshot_root_bank.slot();
    let slot_b = snapshot_request_b.snapshot_root_bank.slot();
    snapshot_package::cmp_accounts_package_kinds_by_priority(
        accounts_package_kind_a,
        accounts_package_kind_b,
    )
    .then(slot_a.cmp(&slot_b))
}

/// An iterator over a slice producing non-overlapping runs
/// of elements using a predicate to separate them.
///
/// This can be used to extract sorted subslices.
///
/// (`Vec::group_by()`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.group_by)
/// is currently a nightly-only experimental API.  Once the API is stablized, use it instead.
///
/// tracking issue: https://github.com/rust-lang/rust/issues/80552
/// rust-lang PR: https://github.com/rust-lang/rust/pull/79895/
/// implementation permalink: https://github.com/Kerollmops/rust/blob/8b53be660444d736bb6a6e1c6ba42c8180c968e7/library/core/src/slice/iter.rs#L2972-L3023
struct GroupBy<'a, T: 'a, P> {
    slice: &'a [T],
    predicate: P,
}
impl<'a, T: 'a, P> GroupBy<'a, T, P>
where
    P: FnMut(&T, &T) -> bool,
{
    fn new(slice: &'a [T], predicate: P) -> Self {
        GroupBy { slice, predicate }
    }
}
impl<'a, T: 'a, P> Iterator for GroupBy<'a, T, P>
where
    P: FnMut(&T, &T) -> bool,
{
    type Item = &'a [T];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            None
        } else {
            let mut len = 1;
            let mut iter = self.slice.windows(2);
            while let Some([l, r]) = iter.next() {
                if (self.predicate)(l, r) {
                    len += 1
                } else {
                    break;
                }
            }
            let (head, tail) = self.slice.split_at(len);
            self.slice = tail;
            Some(head)
        }
    }
}
