use {
    crate::{
        invoke_context::{BuiltinFunctionWithContext, InvokeContext},
        timings::ExecuteDetailsTimings,
    },
    log::{debug, error, log_enabled, trace},
    percentage::PercentageInteger,
    rand::{thread_rng, Rng},
    solana_measure::measure::Measure,
    solana_rbpf::{
        elf::Executable,
        program::{BuiltinProgram, FunctionRegistry},
        verifier::RequisiteVerifier,
        vm::Config,
    },
    solana_sdk::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable,
        clock::{Epoch, Slot},
        loader_v4,
        pubkey::Pubkey,
        saturating_add_assign,
    },
    std::{
        collections::HashMap,
        fmt::{Debug, Formatter},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Condvar, Mutex, RwLock,
        },
    },
};

pub type ProgramRuntimeEnvironment = Arc<BuiltinProgram<InvokeContext<'static>>>;
pub const MAX_LOADED_ENTRY_COUNT: usize = 256;
pub const DELAY_VISIBILITY_SLOT_OFFSET: Slot = 1;

/// Relationship between two fork IDs
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BlockRelation {
    /// The slot is on the same fork and is an ancestor of the other slot
    Ancestor,
    /// The two slots are equal and are on the same fork
    Equal,
    /// The slot is on the same fork and is a descendant of the other slot
    Descendant,
    /// The slots are on two different forks and may have had a common ancestor at some point
    Unrelated,
    /// Either one or both of the slots are either older than the latest root, or are in future
    Unknown,
}

/// Maps relationship between two slots.
pub trait ForkGraph {
    /// Returns the BlockRelation of A to B
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation;

    /// Returns the epoch of the given slot
    fn slot_epoch(&self, _slot: Slot) -> Option<Epoch> {
        Some(0)
    }
}

#[derive(Default)]
pub enum LoadedProgramType {
    /// Tombstone for undeployed, closed or unloadable programs
    FailedVerification(ProgramRuntimeEnvironment),
    #[default]
    Closed,
    DelayVisibility,
    /// Successfully verified but not currently compiled, used to track usage statistics when a compiled program is evicted from memory.
    Unloaded(ProgramRuntimeEnvironment),
    LegacyV0(Executable<InvokeContext<'static>>),
    LegacyV1(Executable<InvokeContext<'static>>),
    Typed(Executable<InvokeContext<'static>>),
    #[cfg(test)]
    TestLoaded(ProgramRuntimeEnvironment),
    Builtin(BuiltinProgram<InvokeContext<'static>>),
}

impl Debug for LoadedProgramType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadedProgramType::FailedVerification(_) => {
                write!(f, "LoadedProgramType::FailedVerification")
            }
            LoadedProgramType::Closed => write!(f, "LoadedProgramType::Closed"),
            LoadedProgramType::DelayVisibility => write!(f, "LoadedProgramType::DelayVisibility"),
            LoadedProgramType::Unloaded(_) => write!(f, "LoadedProgramType::Unloaded"),
            LoadedProgramType::LegacyV0(_) => write!(f, "LoadedProgramType::LegacyV0"),
            LoadedProgramType::LegacyV1(_) => write!(f, "LoadedProgramType::LegacyV1"),
            LoadedProgramType::Typed(_) => write!(f, "LoadedProgramType::Typed"),
            #[cfg(test)]
            LoadedProgramType::TestLoaded(_) => write!(f, "LoadedProgramType::TestLoaded"),
            LoadedProgramType::Builtin(_) => write!(f, "LoadedProgramType::Builtin"),
        }
    }
}

impl LoadedProgramType {
    /// Returns a reference to its environment if it has one
    pub fn get_environment(&self) -> Option<&ProgramRuntimeEnvironment> {
        match self {
            LoadedProgramType::LegacyV0(program)
            | LoadedProgramType::LegacyV1(program)
            | LoadedProgramType::Typed(program) => Some(program.get_loader()),
            LoadedProgramType::FailedVerification(env) | LoadedProgramType::Unloaded(env) => {
                Some(env)
            }
            #[cfg(test)]
            LoadedProgramType::TestLoaded(environment) => Some(environment),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct LoadedProgram {
    /// The program of this entry
    pub program: LoadedProgramType,
    /// Size of account that stores the program and program data
    pub account_size: usize,
    /// Slot in which the program was (re)deployed
    pub deployment_slot: Slot,
    /// Slot in which this entry will become active (can be in the future)
    pub effective_slot: Slot,
    /// Optional expiration slot for this entry, after which it is treated as non-existent
    pub maybe_expiration_slot: Option<Slot>,
    /// How often this entry was used by a transaction
    pub tx_usage_counter: AtomicU64,
    /// How often this entry was used by an instruction
    pub ix_usage_counter: AtomicU64,
    /// Latest slot in which the entry was used
    pub latest_access_slot: AtomicU64,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: HashMap<Pubkey, u64>,
    pub insertions: AtomicU64,
    pub replacements: AtomicU64,
    pub one_hit_wonders: AtomicU64,
    pub prunes_orphan: AtomicU64,
    pub prunes_expired: AtomicU64,
    pub prunes_environment: AtomicU64,
    pub empty_entries: AtomicU64,
}

impl Stats {
    /// Logs the measurement values
    pub fn submit(&self, slot: Slot) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let insertions = self.insertions.load(Ordering::Relaxed);
        let replacements = self.replacements.load(Ordering::Relaxed);
        let one_hit_wonders = self.one_hit_wonders.load(Ordering::Relaxed);
        let evictions: u64 = self.evictions.values().sum();
        let prunes_orphan = self.prunes_orphan.load(Ordering::Relaxed);
        let prunes_expired = self.prunes_expired.load(Ordering::Relaxed);
        let prunes_environment = self.prunes_environment.load(Ordering::Relaxed);
        let empty_entries = self.empty_entries.load(Ordering::Relaxed);
        datapoint_info!(
            "loaded-programs-cache-stats",
            ("slot", slot, i64),
            ("hits", hits, i64),
            ("misses", misses, i64),
            ("evictions", evictions, i64),
            ("insertions", insertions, i64),
            ("replacements", replacements, i64),
            ("one_hit_wonders", one_hit_wonders, i64),
            ("prunes_orphan", prunes_orphan, i64),
            ("prunes_expired", prunes_expired, i64),
            ("prunes_environment", prunes_environment, i64),
            ("empty_entries", empty_entries, i64),
        );
        debug!(
            "Loaded Programs Cache Stats -- Hits: {}, Misses: {}, Evictions: {}, Insertions: {}, Replacements: {}, One-Hit-Wonders: {}, Prunes-Orphan: {}, Prunes-Expired: {}, Prunes-Environment: {}, Empty: {}",
            hits, misses, evictions, insertions, replacements, one_hit_wonders, prunes_orphan, prunes_expired, prunes_environment, empty_entries
        );
        if log_enabled!(log::Level::Trace) && !self.evictions.is_empty() {
            let mut evictions = self.evictions.iter().collect::<Vec<_>>();
            evictions.sort_by_key(|e| e.1);
            let evictions = evictions
                .into_iter()
                .rev()
                .map(|(program_id, evictions)| {
                    format!("  {:<44}  {}", program_id.to_string(), evictions)
                })
                .collect::<Vec<_>>();
            let evictions = evictions.join("\n");
            trace!(
                "Eviction Details:\n  {:<44}  {}\n{}",
                "Program",
                "Count",
                evictions
            );
        }
    }

    pub fn reset(&mut self) {
        *self = Stats::default();
    }
}

#[derive(Debug, Default)]
pub struct LoadProgramMetrics {
    pub program_id: String,
    pub register_syscalls_us: u64,
    pub load_elf_us: u64,
    pub verify_code_us: u64,
    pub jit_compile_us: u64,
}

impl LoadProgramMetrics {
    pub fn submit_datapoint(&self, timings: &mut ExecuteDetailsTimings) {
        saturating_add_assign!(
            timings.create_executor_register_syscalls_us,
            self.register_syscalls_us
        );
        saturating_add_assign!(timings.create_executor_load_elf_us, self.load_elf_us);
        saturating_add_assign!(timings.create_executor_verify_code_us, self.verify_code_us);
        saturating_add_assign!(timings.create_executor_jit_compile_us, self.jit_compile_us);
        datapoint_trace!(
            "create_executor_trace",
            ("program_id", self.program_id, String),
            ("register_syscalls_us", self.register_syscalls_us, i64),
            ("load_elf_us", self.load_elf_us, i64),
            ("verify_code_us", self.verify_code_us, i64),
            ("jit_compile_us", self.jit_compile_us, i64),
        );
    }
}

impl PartialEq for LoadedProgram {
    fn eq(&self, other: &Self) -> bool {
        self.effective_slot == other.effective_slot
            && self.deployment_slot == other.deployment_slot
            && self.is_tombstone() == other.is_tombstone()
    }
}

impl LoadedProgram {
    /// Creates a new user program
    pub fn new(
        loader_key: &Pubkey,
        program_runtime_environment: ProgramRuntimeEnvironment,
        deployment_slot: Slot,
        effective_slot: Slot,
        maybe_expiration_slot: Option<Slot>,
        elf_bytes: &[u8],
        account_size: usize,
        metrics: &mut LoadProgramMetrics,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_internal(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            maybe_expiration_slot,
            elf_bytes,
            account_size,
            metrics,
            false, /* reloading */
        )
    }

    /// Reloads a user program, *without* running the verifier.
    ///
    /// # Safety
    ///
    /// This method is unsafe since it assumes that the program has already been verified. Should
    /// only be called when the program was previously verified and loaded in the cache, but was
    /// unloaded due to inactivity. It should also be checked that the `program_runtime_environment`
    /// hasn't changed since it was unloaded.
    pub unsafe fn reload(
        loader_key: &Pubkey,
        program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
        deployment_slot: Slot,
        effective_slot: Slot,
        maybe_expiration_slot: Option<Slot>,
        elf_bytes: &[u8],
        account_size: usize,
        metrics: &mut LoadProgramMetrics,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_internal(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            maybe_expiration_slot,
            elf_bytes,
            account_size,
            metrics,
            true, /* reloading */
        )
    }

    fn new_internal(
        loader_key: &Pubkey,
        program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
        deployment_slot: Slot,
        effective_slot: Slot,
        maybe_expiration_slot: Option<Slot>,
        elf_bytes: &[u8],
        account_size: usize,
        metrics: &mut LoadProgramMetrics,
        reloading: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut load_elf_time = Measure::start("load_elf_time");
        // The following unused_mut exception is needed for architectures that do not
        // support JIT compilation.
        #[allow(unused_mut)]
        let mut executable = Executable::load(elf_bytes, program_runtime_environment.clone())?;
        load_elf_time.stop();
        metrics.load_elf_us = load_elf_time.as_us();

        if !reloading {
            let mut verify_code_time = Measure::start("verify_code_time");
            executable.verify::<RequisiteVerifier>()?;
            verify_code_time.stop();
            metrics.verify_code_us = verify_code_time.as_us();
        }

        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        {
            let mut jit_compile_time = Measure::start("jit_compile_time");
            executable.jit_compile()?;
            jit_compile_time.stop();
            metrics.jit_compile_us = jit_compile_time.as_us();
        }

        // Allowing mut here, since it may be needed for jit compile, which is under a config flag
        #[allow(unused_mut)]
        let mut program = if bpf_loader_deprecated::check_id(loader_key) {
            LoadedProgramType::LegacyV0(executable)
        } else if bpf_loader::check_id(loader_key) || bpf_loader_upgradeable::check_id(loader_key) {
            LoadedProgramType::LegacyV1(executable)
        } else if loader_v4::check_id(loader_key) {
            LoadedProgramType::Typed(executable)
        } else {
            panic!();
        };

        Ok(Self {
            deployment_slot,
            account_size,
            effective_slot,
            maybe_expiration_slot,
            tx_usage_counter: AtomicU64::new(0),
            program,
            ix_usage_counter: AtomicU64::new(0),
            latest_access_slot: AtomicU64::new(0),
        })
    }

    pub fn to_unloaded(&self) -> Option<Self> {
        Some(Self {
            program: LoadedProgramType::Unloaded(self.program.get_environment()?.clone()),
            account_size: self.account_size,
            deployment_slot: self.deployment_slot,
            effective_slot: self.effective_slot,
            maybe_expiration_slot: self.maybe_expiration_slot,
            tx_usage_counter: AtomicU64::new(self.tx_usage_counter.load(Ordering::Relaxed)),
            ix_usage_counter: AtomicU64::new(self.ix_usage_counter.load(Ordering::Relaxed)),
            latest_access_slot: AtomicU64::new(self.latest_access_slot.load(Ordering::Relaxed)),
        })
    }

    /// Creates a new built-in program
    pub fn new_builtin(
        deployment_slot: Slot,
        account_size: usize,
        builtin_function: BuiltinFunctionWithContext,
    ) -> Self {
        let mut function_registry = FunctionRegistry::default();
        function_registry
            .register_function_hashed(*b"entrypoint", builtin_function)
            .unwrap();
        Self {
            deployment_slot,
            account_size,
            effective_slot: deployment_slot,
            maybe_expiration_slot: None,
            tx_usage_counter: AtomicU64::new(0),
            program: LoadedProgramType::Builtin(BuiltinProgram::new_builtin(function_registry)),
            ix_usage_counter: AtomicU64::new(0),
            latest_access_slot: AtomicU64::new(0),
        }
    }

    pub fn new_tombstone(slot: Slot, reason: LoadedProgramType) -> Self {
        let maybe_expiration_slot = matches!(reason, LoadedProgramType::DelayVisibility)
            .then_some(slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET));
        let tombstone = Self {
            program: reason,
            account_size: 0,
            deployment_slot: slot,
            effective_slot: slot,
            maybe_expiration_slot,
            tx_usage_counter: AtomicU64::default(),
            ix_usage_counter: AtomicU64::default(),
            latest_access_slot: AtomicU64::new(0),
        };
        debug_assert!(tombstone.is_tombstone());
        tombstone
    }

    pub fn is_tombstone(&self) -> bool {
        matches!(
            self.program,
            LoadedProgramType::FailedVerification(_)
                | LoadedProgramType::Closed
                | LoadedProgramType::DelayVisibility
        )
    }

    fn is_implicit_delay_visibility_tombstone(&self, slot: Slot) -> bool {
        !matches!(self.program, LoadedProgramType::Builtin(_))
            && self.effective_slot.saturating_sub(self.deployment_slot)
                == DELAY_VISIBILITY_SLOT_OFFSET
            && slot >= self.deployment_slot
            && slot < self.effective_slot
    }

    pub fn update_access_slot(&self, slot: Slot) {
        let _ = self.latest_access_slot.fetch_max(slot, Ordering::Relaxed);
    }

    pub fn decayed_usage_counter(&self, now: Slot) -> u64 {
        let last_access = self.latest_access_slot.load(Ordering::Relaxed);
        let decaying_for = now.saturating_sub(last_access);
        self.tx_usage_counter.load(Ordering::Relaxed) >> decaying_for
    }
}

#[derive(Clone, Debug)]
pub struct ProgramRuntimeEnvironments {
    /// Globally shared RBPF config and syscall registry for runtime V1
    pub program_runtime_v1: ProgramRuntimeEnvironment,
    /// Globally shared RBPF config and syscall registry for runtime V2
    pub program_runtime_v2: ProgramRuntimeEnvironment,
}

impl Default for ProgramRuntimeEnvironments {
    fn default() -> Self {
        let empty_loader = Arc::new(BuiltinProgram::new_loader(
            Config::default(),
            FunctionRegistry::default(),
        ));
        Self {
            program_runtime_v1: empty_loader.clone(),
            program_runtime_v2: empty_loader,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadingTaskCookie(u64);

impl LoadingTaskCookie {
    fn new() -> Self {
        Self(0)
    }

    fn update(&mut self) {
        let LoadingTaskCookie(cookie) = self;
        *cookie = cookie.wrapping_add(1);
    }
}

/// Prevents excessive polling during cooperative loading
#[derive(Debug, Default)]
pub struct LoadingTaskWaiter {
    cookie: Mutex<LoadingTaskCookie>,
    cond: Condvar,
}

impl LoadingTaskWaiter {
    pub fn new() -> Self {
        Self {
            cookie: Mutex::new(LoadingTaskCookie::new()),
            cond: Condvar::new(),
        }
    }

    pub fn cookie(&self) -> LoadingTaskCookie {
        *self.cookie.lock().unwrap()
    }

    pub fn notify(&self) {
        let mut cookie = self.cookie.lock().unwrap();
        cookie.update();
        self.cond.notify_all();
    }

    pub fn wait(&self, cookie: LoadingTaskCookie) -> LoadingTaskCookie {
        let cookie_guard = self.cookie.lock().unwrap();
        *self
            .cond
            .wait_while(cookie_guard, |current_cookie| *current_cookie == cookie)
            .unwrap()
    }
}

#[derive(Debug, Default)]
struct SecondLevel {
    slot_versions: Vec<Arc<LoadedProgram>>,
    /// Contains the bank and TX batch a program at this address is currently being loaded
    cooperative_loading_lock: Option<(Slot, std::thread::ThreadId)>,
}

pub struct LoadedPrograms<FG: ForkGraph> {
    /// A two level index:
    ///
    /// The first level is for the address at which programs are deployed and the second level for the slot (and thus also fork).
    entries: HashMap<Pubkey, SecondLevel>,
    /// The slot of the last rerooting
    pub latest_root_slot: Slot,
    /// The epoch of the last rerooting
    pub latest_root_epoch: Epoch,
    /// Environments of the current epoch
    pub environments: ProgramRuntimeEnvironments,
    /// Anticipated replacement for `environments` at the next epoch
    ///
    /// This is `None` during most of an epoch, and only `Some` around the boundaries (at the end and beginning of an epoch).
    /// More precisely, it starts with the recompilation phase a few hundred slots before the epoch boundary,
    /// and it ends with the first rerooting after the epoch boundary.
    pub upcoming_environments: Option<ProgramRuntimeEnvironments>,
    /// List of loaded programs which should be recompiled before the next epoch (but don't have to).
    pub programs_to_recompile: Vec<(Pubkey, Arc<LoadedProgram>)>,
    pub stats: Stats,
    pub fork_graph: Option<Arc<RwLock<FG>>>,
    pub loading_task_waiter: Arc<LoadingTaskWaiter>,
}

impl<FG: ForkGraph> Debug for LoadedPrograms<FG> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPrograms")
            .field("root slot", &self.latest_root_slot)
            .field("root epoch", &self.latest_root_epoch)
            .field("stats", &self.stats)
            .field("cache", &self.entries)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoadedProgramsForTxBatch {
    /// Pubkey is the address of a program.
    /// LoadedProgram is the corresponding program entry valid for the slot in which a transaction is being executed.
    entries: HashMap<Pubkey, Arc<LoadedProgram>>,
    slot: Slot,
    pub environments: ProgramRuntimeEnvironments,
}

impl LoadedProgramsForTxBatch {
    pub fn new(slot: Slot, environments: ProgramRuntimeEnvironments) -> Self {
        Self {
            entries: HashMap::new(),
            slot,
            environments,
        }
    }

    /// Refill the cache with a single entry. It's typically called during transaction loading, and
    /// transaction processing (for program management instructions).
    /// It replaces the existing entry (if any) with the provided entry. The return value contains
    /// `true` if an entry existed.
    /// The function also returns the newly inserted value.
    pub fn replenish(
        &mut self,
        key: Pubkey,
        entry: Arc<LoadedProgram>,
    ) -> (bool, Arc<LoadedProgram>) {
        (self.entries.insert(key, entry.clone()).is_some(), entry)
    }

    pub fn find(&self, key: &Pubkey) -> Option<Arc<LoadedProgram>> {
        self.entries.get(key).map(|entry| {
            if entry.is_implicit_delay_visibility_tombstone(self.slot) {
                // Found a program entry on the current fork, but it's not effective
                // yet. It indicates that the program has delayed visibility. Return
                // the tombstone to reflect that.
                Arc::new(LoadedProgram::new_tombstone(
                    entry.deployment_slot,
                    LoadedProgramType::DelayVisibility,
                ))
            } else {
                entry.clone()
            }
        })
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn set_slot_for_tests(&mut self, slot: Slot) {
        self.slot = slot;
    }

    pub fn merge(&mut self, other: &Self) {
        other.entries.iter().for_each(|(key, entry)| {
            self.replenish(*key, entry.clone());
        })
    }
}

pub enum LoadedProgramMatchCriteria {
    DeployedOnOrAfterSlot(Slot),
    Tombstone,
    NoCriteria,
}

impl<FG: ForkGraph> LoadedPrograms<FG> {
    pub fn new(root_slot: Slot, root_epoch: Epoch) -> Self {
        Self {
            entries: HashMap::new(),
            latest_root_slot: root_slot,
            latest_root_epoch: root_epoch,
            environments: ProgramRuntimeEnvironments::default(),
            upcoming_environments: None,
            programs_to_recompile: Vec::default(),
            stats: Stats::default(),
            fork_graph: None,
            loading_task_waiter: Arc::new(LoadingTaskWaiter::default()),
        }
    }

    pub fn set_fork_graph(&mut self, fork_graph: Arc<RwLock<FG>>) {
        self.fork_graph = Some(fork_graph);
    }

    /// Returns the current environments depending on the given epoch
    pub fn get_environments_for_epoch(&self, epoch: Epoch) -> &ProgramRuntimeEnvironments {
        if epoch != self.latest_root_epoch {
            if let Some(upcoming_environments) = self.upcoming_environments.as_ref() {
                return upcoming_environments;
            }
        }
        &self.environments
    }

    /// Refill the cache with a single entry. It's typically called during transaction loading,
    /// when the cache doesn't contain the entry corresponding to program `key`.
    /// The function dedupes the cache, in case some other thread replenished the entry in parallel.
    pub fn replenish(
        &mut self,
        key: Pubkey,
        entry: Arc<LoadedProgram>,
    ) -> (bool, Arc<LoadedProgram>) {
        let slot_versions = &mut self.entries.entry(key).or_default().slot_versions;
        let index = slot_versions
            .iter()
            .position(|at| at.effective_slot >= entry.effective_slot);
        if let Some((existing, entry_index)) =
            index.and_then(|index| slot_versions.get(index).map(|value| (value, index)))
        {
            if existing.deployment_slot == entry.deployment_slot
                && existing.effective_slot == entry.effective_slot
            {
                if matches!(existing.program, LoadedProgramType::Unloaded(_)) {
                    // The unloaded program is getting reloaded
                    // Copy over the usage counter to the new entry
                    entry.tx_usage_counter.fetch_add(
                        existing.tx_usage_counter.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    entry.ix_usage_counter.fetch_add(
                        existing.ix_usage_counter.load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    slot_versions.remove(entry_index);
                } else if existing.is_tombstone() != entry.is_tombstone() {
                    // Either the old entry is tombstone and the new one is not.
                    // (Let's give the new entry a chance).
                    // Or, the old entry is not a tombstone and the new one is a tombstone.
                    // (Remove the old entry, as the tombstone makes it obsolete).
                    slot_versions.remove(entry_index);
                } else {
                    self.stats.replacements.fetch_add(1, Ordering::Relaxed);
                    return (true, existing.clone());
                }
            }
        }
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
        slot_versions.insert(index.unwrap_or(slot_versions.len()), entry.clone());
        (false, entry)
    }

    /// Assign the program `entry` to the given `key` in the cache.
    /// This is typically called when a deployed program is managed (un-/re-/deployed) via
    /// loader instructions. Because of the cooldown, entires can not have the same
    /// deployment_slot and effective_slot.
    pub fn assign_program(&mut self, key: Pubkey, entry: Arc<LoadedProgram>) -> Arc<LoadedProgram> {
        let (was_occupied, entry) = self.replenish(key, entry);
        debug_assert!(!was_occupied);
        entry
    }

    pub fn prune_by_deployment_slot(&mut self, slot: Slot) {
        for second_level in self.entries.values_mut() {
            second_level
                .slot_versions
                .retain(|entry| entry.deployment_slot != slot);
        }
        self.remove_programs_with_no_entries();
    }

    /// Before rerooting the blockstore this removes all superfluous entries
    pub fn prune(&mut self, new_root_slot: Slot, new_root_epoch: Epoch) {
        let Some(fork_graph) = self.fork_graph.clone() else {
            error!("Program cache doesn't have fork graph.");
            return;
        };
        let Ok(fork_graph) = fork_graph.read() else {
            error!("Failed to lock fork graph for reading.");
            return;
        };
        let mut recompilation_phase_ends = false;
        if self.latest_root_epoch != new_root_epoch {
            self.latest_root_epoch = new_root_epoch;
            if let Some(upcoming_environments) = self.upcoming_environments.take() {
                recompilation_phase_ends = true;
                self.environments = upcoming_environments;
                self.programs_to_recompile.clear();
            }
        }
        for second_level in self.entries.values_mut() {
            // Remove entries un/re/deployed on orphan forks
            let mut first_ancestor_found = false;
            let mut first_ancestor_env = None;
            second_level.slot_versions = second_level
                .slot_versions
                .iter()
                .rev()
                .filter(|entry| {
                    let relation = fork_graph.relationship(entry.deployment_slot, new_root_slot);
                    if entry.deployment_slot >= new_root_slot {
                        matches!(relation, BlockRelation::Equal | BlockRelation::Descendant)
                    } else if matches!(relation, BlockRelation::Ancestor)
                        || entry.deployment_slot <= self.latest_root_slot
                    {
                        if !first_ancestor_found {
                            first_ancestor_found = true;
                            first_ancestor_env = entry.program.get_environment();
                            return true;
                        }
                        // Do not prune the entry if the runtime environment of the entry is different
                        // than the entry that was previously found (stored in first_ancestor_env).
                        // Different environment indicates that this entry might belong to an older
                        // epoch that had a different environment (e.g. different feature set).
                        // Once the root moves to the new/current epoch, the entry will get pruned.
                        // But, until then the entry might still be getting used by an older slot.
                        if let Some(entry_env) = entry.program.get_environment() {
                            if let Some(env) = first_ancestor_env {
                                if !Arc::ptr_eq(entry_env, env) {
                                    return true;
                                }
                            }
                        }
                        self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                        false
                    } else {
                        self.stats.prunes_orphan.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                })
                .filter(|entry| {
                    // Remove expired
                    if let Some(expiration) = entry.maybe_expiration_slot {
                        if expiration <= new_root_slot {
                            self.stats.prunes_expired.fetch_add(1, Ordering::Relaxed);
                            return false;
                        }
                    }
                    // Remove outdated environment of previous feature set
                    if recompilation_phase_ends
                        && !Self::matches_environment(entry, &self.environments)
                    {
                        self.stats
                            .prunes_environment
                            .fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                    true
                })
                .cloned()
                .collect();
            second_level.slot_versions.reverse();
        }
        self.remove_programs_with_no_entries();
        debug_assert!(self.latest_root_slot <= new_root_slot);
        self.latest_root_slot = new_root_slot;
    }

    fn matches_environment(
        entry: &Arc<LoadedProgram>,
        environments: &ProgramRuntimeEnvironments,
    ) -> bool {
        let Some(environment) = entry.program.get_environment() else {
            return true;
        };
        Arc::ptr_eq(environment, &environments.program_runtime_v1)
            || Arc::ptr_eq(environment, &environments.program_runtime_v2)
    }

    fn matches_loaded_program_criteria(
        program: &Arc<LoadedProgram>,
        criteria: &LoadedProgramMatchCriteria,
    ) -> bool {
        match criteria {
            LoadedProgramMatchCriteria::DeployedOnOrAfterSlot(slot) => {
                program.deployment_slot >= *slot
            }
            LoadedProgramMatchCriteria::Tombstone => program.is_tombstone(),
            LoadedProgramMatchCriteria::NoCriteria => true,
        }
    }

    fn is_entry_usable(
        entry: &Arc<LoadedProgram>,
        current_slot: Slot,
        match_criteria: &LoadedProgramMatchCriteria,
    ) -> bool {
        if entry
            .maybe_expiration_slot
            .map(|expiration_slot| expiration_slot <= current_slot)
            .unwrap_or(false)
        {
            // Found an entry that's already expired. Any further entries in the list
            // are older than the current one. So treat the program as missing in the
            // cache and return early.
            return false;
        }

        Self::matches_loaded_program_criteria(entry, match_criteria)
    }

    /// Extracts a subset of the programs relevant to a transaction batch
    /// and returns which program accounts the accounts DB needs to load.
    pub fn extract(
        &mut self,
        search_for: &mut Vec<(Pubkey, (LoadedProgramMatchCriteria, u64))>,
        loaded_programs_for_tx_batch: &mut LoadedProgramsForTxBatch,
    ) -> Option<(Pubkey, u64)> {
        debug_assert!(self.fork_graph.is_some());
        let locked_fork_graph = self.fork_graph.as_ref().unwrap().read().unwrap();
        let mut cooperative_loading_task = None;
        search_for.retain(|(key, (match_criteria, usage_count))| {
            if let Some(second_level) = self.entries.get_mut(key) {
                for entry in second_level.slot_versions.iter().rev() {
                    let is_ancestor = matches!(
                        locked_fork_graph
                            .relationship(entry.deployment_slot, loaded_programs_for_tx_batch.slot),
                        BlockRelation::Ancestor
                    );

                    if entry.deployment_slot <= self.latest_root_slot
                        || entry.deployment_slot == loaded_programs_for_tx_batch.slot
                        || is_ancestor
                    {
                        let entry_to_return = if loaded_programs_for_tx_batch.slot
                            >= entry.effective_slot
                            && Self::matches_environment(
                                entry,
                                &loaded_programs_for_tx_batch.environments,
                            ) {
                            if !Self::is_entry_usable(
                                entry,
                                loaded_programs_for_tx_batch.slot,
                                match_criteria,
                            ) {
                                break;
                            }

                            if let LoadedProgramType::Unloaded(_environment) = &entry.program {
                                break;
                            }
                            entry.clone()
                        } else if entry.is_implicit_delay_visibility_tombstone(
                            loaded_programs_for_tx_batch.slot,
                        ) {
                            // Found a program entry on the current fork, but it's not effective
                            // yet. It indicates that the program has delayed visibility. Return
                            // the tombstone to reflect that.
                            Arc::new(LoadedProgram::new_tombstone(
                                entry.deployment_slot,
                                LoadedProgramType::DelayVisibility,
                            ))
                        } else {
                            continue;
                        };
                        entry_to_return.update_access_slot(loaded_programs_for_tx_batch.slot);
                        entry_to_return
                            .tx_usage_counter
                            .fetch_add(*usage_count, Ordering::Relaxed);
                        loaded_programs_for_tx_batch
                            .entries
                            .insert(*key, entry_to_return);
                        return false;
                    }
                }
            }
            if cooperative_loading_task.is_none() {
                // We have not selected a task so far
                let second_level = self.entries.entry(*key).or_default();
                if second_level.cooperative_loading_lock.is_none() {
                    // Select this missing entry which is not selected by any other TX batch yet
                    cooperative_loading_task = Some((*key, *usage_count));
                    second_level.cooperative_loading_lock = Some((
                        loaded_programs_for_tx_batch.slot,
                        std::thread::current().id(),
                    ));
                }
            }
            true
        });
        drop(locked_fork_graph);
        self.stats
            .misses
            .fetch_add(search_for.len() as u64, Ordering::Relaxed);
        self.stats.hits.fetch_add(
            loaded_programs_for_tx_batch.entries.len() as u64,
            Ordering::Relaxed,
        );
        cooperative_loading_task
    }

    /// Called by Bank::replenish_program_cache() for each program that is done loading.
    pub fn finish_cooperative_loading_task(
        &mut self,
        slot: Slot,
        key: Pubkey,
        loaded_program: Arc<LoadedProgram>,
    ) {
        let second_level = self.entries.entry(key).or_default();
        debug_assert_eq!(
            second_level.cooperative_loading_lock,
            Some((slot, std::thread::current().id()))
        );
        second_level.cooperative_loading_lock = None;
        self.assign_program(key, loaded_program);
        self.loading_task_waiter.notify();
    }

    pub fn merge(&mut self, tx_batch_cache: &LoadedProgramsForTxBatch) {
        tx_batch_cache.entries.iter().for_each(|(key, entry)| {
            self.replenish(*key, entry.clone());
        })
    }

    /// Returns the list of loaded programs which are verified and compiled.
    pub fn get_flattened_entries(
        &self,
        include_program_runtime_v1: bool,
        include_program_runtime_v2: bool,
    ) -> Vec<(Pubkey, Arc<LoadedProgram>)> {
        self.entries
            .iter()
            .flat_map(|(id, second_level)| {
                second_level
                    .slot_versions
                    .iter()
                    .filter_map(move |program| match program.program {
                        LoadedProgramType::LegacyV0(_) | LoadedProgramType::LegacyV1(_)
                            if include_program_runtime_v1 =>
                        {
                            Some((*id, program.clone()))
                        }
                        LoadedProgramType::Typed(_) if include_program_runtime_v2 => {
                            Some((*id, program.clone()))
                        }
                        #[cfg(test)]
                        LoadedProgramType::TestLoaded(_) => Some((*id, program.clone())),
                        _ => None,
                    })
            })
            .collect()
    }

    /// Unloads programs which were used infrequently
    pub fn sort_and_unload(&mut self, shrink_to: PercentageInteger) {
        let mut sorted_candidates = self.get_flattened_entries(true, true);
        sorted_candidates
            .sort_by_cached_key(|(_id, program)| program.tx_usage_counter.load(Ordering::Relaxed));
        let num_to_unload = sorted_candidates
            .len()
            .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        self.unload_program_entries(sorted_candidates.iter().take(num_to_unload));
    }

    /// Evicts programs using 2's random selection, choosing the least used program out of the two entries.
    /// The eviction is performed enough number of times to reduce the cache usage to the given percentage.
    pub fn evict_using_2s_random_selection(&mut self, shrink_to: PercentageInteger, now: Slot) {
        let mut candidates = self.get_flattened_entries(true, true);
        let num_to_unload = candidates
            .len()
            .saturating_sub(shrink_to.apply_to(MAX_LOADED_ENTRY_COUNT));
        fn random_index_and_usage_counter(
            candidates: &[(Pubkey, Arc<LoadedProgram>)],
            now: Slot,
        ) -> (usize, u64) {
            let mut rng = thread_rng();
            let index = rng.gen_range(0..candidates.len());
            let usage_counter = candidates
                .get(index)
                .expect("Failed to get cached entry")
                .1
                .decayed_usage_counter(now);
            (index, usage_counter)
        }

        for _ in 0..num_to_unload {
            let (index1, usage_counter1) = random_index_and_usage_counter(&candidates, now);
            let (index2, usage_counter2) = random_index_and_usage_counter(&candidates, now);

            let (program, entry) = if usage_counter1 < usage_counter2 {
                candidates.swap_remove(index1)
            } else {
                candidates.swap_remove(index2)
            };
            self.unload_program_entry(&program, &entry);
        }
    }

    /// Removes all the entries at the given keys, if they exist
    pub fn remove_programs(&mut self, keys: impl Iterator<Item = Pubkey>) {
        for k in keys {
            self.entries.remove(&k);
        }
    }

    fn unload_program(&mut self, id: &Pubkey) {
        if let Some(second_level) = self.entries.get_mut(id) {
            for entry in second_level.slot_versions.iter_mut() {
                if let Some(unloaded) = entry.to_unloaded() {
                    *entry = Arc::new(unloaded);
                    self.stats
                        .evictions
                        .entry(*id)
                        .and_modify(|c| saturating_add_assign!(*c, 1))
                        .or_insert(1);
                } else {
                    error!(
                        "Failed to create an unloaded cache entry for a program type {:?}",
                        entry.program
                    );
                }
            }
        }
    }

    pub fn unload_all_programs(&mut self) {
        let keys = self.entries.keys().copied().collect::<Vec<Pubkey>>();
        keys.iter().for_each(|key| self.unload_program(key));
    }

    /// This function removes the given entry for the given program from the cache.
    /// The function expects that the program and entry exists in the cache. Otherwise it'll panic.
    fn unload_program_entry(&mut self, program: &Pubkey, remove_entry: &Arc<LoadedProgram>) {
        let second_level = self.entries.get_mut(program).expect("Cache lookup failed");
        let candidate = second_level
            .slot_versions
            .iter_mut()
            .find(|entry| entry == &remove_entry)
            .expect("Program entry not found");

        // Certain entry types cannot be unloaded, such as tombstones, or already unloaded entries.
        // For such entries, `to_unloaded()` will return None.
        // These entry types do not occupy much memory.
        if let Some(unloaded) = candidate.to_unloaded() {
            if candidate.tx_usage_counter.load(Ordering::Relaxed) == 1 {
                self.stats.one_hit_wonders.fetch_add(1, Ordering::Relaxed);
            }
            self.stats
                .evictions
                .entry(*program)
                .and_modify(|c| saturating_add_assign!(*c, 1))
                .or_insert(1);
            *candidate = Arc::new(unloaded);
        }
    }

    fn unload_program_entries<'a>(
        &mut self,
        remove: impl Iterator<Item = &'a (Pubkey, Arc<LoadedProgram>)>,
    ) {
        for (program, entry) in remove {
            self.unload_program_entry(program, entry);
        }
    }

    fn remove_programs_with_no_entries(&mut self) {
        let num_programs_before_removal = self.entries.len();
        self.entries.retain(|_, second_level| {
            !second_level.slot_versions.is_empty()
                || second_level.cooperative_loading_lock.is_some()
        });
        if self.entries.len() < num_programs_before_removal {
            self.stats.empty_entries.fetch_add(
                num_programs_before_removal.saturating_sub(self.entries.len()) as u64,
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl solana_frozen_abi::abi_example::AbiExample for LoadedProgram {
    fn example() -> Self {
        // LoadedProgram isn't serializable by definition.
        Self::default()
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl<FG: ForkGraph> solana_frozen_abi::abi_example::AbiExample for LoadedPrograms<FG> {
    fn example() -> Self {
        // LoadedPrograms isn't serializable by definition.
        Self::new(Slot::default(), Epoch::default())
    }
}
