use {
    solana_measure::measure::Measure,
    solana_program_runtime::{
        compute_budget::ComputeBudget,
        ic_logger_msg,
        invoke_context::InvokeContext,
        loaded_programs::{
            LoadProgramMetrics, LoadedProgram, LoadedProgramType, DELAY_VISIBILITY_SLOT_OFFSET,
        },
        log_collector::LogCollector,
        stable_log,
    },
    solana_rbpf::{
        aligned_memory::AlignedMemory,
        declare_builtin_function, ebpf,
        elf::Executable,
        error::ProgramResult,
        memory_region::{MemoryMapping, MemoryRegion},
        program::{BuiltinProgram, FunctionRegistry},
        vm::{Config, ContextObject, EbpfVm},
    },
    solana_sdk::{
        entrypoint::SUCCESS,
        instruction::InstructionError,
        loader_v4::{self, LoaderV4State, LoaderV4Status, DEPLOYMENT_COOLDOWN_IN_SLOTS},
        loader_v4_instruction::LoaderV4Instruction,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        saturating_add_assign,
        transaction_context::{BorrowedAccount, InstructionContext},
    },
    std::{
        cell::RefCell,
        rc::Rc,
        sync::{atomic::Ordering, Arc},
    },
};

pub const DEFAULT_COMPUTE_UNITS: u64 = 2_000;

pub fn get_state(data: &[u8]) -> Result<&LoaderV4State, InstructionError> {
    unsafe {
        let data = data
            .get(0..LoaderV4State::program_data_offset())
            .ok_or(InstructionError::AccountDataTooSmall)?
            .try_into()
            .unwrap();
        Ok(std::mem::transmute::<
            &[u8; LoaderV4State::program_data_offset()],
            &LoaderV4State,
        >(data))
    }
}

fn get_state_mut(data: &mut [u8]) -> Result<&mut LoaderV4State, InstructionError> {
    unsafe {
        let data = data
            .get_mut(0..LoaderV4State::program_data_offset())
            .ok_or(InstructionError::AccountDataTooSmall)?
            .try_into()
            .unwrap();
        Ok(std::mem::transmute::<
            &mut [u8; LoaderV4State::program_data_offset()],
            &mut LoaderV4State,
        >(data))
    }
}

pub fn create_program_runtime_environment_v2<'a>(
    compute_budget: &ComputeBudget,
    debugging_features: bool,
) -> BuiltinProgram<InvokeContext<'a>> {
    let config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true, // To be deactivated once we have BTF inference and verification
        enable_stack_frame_gaps: false,
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_instruction_tracing: debugging_features,
        enable_symbol_and_section_labels: debugging_features,
        reject_broken_elfs: true,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        external_internal_function_hash_collision: true,
        reject_callx_r10: true,
        enable_sbpf_v1: false,
        enable_sbpf_v2: true,
        optimize_rodata: true,
        new_elf_parser: true,
        aligned_memory_mapping: true,
        // Warning, do not use `Config::default()` so that configuration here is explicit.
    };
    BuiltinProgram::new_loader(config, FunctionRegistry::default())
}

fn calculate_heap_cost(heap_size: u32, heap_cost: u64) -> u64 {
    const KIBIBYTE: u64 = 1024;
    const PAGE_SIZE_KB: u64 = 32;
    u64::from(heap_size)
        .saturating_add(PAGE_SIZE_KB.saturating_mul(KIBIBYTE).saturating_sub(1))
        .checked_div(PAGE_SIZE_KB.saturating_mul(KIBIBYTE))
        .expect("PAGE_SIZE_KB * KIBIBYTE > 0")
        .saturating_sub(1)
        .saturating_mul(heap_cost)
}

/// Create the SBF virtual machine
pub fn create_vm<'a, 'b>(
    invoke_context: &'a mut InvokeContext<'b>,
    program: &'a Executable<InvokeContext<'b>>,
) -> Result<EbpfVm<'a, InvokeContext<'b>>, Box<dyn std::error::Error>> {
    let config = program.get_config();
    let sbpf_version = program.get_sbpf_version();
    let compute_budget = invoke_context.get_compute_budget();
    let heap_size = compute_budget.heap_size;
    invoke_context.consume_checked(calculate_heap_cost(heap_size, compute_budget.heap_cost))?;
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(
        usize::try_from(compute_budget.heap_size).unwrap(),
    );
    let stack_len = stack.len();
    let regions: Vec<MemoryRegion> = vec![
        program.get_ro_region(),
        MemoryRegion::new_writable_gapped(stack.as_slice_mut(), ebpf::MM_STACK_START, 0),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
    ];
    let log_collector = invoke_context.get_log_collector();
    let memory_mapping = MemoryMapping::new(regions, config, sbpf_version).map_err(|err| {
        ic_logger_msg!(log_collector, "Failed to create SBF VM: {}", err);
        Box::new(InstructionError::ProgramEnvironmentSetupFailure)
    })?;
    Ok(EbpfVm::new(
        program.get_loader().clone(),
        sbpf_version,
        invoke_context,
        memory_mapping,
        stack_len,
    ))
}

fn execute<'a, 'b: 'a>(
    invoke_context: &'a mut InvokeContext<'b>,
    executable: &'a Executable<InvokeContext<'static>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // We dropped the lifetime tracking in the Executor by setting it to 'static,
    // thus we need to reintroduce the correct lifetime of InvokeContext here again.
    let executable =
        unsafe { std::mem::transmute::<_, &'a Executable<InvokeContext<'b>>>(executable) };
    let log_collector = invoke_context.get_log_collector();
    let stack_height = invoke_context.get_stack_height();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_id = *instruction_context.get_last_program_key(transaction_context)?;
    #[cfg(any(target_os = "windows", not(target_arch = "x86_64")))]
    let use_jit = false;
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    let use_jit = executable.get_compiled_program().is_some();

    let compute_meter_prev = invoke_context.get_remaining();
    let mut create_vm_time = Measure::start("create_vm");
    let mut vm = create_vm(invoke_context, executable)?;
    create_vm_time.stop();

    let mut execute_time = Measure::start("execute");
    stable_log::program_invoke(&log_collector, &program_id, stack_height);
    let (compute_units_consumed, result) = vm.execute_program(executable, !use_jit);
    drop(vm);
    ic_logger_msg!(
        log_collector,
        "Program {} consumed {} of {} compute units",
        &program_id,
        compute_units_consumed,
        compute_meter_prev
    );
    execute_time.stop();

    let timings = &mut invoke_context.timings;
    timings.create_vm_us = timings.create_vm_us.saturating_add(create_vm_time.as_us());
    timings.execute_us = timings.execute_us.saturating_add(execute_time.as_us());

    match result {
        ProgramResult::Ok(status) if status != SUCCESS => {
            let error: InstructionError = status.into();
            Err(error.into())
        }
        ProgramResult::Err(error) => Err(error.into()),
        _ => Ok(()),
    }
}

fn check_program_account(
    log_collector: &Option<Rc<RefCell<LogCollector>>>,
    instruction_context: &InstructionContext,
    program: &BorrowedAccount,
    authority_address: &Pubkey,
) -> Result<LoaderV4State, InstructionError> {
    if !loader_v4::check_id(program.get_owner()) {
        ic_logger_msg!(log_collector, "Program not owned by loader");
        return Err(InstructionError::InvalidAccountOwner);
    }
    if program.get_data().is_empty() {
        ic_logger_msg!(log_collector, "Program is uninitialized");
        return Err(InstructionError::InvalidAccountData);
    }
    let state = get_state(program.get_data())?;
    if !program.is_writable() {
        ic_logger_msg!(log_collector, "Program is not writeable");
        return Err(InstructionError::InvalidArgument);
    }
    if !instruction_context.is_instruction_account_signer(1)? {
        ic_logger_msg!(log_collector, "Authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }
    if state.authority_address != *authority_address {
        ic_logger_msg!(log_collector, "Incorrect authority provided");
        return Err(InstructionError::IncorrectAuthority);
    }
    if matches!(state.status, LoaderV4Status::Finalized) {
        ic_logger_msg!(log_collector, "Program is finalized");
        return Err(InstructionError::Immutable);
    }
    Ok(*state)
}

pub fn process_instruction_write(
    invoke_context: &mut InvokeContext,
    offset: u32,
    bytes: Vec<u8>,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(1)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))?;
    let state = check_program_account(
        &log_collector,
        instruction_context,
        &program,
        authority_address,
    )?;
    if !matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Program is not retracted");
        return Err(InstructionError::InvalidArgument);
    }
    let end_offset = (offset as usize).saturating_add(bytes.len());
    program
        .get_data_mut(&invoke_context.feature_set)?
        .get_mut(
            LoaderV4State::program_data_offset().saturating_add(offset as usize)
                ..LoaderV4State::program_data_offset().saturating_add(end_offset),
        )
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Write out of bounds");
            InstructionError::AccountDataTooSmall
        })?
        .copy_from_slice(&bytes);
    Ok(())
}

pub fn process_instruction_truncate(
    invoke_context: &mut InvokeContext,
    new_size: u32,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(1)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))?;
    let is_initialization =
        new_size > 0 && program.get_data().len() < LoaderV4State::program_data_offset();
    if is_initialization {
        if !loader_v4::check_id(program.get_owner()) {
            ic_logger_msg!(log_collector, "Program not owned by loader");
            return Err(InstructionError::InvalidAccountOwner);
        }
        if !program.is_writable() {
            ic_logger_msg!(log_collector, "Program is not writeable");
            return Err(InstructionError::InvalidArgument);
        }
        if !program.is_signer() {
            ic_logger_msg!(log_collector, "Program did not sign");
            return Err(InstructionError::MissingRequiredSignature);
        }
        if !instruction_context.is_instruction_account_signer(1)? {
            ic_logger_msg!(log_collector, "Authority did not sign");
            return Err(InstructionError::MissingRequiredSignature);
        }
    } else {
        let state = check_program_account(
            &log_collector,
            instruction_context,
            &program,
            authority_address,
        )?;
        if !matches!(state.status, LoaderV4Status::Retracted) {
            ic_logger_msg!(log_collector, "Program is not retracted");
            return Err(InstructionError::InvalidArgument);
        }
    }
    let required_lamports = if new_size == 0 {
        0
    } else {
        let rent = invoke_context.get_sysvar_cache().get_rent()?;
        rent.minimum_balance(LoaderV4State::program_data_offset().saturating_add(new_size as usize))
    };
    match program.get_lamports().cmp(&required_lamports) {
        std::cmp::Ordering::Less => {
            ic_logger_msg!(
                log_collector,
                "Insufficient lamports, {} are required",
                required_lamports
            );
            return Err(InstructionError::InsufficientFunds);
        }
        std::cmp::Ordering::Greater => {
            let mut recipient =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            if !instruction_context.is_instruction_account_writable(2)? {
                ic_logger_msg!(log_collector, "Recipient is not writeable");
                return Err(InstructionError::InvalidArgument);
            }
            let lamports_to_receive = program.get_lamports().saturating_sub(required_lamports);
            program.checked_sub_lamports(lamports_to_receive, &invoke_context.feature_set)?;
            recipient.checked_add_lamports(lamports_to_receive, &invoke_context.feature_set)?;
        }
        std::cmp::Ordering::Equal => {}
    }
    if new_size == 0 {
        program.set_data_length(0, &invoke_context.feature_set)?;
    } else {
        program.set_data_length(
            LoaderV4State::program_data_offset().saturating_add(new_size as usize),
            &invoke_context.feature_set,
        )?;
        if is_initialization {
            let state = get_state_mut(program.get_data_mut(&invoke_context.feature_set)?)?;
            state.slot = 0;
            state.status = LoaderV4Status::Retracted;
            state.authority_address = *authority_address;
        }
    }
    Ok(())
}

pub fn process_instruction_deploy(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(1)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))?;
    let source_program = instruction_context
        .try_borrow_instruction_account(transaction_context, 2)
        .ok();
    let state = check_program_account(
        &log_collector,
        instruction_context,
        &program,
        authority_address,
    )?;
    let current_slot = invoke_context.get_sysvar_cache().get_clock()?.slot;

    // Slot = 0 indicates that the program hasn't been deployed yet. So no need to check for the cooldown slots.
    // (Without this check, the program deployment is failing in freshly started test validators. That's
    //  because at startup current_slot is 0, which is < DEPLOYMENT_COOLDOWN_IN_SLOTS).
    if state.slot != 0 && state.slot.saturating_add(DEPLOYMENT_COOLDOWN_IN_SLOTS) > current_slot {
        ic_logger_msg!(
            log_collector,
            "Program was deployed recently, cooldown still in effect"
        );
        return Err(InstructionError::InvalidArgument);
    }
    if !matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Destination program is not retracted");
        return Err(InstructionError::InvalidArgument);
    }
    let buffer = if let Some(ref source_program) = source_program {
        let source_state = check_program_account(
            &log_collector,
            instruction_context,
            source_program,
            authority_address,
        )?;
        if !matches!(source_state.status, LoaderV4Status::Retracted) {
            ic_logger_msg!(log_collector, "Source program is not retracted");
            return Err(InstructionError::InvalidArgument);
        }
        source_program
    } else {
        &program
    };

    let programdata = buffer
        .get_data()
        .get(LoaderV4State::program_data_offset()..)
        .ok_or(InstructionError::AccountDataTooSmall)?;

    let deployment_slot = state.slot;
    let effective_slot = deployment_slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET);

    let mut load_program_metrics = LoadProgramMetrics {
        program_id: buffer.get_key().to_string(),
        ..LoadProgramMetrics::default()
    };
    let executor = LoadedProgram::new(
        &loader_v4::id(),
        invoke_context
            .programs_modified_by_tx
            .environments
            .program_runtime_v2
            .clone(),
        deployment_slot,
        effective_slot,
        None,
        programdata,
        buffer.get_data().len(),
        &mut load_program_metrics,
    )
    .map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    load_program_metrics.submit_datapoint(&mut invoke_context.timings);
    if let Some(mut source_program) = source_program {
        let rent = invoke_context.get_sysvar_cache().get_rent()?;
        let required_lamports = rent.minimum_balance(source_program.get_data().len());
        let transfer_lamports = required_lamports.saturating_sub(program.get_lamports());
        program.set_data_from_slice(source_program.get_data(), &invoke_context.feature_set)?;
        source_program.set_data_length(0, &invoke_context.feature_set)?;
        source_program.checked_sub_lamports(transfer_lamports, &invoke_context.feature_set)?;
        program.checked_add_lamports(transfer_lamports, &invoke_context.feature_set)?;
    }
    let state = get_state_mut(program.get_data_mut(&invoke_context.feature_set)?)?;
    state.slot = current_slot;
    state.status = LoaderV4Status::Deployed;

    if let Some(old_entry) = invoke_context.find_program_in_cache(program.get_key()) {
        executor.tx_usage_counter.store(
            old_entry.tx_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        executor.ix_usage_counter.store(
            old_entry.ix_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
    invoke_context
        .programs_modified_by_tx
        .replenish(*program.get_key(), Arc::new(executor));
    Ok(())
}

pub fn process_instruction_retract(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;

    let authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(1)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))?;
    let state = check_program_account(
        &log_collector,
        instruction_context,
        &program,
        authority_address,
    )?;
    let current_slot = invoke_context.get_sysvar_cache().get_clock()?.slot;
    if state.slot.saturating_add(DEPLOYMENT_COOLDOWN_IN_SLOTS) > current_slot {
        ic_logger_msg!(
            log_collector,
            "Program was deployed recently, cooldown still in effect"
        );
        return Err(InstructionError::InvalidArgument);
    }
    if matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Program is not deployed");
        return Err(InstructionError::InvalidArgument);
    }
    let state = get_state_mut(program.get_data_mut(&invoke_context.feature_set)?)?;
    state.status = LoaderV4Status::Retracted;
    Ok(())
}

pub fn process_instruction_transfer_authority(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(1)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))?;
    let new_authority_address = instruction_context
        .get_index_of_instruction_account_in_transaction(2)
        .and_then(|index| transaction_context.get_key_of_account_at_index(index))
        .ok()
        .cloned();
    let _state = check_program_account(
        &log_collector,
        instruction_context,
        &program,
        authority_address,
    )?;
    if new_authority_address.is_some() && !instruction_context.is_instruction_account_signer(2)? {
        ic_logger_msg!(log_collector, "New authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }
    let state = get_state_mut(program.get_data_mut(&invoke_context.feature_set)?)?;
    if let Some(new_authority_address) = new_authority_address {
        state.authority_address = new_authority_address;
    } else if matches!(state.status, LoaderV4Status::Deployed) {
        state.status = LoaderV4Status::Finalized;
    } else {
        ic_logger_msg!(log_collector, "Program must be deployed to be finalized");
        return Err(InstructionError::InvalidArgument);
    }
    Ok(())
}

declare_builtin_function!(
    Entrypoint,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg0: u64,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        process_instruction_inner(invoke_context)
    }
);

pub fn process_instruction_inner(
    invoke_context: &mut InvokeContext,
) -> Result<u64, Box<dyn std::error::Error>> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let instruction_data = instruction_context.get_instruction_data();
    let program_id = instruction_context.get_last_program_key(transaction_context)?;
    if loader_v4::check_id(program_id) {
        invoke_context.consume_checked(DEFAULT_COMPUTE_UNITS)?;
        match limited_deserialize(instruction_data)? {
            LoaderV4Instruction::Write { offset, bytes } => {
                process_instruction_write(invoke_context, offset, bytes)
            }
            LoaderV4Instruction::Truncate { new_size } => {
                process_instruction_truncate(invoke_context, new_size)
            }
            LoaderV4Instruction::Deploy => process_instruction_deploy(invoke_context),
            LoaderV4Instruction::Retract => process_instruction_retract(invoke_context),
            LoaderV4Instruction::TransferAuthority => {
                process_instruction_transfer_authority(invoke_context)
            }
        }
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
    } else {
        let program = instruction_context.try_borrow_last_program_account(transaction_context)?;
        if !loader_v4::check_id(program.get_owner()) {
            ic_logger_msg!(log_collector, "Program not owned by loader");
            return Err(Box::new(InstructionError::InvalidAccountOwner));
        }
        if program.get_data().is_empty() {
            ic_logger_msg!(log_collector, "Program is uninitialized");
            return Err(Box::new(InstructionError::InvalidAccountData));
        }
        let state = get_state(program.get_data())?;
        if matches!(state.status, LoaderV4Status::Retracted) {
            ic_logger_msg!(log_collector, "Program is not deployed");
            return Err(Box::new(InstructionError::InvalidArgument));
        }
        let mut get_or_create_executor_time = Measure::start("get_or_create_executor_time");
        let loaded_program = invoke_context
            .find_program_in_cache(program.get_key())
            .ok_or_else(|| {
                ic_logger_msg!(log_collector, "Program is not cached");
                InstructionError::InvalidAccountData
            })?;
        get_or_create_executor_time.stop();
        saturating_add_assign!(
            invoke_context.timings.get_or_create_executor_us,
            get_or_create_executor_time.as_us()
        );
        drop(program);
        loaded_program
            .ix_usage_counter
            .fetch_add(1, Ordering::Relaxed);
        match &loaded_program.program {
            LoadedProgramType::FailedVerification(_)
            | LoadedProgramType::Closed
            | LoadedProgramType::DelayVisibility => {
                ic_logger_msg!(log_collector, "Program is not deployed");
                Err(Box::new(InstructionError::InvalidAccountData) as Box<dyn std::error::Error>)
            }
            LoadedProgramType::Typed(executable) => execute(invoke_context, executable),
            _ => Err(Box::new(InstructionError::IncorrectProgramId) as Box<dyn std::error::Error>),
        }
    }
    .map(|_| 0)
}
