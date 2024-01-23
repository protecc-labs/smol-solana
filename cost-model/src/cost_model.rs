//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!

use {
    crate::{block_cost_limits::*, transaction_cost::*},
    log::*,
    solana_program_runtime::{
        compute_budget::DEFAULT_HEAP_COST,
        compute_budget_processor::{
            process_compute_budget_instructions, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            MAX_COMPUTE_UNIT_LIMIT,
        },
    },
    solana_sdk::{
        borsh1::try_from_slice_unchecked,
        compute_budget::{self, ComputeBudgetInstruction},
        feature_set::{self, include_loaded_accounts_data_size_in_fee_calculation, FeatureSet},
        fee::FeeStructure,
        instruction::CompiledInstruction,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::SystemInstruction,
        system_program,
        transaction::SanitizedTransaction,
    },
};

pub struct CostModel;

impl CostModel {
    pub fn calculate_cost(
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) -> TransactionCost {
        if transaction.is_simple_vote_transaction() {
            TransactionCost::SimpleVote {
                writable_accounts: Self::get_writable_accounts(transaction),
            }
        } else {
            let mut tx_cost = UsageCostDetails::new_with_default_capacity();

            tx_cost.signature_cost = Self::get_signature_cost(transaction);
            Self::get_write_lock_cost(&mut tx_cost, transaction, feature_set);
            Self::get_transaction_cost(&mut tx_cost, transaction, feature_set);
            tx_cost.account_data_size = Self::calculate_account_data_size(transaction);

            debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
            TransactionCost::Transaction(tx_cost)
        }
    }

    fn get_signature_cost(transaction: &SanitizedTransaction) -> u64 {
        transaction.signatures().len() as u64 * SIGNATURE_COST
    }

    fn get_writable_accounts(transaction: &SanitizedTransaction) -> Vec<Pubkey> {
        let message = transaction.message();
        message
            .account_keys()
            .iter()
            .enumerate()
            .filter_map(|(i, k)| {
                if message.is_writable(i) {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_write_lock_cost(
        tx_cost: &mut UsageCostDetails,
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) {
        tx_cost.writable_accounts = Self::get_writable_accounts(transaction);
        let num_write_locks =
            if feature_set.is_active(&feature_set::cost_model_requested_write_lock_cost::id()) {
                transaction.message().num_write_locks()
            } else {
                tx_cost.writable_accounts.len() as u64
            };
        tx_cost.write_lock_cost = WRITE_LOCK_UNITS.saturating_mul(num_write_locks);
    }

    fn get_transaction_cost(
        tx_cost: &mut UsageCostDetails,
        transaction: &SanitizedTransaction,
        feature_set: &FeatureSet,
    ) {
        let mut builtin_costs = 0u64;
        let mut bpf_costs = 0u64;
        let mut loaded_accounts_data_size_cost = 0u64;
        let mut data_bytes_len_total = 0u64;
        let mut compute_unit_limit_is_set = false;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            // to keep the same behavior, look for builtin first
            if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                builtin_costs = builtin_costs.saturating_add(*builtin_cost);
            } else {
                bpf_costs = bpf_costs
                    .saturating_add(u64::from(DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT))
                    .min(u64::from(MAX_COMPUTE_UNIT_LIMIT));
            }
            data_bytes_len_total =
                data_bytes_len_total.saturating_add(instruction.data.len() as u64);

            if compute_budget::check_id(program_id) {
                if let Ok(ComputeBudgetInstruction::SetComputeUnitLimit(_)) =
                    try_from_slice_unchecked(&instruction.data)
                {
                    compute_unit_limit_is_set = true;
                }
            }
        }

        // calculate bpf cost based on compute budget instructions

        // if failed to process compute_budget instructions, the transaction will not be executed
        // by `bank`, therefore it should be considered as no execution cost by cost model.
        match process_compute_budget_instructions(transaction.message().program_instructions_iter())
        {
            Ok(compute_budget_limits) => {
                // if tx contained user-space instructions and a more accurate estimate available correct it,
                // where "user-space instructions" must be specifically checked by
                // 'compute_unit_limit_is_set' flag, because compute_budget does not distinguish
                // builtin and bpf instructions when calculating default compute-unit-limit. (see
                // compute_budget.rs test `test_process_mixed_instructions_without_compute_budget`)
                if bpf_costs > 0 && compute_unit_limit_is_set {
                    bpf_costs = u64::from(compute_budget_limits.compute_unit_limit);
                }

                if feature_set
                    .is_active(&include_loaded_accounts_data_size_in_fee_calculation::id())
                {
                    loaded_accounts_data_size_cost = FeeStructure::calculate_memory_usage_cost(
                        usize::try_from(compute_budget_limits.loaded_accounts_bytes).unwrap(),
                        DEFAULT_HEAP_COST,
                    )
                }
            }
            Err(_) => {
                builtin_costs = 0;
                bpf_costs = 0;
            }
        }

        tx_cost.builtins_execution_cost = builtin_costs;
        tx_cost.bpf_execution_cost = bpf_costs;
        tx_cost.loaded_accounts_data_size_cost = loaded_accounts_data_size_cost;
        tx_cost.data_bytes_cost = data_bytes_len_total / INSTRUCTION_DATA_BYTES_COST;
    }

    fn calculate_account_data_size_on_deserialized_system_instruction(
        instruction: SystemInstruction,
    ) -> u64 {
        match instruction {
            SystemInstruction::CreateAccount {
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::CreateAccountWithSeed {
                base: _base,
                seed: _seed,
                lamports: _lamports,
                space,
                owner: _owner,
            } => space,
            SystemInstruction::Allocate { space } => space,
            SystemInstruction::AllocateWithSeed {
                base: _base,
                seed: _seed,
                space,
                owner: _owner,
            } => space,
            _ => 0,
        }
    }

    fn calculate_account_data_size_on_instruction(
        program_id: &Pubkey,
        instruction: &CompiledInstruction,
    ) -> u64 {
        if program_id == &system_program::id() {
            if let Ok(instruction) = limited_deserialize(&instruction.data) {
                return Self::calculate_account_data_size_on_deserialized_system_instruction(
                    instruction,
                );
            }
        }
        0
    }

    /// eventually, potentially determine account data size of all writable accounts
    /// at the moment, calculate account data size of account creation
    fn calculate_account_data_size(transaction: &SanitizedTransaction) -> u64 {
        transaction
            .message()
            .program_instructions_iter()
            .map(|(program_id, instruction)| {
                Self::calculate_account_data_size_on_instruction(program_id, instruction)
            })
            .sum()
    }
}
