use {
    solana_program_runtime::compute_budget_processor::process_compute_budget_instructions,
    solana_sdk::{
        instruction::CompiledInstruction,
        pubkey::Pubkey,
        transaction::{SanitizedTransaction, SanitizedVersionedTransaction},
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPriorityDetails {
    pub priority: u64,
    pub compute_unit_limit: u64,
}

pub trait GetTransactionPriorityDetails {
    fn get_transaction_priority_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<TransactionPriorityDetails>;

    fn process_compute_budget_instruction<'a>(
        instructions: impl Iterator<Item = (&'a Pubkey, &'a CompiledInstruction)>,
        _round_compute_unit_price_enabled: bool,
    ) -> Option<TransactionPriorityDetails> {
        let compute_budget_limits = process_compute_budget_instructions(instructions).ok()?;
        Some(TransactionPriorityDetails {
            priority: compute_budget_limits.compute_unit_price,
            compute_unit_limit: u64::from(compute_budget_limits.compute_unit_limit),
        })
    }
}

impl GetTransactionPriorityDetails for SanitizedVersionedTransaction {
    fn get_transaction_priority_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<TransactionPriorityDetails> {
        Self::process_compute_budget_instruction(
            self.get_message().program_instructions_iter(),
            round_compute_unit_price_enabled,
        )
    }
}

impl GetTransactionPriorityDetails for SanitizedTransaction {
    fn get_transaction_priority_details(
        &self,
        round_compute_unit_price_enabled: bool,
    ) -> Option<TransactionPriorityDetails> {
        Self::process_compute_budget_instruction(
            self.message().program_instructions_iter(),
            round_compute_unit_price_enabled,
        )
    }
}
