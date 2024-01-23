//! `Instruction`, with a stable memory layout

use {
    crate::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        stable_layout::stable_vec::StableVec,
    },
    std::fmt::Debug,
};

/// `Instruction`, with a stable memory layout
///
/// This is used within the runtime to ensure memory mapping and memory accesses are valid.  We
/// rely on known addresses and offsets within the runtime, and since `Instruction`'s layout is
/// allowed to change, we must provide a way to lock down the memory layout.  `StableInstruction`
/// reimplements the bare minimum of `Instruction`'s API sufficient only for the runtime's needs.
///
/// # Examples
///
/// Creating a `StableInstruction` from an `Instruction`
///
/// ```
/// # use solana_program::{instruction::Instruction, pubkey::Pubkey, stable_layout::stable_instruction::StableInstruction};
/// # let program_id = Pubkey::default();
/// # let accounts = Vec::default();
/// # let data = Vec::default();
/// let instruction = Instruction { program_id, accounts, data };
/// let instruction = StableInstruction::from(instruction);
/// ```
#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct StableInstruction {
    pub accounts: StableVec<AccountMeta>,
    pub data: StableVec<u8>,
    pub program_id: Pubkey,
}

impl From<Instruction> for StableInstruction {
    fn from(other: Instruction) -> Self {
        Self {
            accounts: other.accounts.into(),
            data: other.data.into(),
            program_id: other.program_id,
        }
    }
}
