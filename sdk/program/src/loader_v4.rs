//! The v4 built-in loader program.
//!
//! This is the loader of the program runtime v2.

use crate::{
    instruction::{AccountMeta, Instruction},
    loader_v4_instruction::LoaderV4Instruction,
    pubkey::Pubkey,
    system_instruction,
};

crate::declare_id!("LoaderV411111111111111111111111111111111111");

/// Cooldown before a program can be un-/redeployed again
pub const DEPLOYMENT_COOLDOWN_IN_SLOTS: u64 = 750;

#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, AbiExample)]
pub enum LoaderV4Status {
    /// Program is in maintenance
    Retracted,
    /// Program is ready to be executed
    Deployed,
    /// Same as `Deployed`, but can not be retracted anymore
    Finalized,
}

/// LoaderV4 account states
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, AbiExample)]
pub struct LoaderV4State {
    /// Slot in which the program was last deployed, retracted or initialized.
    pub slot: u64,
    /// Address of signer which can send program management instructions.
    pub authority_address: Pubkey,
    /// Deployment status.
    pub status: LoaderV4Status,
    // The raw program data follows this serialized structure in the
    // account's data.
}

impl LoaderV4State {
    /// Size of a serialized program account.
    pub const fn program_data_offset() -> usize {
        std::mem::size_of::<Self>()
    }
}

pub fn is_write_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 0 == instruction_data[0]
}

pub fn is_truncate_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 1 == instruction_data[0]
}

pub fn is_deploy_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 2 == instruction_data[0]
}

pub fn is_retract_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 3 == instruction_data[0]
}

pub fn is_transfer_authority_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 4 == instruction_data[0]
}

/// Returns the instructions required to initialize a program/buffer account.
pub fn create_buffer(
    payer_address: &Pubkey,
    buffer_address: &Pubkey,
    lamports: u64,
    authority: &Pubkey,
    new_size: u32,
    recipient_address: &Pubkey,
) -> Vec<Instruction> {
    vec![
        system_instruction::create_account(payer_address, buffer_address, lamports, 0, &id()),
        truncate_uninitialized(buffer_address, authority, new_size, recipient_address),
    ]
}

/// Returns the instructions required to set the length of an uninitialized program account.
/// This instruction will require the program account to also sign the transaction.
pub fn truncate_uninitialized(
    program_address: &Pubkey,
    authority: &Pubkey,
    new_size: u32,
    recipient_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Truncate { new_size },
        vec![
            AccountMeta::new(*program_address, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*recipient_address, false),
        ],
    )
}

/// Returns the instructions required to set the length of the program account.
pub fn truncate(
    program_address: &Pubkey,
    authority: &Pubkey,
    new_size: u32,
    recipient_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Truncate { new_size },
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*recipient_address, false),
        ],
    )
}

/// Returns the instructions required to write a chunk of program data to a
/// buffer account.
pub fn write(
    program_address: &Pubkey,
    authority: &Pubkey,
    offset: u32,
    bytes: Vec<u8>,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Write { offset, bytes },
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to deploy a program.
pub fn deploy(program_address: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Deploy,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to deploy a program using a buffer.
pub fn deploy_from_source(
    program_address: &Pubkey,
    authority: &Pubkey,
    source_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Deploy,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*source_address, false),
        ],
    )
}

/// Returns the instructions required to retract a program.
pub fn retract(program_address: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Retract,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to transfer authority over a program.
pub fn transfer_authority(
    program_address: &Pubkey,
    authority: &Pubkey,
    new_authority: Option<&Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(*program_address, false),
        AccountMeta::new_readonly(*authority, true),
    ];

    if let Some(new_auth) = new_authority {
        accounts.push(AccountMeta::new_readonly(*new_auth, true));
    }

    Instruction::new_with_bincode(id(), &LoaderV4Instruction::TransferAuthority, accounts)
}
