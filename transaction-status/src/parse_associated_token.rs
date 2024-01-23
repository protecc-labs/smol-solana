use {
    crate::parse_instruction::{
        check_num_accounts, ParsableProgram, ParseInstructionError, ParsedInstructionEnum,
    },
    borsh::BorshDeserialize,
    serde_json::json,
    solana_sdk::{instruction::CompiledInstruction, message::AccountKeys, pubkey::Pubkey},
    spl_associated_token_account::instruction::AssociatedTokenAccountInstruction,
};

// A helper function to convert spl_associated_token_account::id() as spl_sdk::pubkey::Pubkey
// to solana_sdk::pubkey::Pubkey
pub fn spl_associated_token_id() -> Pubkey {
    Pubkey::new_from_array(spl_associated_token_account::id().to_bytes())
}

pub fn parse_associated_token(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::SplAssociatedTokenAccount,
            ));
        }
    }
    let ata_instruction = if instruction.data.is_empty() {
        AssociatedTokenAccountInstruction::Create
    } else {
        AssociatedTokenAccountInstruction::try_from_slice(&instruction.data)
            .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?
    };

    match ata_instruction {
        AssociatedTokenAccountInstruction::Create => {
            check_num_associated_token_accounts(&instruction.accounts, 6)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "create".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "account": account_keys[instruction.accounts[1] as usize].to_string(),
                    "wallet": account_keys[instruction.accounts[2] as usize].to_string(),
                    "mint": account_keys[instruction.accounts[3] as usize].to_string(),
                    "systemProgram": account_keys[instruction.accounts[4] as usize].to_string(),
                    "tokenProgram": account_keys[instruction.accounts[5] as usize].to_string(),
                }),
            })
        }
        AssociatedTokenAccountInstruction::CreateIdempotent => {
            check_num_associated_token_accounts(&instruction.accounts, 6)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "createIdempotent".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "account": account_keys[instruction.accounts[1] as usize].to_string(),
                    "wallet": account_keys[instruction.accounts[2] as usize].to_string(),
                    "mint": account_keys[instruction.accounts[3] as usize].to_string(),
                    "systemProgram": account_keys[instruction.accounts[4] as usize].to_string(),
                    "tokenProgram": account_keys[instruction.accounts[5] as usize].to_string(),
                }),
            })
        }
        AssociatedTokenAccountInstruction::RecoverNested => {
            check_num_associated_token_accounts(&instruction.accounts, 7)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "recoverNested".to_string(),
                info: json!({
                    "nestedSource": account_keys[instruction.accounts[0] as usize].to_string(),
                    "nestedMint": account_keys[instruction.accounts[1] as usize].to_string(),
                    "destination": account_keys[instruction.accounts[2] as usize].to_string(),
                    "nestedOwner": account_keys[instruction.accounts[3] as usize].to_string(),
                    "ownerMint": account_keys[instruction.accounts[4] as usize].to_string(),
                    "wallet": account_keys[instruction.accounts[5] as usize].to_string(),
                    "tokenProgram": account_keys[instruction.accounts[6] as usize].to_string(),
                }),
            })
        }
    }
}

fn check_num_associated_token_accounts(
    accounts: &[u8],
    num: usize,
) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::SplAssociatedTokenAccount)
}