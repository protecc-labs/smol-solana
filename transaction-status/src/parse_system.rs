use {
    crate::parse_instruction::{
        check_num_accounts, ParsableProgram, ParseInstructionError, ParsedInstructionEnum,
    },
    bincode::deserialize,
    serde_json::json,
    solana_sdk::{
        instruction::CompiledInstruction, message::AccountKeys,
        system_instruction::SystemInstruction,
    },
};

pub fn parse_system(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let system_instruction: SystemInstruction = deserialize(&instruction.data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::System))?;
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::System,
            ));
        }
    }
    match system_instruction {
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "createAccount".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "newAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "lamports": lamports,
                    "space": space,
                    "owner": owner.to_string(),
                }),
            })
        }
        SystemInstruction::Assign { owner } => {
            check_num_system_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "assign".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "owner": owner.to_string(),
                }),
            })
        }
        SystemInstruction::Transfer { lamports } => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "transfer".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "destination": account_keys[instruction.accounts[1] as usize].to_string(),
                    "lamports": lamports,
                }),
            })
        }
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "createAccountWithSeed".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "newAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "base": base.to_string(),
                    "seed": seed,
                    "lamports": lamports,
                    "space": space,
                    "owner": owner.to_string(),
                }),
            })
        }
        SystemInstruction::AdvanceNonceAccount => {
            check_num_system_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "advanceNonce".to_string(),
                info: json!({
                    "nonceAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "recentBlockhashesSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "nonceAuthority": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        SystemInstruction::WithdrawNonceAccount(lamports) => {
            check_num_system_accounts(&instruction.accounts, 5)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "withdrawFromNonce".to_string(),
                info: json!({
                    "nonceAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "destination": account_keys[instruction.accounts[1] as usize].to_string(),
                    "recentBlockhashesSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[3] as usize].to_string(),
                    "nonceAuthority": account_keys[instruction.accounts[4] as usize].to_string(),
                    "lamports": lamports,
                }),
            })
        }
        SystemInstruction::InitializeNonceAccount(authority) => {
            check_num_system_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeNonce".to_string(),
                info: json!({
                    "nonceAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "recentBlockhashesSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "nonceAuthority": authority.to_string(),
                }),
            })
        }
        SystemInstruction::AuthorizeNonceAccount(authority) => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeNonce".to_string(),
                info: json!({
                    "nonceAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "nonceAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "newAuthorized": authority.to_string(),
                }),
            })
        }
        SystemInstruction::UpgradeNonceAccount => {
            check_num_system_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "upgradeNonce".to_string(),
                info: json!({
                    "nonceAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                }),
            })
        }
        SystemInstruction::Allocate { space } => {
            check_num_system_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "allocate".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "space": space,
                }),
            })
        }
        SystemInstruction::AllocateWithSeed {
            base,
            seed,
            space,
            owner,
        } => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "allocateWithSeed".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "base": base.to_string(),
                    "seed": seed,
                    "space": space,
                    "owner": owner.to_string(),
                }),
            })
        }
        SystemInstruction::AssignWithSeed { base, seed, owner } => {
            check_num_system_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "assignWithSeed".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "base": base.to_string(),
                    "seed": seed,
                    "owner": owner.to_string(),
                }),
            })
        }
        SystemInstruction::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        } => {
            check_num_system_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "transferWithSeed".to_string(),
                info: json!({
                    "source": account_keys[instruction.accounts[0] as usize].to_string(),
                    "sourceBase": account_keys[instruction.accounts[1] as usize].to_string(),
                    "destination": account_keys[instruction.accounts[2] as usize].to_string(),
                    "lamports": lamports,
                    "sourceSeed": from_seed,
                    "sourceOwner": from_owner.to_string(),
                }),
            })
        }
    }
}

fn check_num_system_accounts(accounts: &[u8], num: usize) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::System)
}
