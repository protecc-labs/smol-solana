use {
    crate::parse_instruction::{
        check_num_accounts, ParsableProgram, ParseInstructionError, ParsedInstructionEnum,
    },
    bincode::deserialize,
    serde_json::{json, Map, Value},
    solana_sdk::{
        instruction::CompiledInstruction, message::AccountKeys,
        stake::instruction::StakeInstruction,
    },
};

pub fn parse_stake(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let stake_instruction: StakeInstruction = deserialize(&instruction.data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::Stake))?;
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::Stake,
            ));
        }
    }
    match stake_instruction {
        StakeInstruction::Initialize(authorized, lockup) => {
            check_num_stake_accounts(&instruction.accounts, 2)?;
            let authorized = json!({
                "staker": authorized.staker.to_string(),
                "withdrawer": authorized.withdrawer.to_string(),
            });
            let lockup = json!({
                "unixTimestamp": lockup.unix_timestamp,
                "epoch": lockup.epoch,
                "custodian": lockup.custodian.to_string(),
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "initialize".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "authorized": authorized,
                    "lockup": lockup,
                }),
            })
        }
        StakeInstruction::Authorize(new_authorized, authority_type) => {
            check_num_stake_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                "authority": account_keys[instruction.accounts[2] as usize].to_string(),
                "newAuthority": new_authorized.to_string(),
                "authorityType": authority_type,
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 4 {
                map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[3] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "authorize".to_string(),
                info: value,
            })
        }
        StakeInstruction::DelegateStake => {
            check_num_stake_accounts(&instruction.accounts, 6)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "delegate".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "stakeHistorySysvar": account_keys[instruction.accounts[3] as usize].to_string(),
                    "stakeConfigAccount": account_keys[instruction.accounts[4] as usize].to_string(),
                    "stakeAuthority": account_keys[instruction.accounts[5] as usize].to_string(),
                }),
            })
        }
        StakeInstruction::Split(lamports) => {
            check_num_stake_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "split".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "newSplitAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "stakeAuthority": account_keys[instruction.accounts[2] as usize].to_string(),
                    "lamports": lamports,
                }),
            })
        }
        StakeInstruction::Withdraw(lamports) => {
            check_num_stake_accounts(&instruction.accounts, 5)?;
            let mut value = json!({
                "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                "destination": account_keys[instruction.accounts[1] as usize].to_string(),
                "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                "stakeHistorySysvar": account_keys[instruction.accounts[3] as usize].to_string(),
                "withdrawAuthority": account_keys[instruction.accounts[4] as usize].to_string(),
                "lamports": lamports,
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 6 {
                map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[5] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "withdraw".to_string(),
                info: value,
            })
        }
        StakeInstruction::Deactivate => {
            check_num_stake_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "deactivate".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "stakeAuthority": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        StakeInstruction::SetLockup(lockup_args) => {
            check_num_stake_accounts(&instruction.accounts, 2)?;
            let mut lockup_map = Map::new();
            if let Some(timestamp) = lockup_args.unix_timestamp {
                lockup_map.insert("unixTimestamp".to_string(), json!(timestamp));
            }
            if let Some(epoch) = lockup_args.epoch {
                lockup_map.insert("epoch".to_string(), json!(epoch));
            }
            if let Some(custodian) = lockup_args.custodian {
                lockup_map.insert("custodian".to_string(), json!(custodian.to_string()));
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "setLockup".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "custodian": account_keys[instruction.accounts[1] as usize].to_string(),
                    "lockup": lockup_map,
                }),
            })
        }
        StakeInstruction::Merge => {
            check_num_stake_accounts(&instruction.accounts, 5)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "merge".to_string(),
                info: json!({
                    "destination": account_keys[instruction.accounts[0] as usize].to_string(),
                    "source": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "stakeHistorySysvar": account_keys[instruction.accounts[3] as usize].to_string(),
                    "stakeAuthority": account_keys[instruction.accounts[4] as usize].to_string(),
                }),
            })
        }
        StakeInstruction::AuthorizeWithSeed(args) => {
            check_num_stake_accounts(&instruction.accounts, 2)?;
            let mut value = json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "authorityBase": account_keys[instruction.accounts[1] as usize].to_string(),
                    "newAuthorized": args.new_authorized_pubkey.to_string(),
                    "authorityType": args.stake_authorize,
                    "authoritySeed": args.authority_seed,
                    "authorityOwner": args.authority_owner.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 3 {
                map.insert(
                    "clockSysvar".to_string(),
                    json!(account_keys[instruction.accounts[2] as usize].to_string()),
                );
            }
            if instruction.accounts.len() >= 4 {
                map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[3] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeWithSeed".to_string(),
                info: value,
            })
        }
        StakeInstruction::InitializeChecked => {
            check_num_stake_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeChecked".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "staker": account_keys[instruction.accounts[2] as usize].to_string(),
                    "withdrawer": account_keys[instruction.accounts[3] as usize].to_string(),
                }),
            })
        }
        StakeInstruction::AuthorizeChecked(authority_type) => {
            check_num_stake_accounts(&instruction.accounts, 4)?;
            let mut value = json!({
                "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                "authority": account_keys[instruction.accounts[2] as usize].to_string(),
                "newAuthority": account_keys[instruction.accounts[3] as usize].to_string(),
                "authorityType": authority_type,
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 5 {
                map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[4] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeChecked".to_string(),
                info: value,
            })
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            check_num_stake_accounts(&instruction.accounts, 4)?;
            let mut value = json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "authorityBase": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "newAuthorized": account_keys[instruction.accounts[3] as usize].to_string(),
                    "authorityType": args.stake_authorize,
                    "authoritySeed": args.authority_seed,
                    "authorityOwner": args.authority_owner.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if instruction.accounts.len() >= 5 {
                map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[4] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeCheckedWithSeed".to_string(),
                info: value,
            })
        }
        StakeInstruction::SetLockupChecked(lockup_args) => {
            check_num_stake_accounts(&instruction.accounts, 2)?;
            let mut lockup_map = Map::new();
            if let Some(timestamp) = lockup_args.unix_timestamp {
                lockup_map.insert("unixTimestamp".to_string(), json!(timestamp));
            }
            if let Some(epoch) = lockup_args.epoch {
                lockup_map.insert("epoch".to_string(), json!(epoch));
            }
            if instruction.accounts.len() >= 3 {
                lockup_map.insert(
                    "custodian".to_string(),
                    json!(account_keys[instruction.accounts[2] as usize].to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "setLockupChecked".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "custodian": account_keys[instruction.accounts[1] as usize].to_string(),
                    "lockup": lockup_map,
                }),
            })
        }
        StakeInstruction::GetMinimumDelegation => Ok(ParsedInstructionEnum {
            instruction_type: "getMinimumDelegation".to_string(),
            info: Value::default(),
        }),
        StakeInstruction::DeactivateDelinquent => {
            check_num_stake_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "deactivateDelinquent".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "referenceVoteAccount": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        StakeInstruction::Redelegate => {
            check_num_stake_accounts(&instruction.accounts, 5)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "redelegate".to_string(),
                info: json!({
                    "stakeAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "newStakeAccount": account_keys[instruction.accounts[1] as usize].to_string(),
                    "voteAccount": account_keys[instruction.accounts[2] as usize].to_string(),
                    "stakeConfigAccount": account_keys[instruction.accounts[3] as usize].to_string(),
                    "stakeAuthority": account_keys[instruction.accounts[4] as usize].to_string(),
                }),
            })
        }
    }
}

fn check_num_stake_accounts(accounts: &[u8], num: usize) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::Stake)
}
