use {
    crate::parse_instruction::{
        check_num_accounts, ParsableProgram, ParseInstructionError, ParsedInstructionEnum,
    },
    bincode::deserialize,
    serde_json::json,
    solana_sdk::{
        instruction::CompiledInstruction, message::AccountKeys, vote::instruction::VoteInstruction,
    },
};

pub fn parse_vote(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let vote_instruction: VoteInstruction = deserialize(&instruction.data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::Vote))?;
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::Vote,
            ));
        }
    }
    match vote_instruction {
        VoteInstruction::InitializeAccount(vote_init) => {
            check_num_vote_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initialize".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "node": account_keys[instruction.accounts[3] as usize].to_string(),
                    "authorizedVoter": vote_init.authorized_voter.to_string(),
                    "authorizedWithdrawer": vote_init.authorized_withdrawer.to_string(),
                    "commission": vote_init.commission,
                }),
            })
        }
        VoteInstruction::Authorize(new_authorized, authority_type) => {
            check_num_vote_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "authorize".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "authority": account_keys[instruction.accounts[2] as usize].to_string(),
                    "newAuthority": new_authorized.to_string(),
                    "authorityType": authority_type,
                }),
            })
        }
        VoteInstruction::AuthorizeWithSeed(args) => {
            check_num_vote_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeWithSeed".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "authorityBaseKey": account_keys[instruction.accounts[2] as usize].to_string(),
                    "authorityOwner": args.current_authority_derived_key_owner.to_string(),
                    "authoritySeed": args.current_authority_derived_key_seed,
                    "newAuthority": args.new_authority.to_string(),
                    "authorityType": args.authorization_type,
                }),
            })
        }
        VoteInstruction::AuthorizeCheckedWithSeed(args) => {
            check_num_vote_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeCheckedWithSeed".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "authorityBaseKey": account_keys[instruction.accounts[2] as usize].to_string(),
                    "authorityOwner": args.current_authority_derived_key_owner.to_string(),
                    "authoritySeed": args.current_authority_derived_key_seed,
                    "newAuthority": account_keys[instruction.accounts[3] as usize].to_string(),
                    "authorityType": args.authorization_type,
                }),
            })
        }
        VoteInstruction::Vote(vote) => {
            check_num_vote_accounts(&instruction.accounts, 4)?;
            let vote = json!({
                "slots": vote.slots,
                "hash": vote.hash.to_string(),
                "timestamp": vote.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "vote".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "slotHashesSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[3] as usize].to_string(),
                    "vote": vote,
                }),
            })
        }
        VoteInstruction::UpdateVoteState(vote_state_update) => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            let vote_state_update = json!({
                "lockouts": vote_state_update.lockouts,
                "root": vote_state_update.root,
                "hash": vote_state_update.hash.to_string(),
                "timestamp": vote_state_update.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updatevotestate".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "voteStateUpdate": vote_state_update,
                }),
            })
        }
        VoteInstruction::UpdateVoteStateSwitch(vote_state_update, hash) => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            let vote_state_update = json!({
                "lockouts": vote_state_update.lockouts,
                "root": vote_state_update.root,
                "hash": vote_state_update.hash.to_string(),
                "timestamp": vote_state_update.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "updatevotestateswitch".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "voteStateUpdate": vote_state_update,
                    "hash": hash.to_string(),
                }),
            })
        }
        VoteInstruction::CompactUpdateVoteState(vote_state_update) => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            let vote_state_update = json!({
                "lockouts": vote_state_update.lockouts,
                "root": vote_state_update.root,
                "hash": vote_state_update.hash.to_string(),
                "timestamp": vote_state_update.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "compactupdatevotestate".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "voteStateUpdate": vote_state_update,
                }),
            })
        }
        VoteInstruction::CompactUpdateVoteStateSwitch(vote_state_update, hash) => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            let vote_state_update = json!({
                "lockouts": vote_state_update.lockouts,
                "root": vote_state_update.root,
                "hash": vote_state_update.hash.to_string(),
                "timestamp": vote_state_update.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "compactupdatevotestateswitch".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "voteStateUpdate": vote_state_update,
                    "hash": hash.to_string(),
                }),
            })
        }
        VoteInstruction::Withdraw(lamports) => {
            check_num_vote_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "withdraw".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "destination": account_keys[instruction.accounts[1] as usize].to_string(),
                    "withdrawAuthority": account_keys[instruction.accounts[2] as usize].to_string(),
                    "lamports": lamports,
                }),
            })
        }
        VoteInstruction::UpdateValidatorIdentity => {
            check_num_vote_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "updateValidatorIdentity".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "newValidatorIdentity": account_keys[instruction.accounts[1] as usize].to_string(),
                    "withdrawAuthority": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        VoteInstruction::UpdateCommission(commission) => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "updateCommission".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "withdrawAuthority": account_keys[instruction.accounts[1] as usize].to_string(),
                    "commission": commission,
                }),
            })
        }
        VoteInstruction::VoteSwitch(vote, hash) => {
            check_num_vote_accounts(&instruction.accounts, 4)?;
            let vote = json!({
                "slots": vote.slots,
                "hash": vote.hash.to_string(),
                "timestamp": vote.timestamp,
            });
            Ok(ParsedInstructionEnum {
                instruction_type: "voteSwitch".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "slotHashesSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                    "voteAuthority": account_keys[instruction.accounts[3] as usize].to_string(),
                    "vote": vote,
                    "hash": hash.to_string(),
                }),
            })
        }
        VoteInstruction::AuthorizeChecked(authority_type) => {
            check_num_vote_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "authorizeChecked".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "clockSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "authority": account_keys[instruction.accounts[2] as usize].to_string(),
                    "newAuthority": account_keys[instruction.accounts[3] as usize].to_string(),
                    "authorityType": authority_type,
                }),
            })
        }
    }
}

fn check_num_vote_accounts(accounts: &[u8], num: usize) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::Vote)
}
