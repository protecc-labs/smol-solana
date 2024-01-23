use {
    super::*,
    spl_token_2022::extension::default_account_state::instruction::{
        decode_instruction, DefaultAccountStateInstruction,
    },
};

pub(in crate::parse_token) fn parse_default_account_state_instruction(
    instruction_data: &[u8],
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let (default_account_state_instruction, account_state) = decode_instruction(instruction_data)
        .map_err(|_| {
        ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken)
    })?;
    let instruction_type = "DefaultAccountState";
    match default_account_state_instruction {
        DefaultAccountStateInstruction::Initialize => {
            check_num_token_accounts(account_indexes, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: format!("initialize{instruction_type}"),
                info: json!({
                    "mint": account_keys[account_indexes[0] as usize].to_string(),
                    "accountState": UiAccountState::from(account_state),
                }),
            })
        }
        DefaultAccountStateInstruction::Update => {
            check_num_token_accounts(account_indexes, 2)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
                "accountState": UiAccountState::from(account_state),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                1,
                account_keys,
                account_indexes,
                "freezeAuthority",
                "multisigFreezeAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: format!("update{instruction_type}"),
                info: value,
            })
        }
    }
}
