use {
    super::*,
    spl_token_2022::{
        extension::transfer_hook::instruction::*,
        instruction::{decode_instruction_data, decode_instruction_type},
    },
};

pub(in crate::parse_token) fn parse_transfer_hook_instruction(
    instruction_data: &[u8],
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match decode_instruction_type(instruction_data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?
    {
        TransferHookInstruction::Initialize => {
            check_num_token_accounts(account_indexes, 1)?;
            let InitializeInstructionData {
                authority,
                program_id,
            } = *decode_instruction_data(instruction_data).map_err(|_| {
                ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken)
            })?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let Some(authority) = Option::<Pubkey>::from(authority) {
                map.insert("authority".to_string(), json!(authority.to_string()));
            }
            if let Some(program_id) = Option::<Pubkey>::from(program_id) {
                map.insert("programId".to_string(), json!(program_id.to_string()));
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeTransferHook".to_string(),
                info: value,
            })
        }
        TransferHookInstruction::Update => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateInstructionData { program_id } = *decode_instruction_data(instruction_data)
                .map_err(|_| {
                ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken)
            })?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let Some(program_id) = Option::<Pubkey>::from(program_id) {
                map.insert("programId".to_string(), json!(program_id.to_string()));
            }
            parse_signers(
                map,
                1,
                account_keys,
                account_indexes,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "updateTransferHook".to_string(),
                info: value,
            })
        }
    }
}
