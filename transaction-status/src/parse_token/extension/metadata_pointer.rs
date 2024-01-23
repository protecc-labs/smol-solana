use {
    super::*,
    spl_token_2022::{
        extension::metadata_pointer::instruction::*,
        instruction::{decode_instruction_data, decode_instruction_type},
    },
};

pub(in crate::parse_token) fn parse_metadata_pointer_instruction(
    instruction_data: &[u8],
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match decode_instruction_type(instruction_data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?
    {
        MetadataPointerInstruction::Initialize => {
            check_num_token_accounts(account_indexes, 1)?;
            let InitializeInstructionData {
                authority,
                metadata_address,
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
            if let Some(metadata_address) = Option::<Pubkey>::from(metadata_address) {
                map.insert(
                    "metadataAddress".to_string(),
                    json!(metadata_address.to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeMetadataPointer".to_string(),
                info: value,
            })
        }
        MetadataPointerInstruction::Update => {
            check_num_token_accounts(account_indexes, 2)?;
            let UpdateInstructionData { metadata_address } =
                *decode_instruction_data(instruction_data).map_err(|_| {
                    ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken)
                })?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let Some(metadata_address) = Option::<Pubkey>::from(metadata_address) {
                map.insert(
                    "metadataAddress".to_string(),
                    json!(metadata_address.to_string()),
                );
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
                instruction_type: "updateMetadataPointer".to_string(),
                info: value,
            })
        }
    }
}
