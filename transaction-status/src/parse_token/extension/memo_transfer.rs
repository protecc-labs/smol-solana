use {
    super::*,
    spl_token_2022::{
        extension::memo_transfer::instruction::RequiredMemoTransfersInstruction,
        instruction::decode_instruction_type,
    },
};

pub(in crate::parse_token) fn parse_memo_transfer_instruction(
    instruction_data: &[u8],
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    check_num_token_accounts(account_indexes, 2)?;
    let instruction_type_str = match decode_instruction_type(instruction_data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?
    {
        RequiredMemoTransfersInstruction::Enable => "enable",
        RequiredMemoTransfersInstruction::Disable => "disable",
    };
    let mut value = json!({
        "account": account_keys[account_indexes[0] as usize].to_string(),
    });
    let map = value.as_object_mut().unwrap();
    parse_signers(
        map,
        1,
        account_keys,
        account_indexes,
        "owner",
        "multisigOwner",
    );
    Ok(ParsedInstructionEnum {
        instruction_type: format!("{instruction_type_str}RequiredMemoTransfers"),
        info: value,
    })
}
