use {super::*, spl_token_2022::solana_program::pubkey::Pubkey};

pub(in crate::parse_token) fn parse_initialize_permanent_delegate_instruction(
    delegate: Pubkey,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    check_num_token_accounts(account_indexes, 1)?;
    Ok(ParsedInstructionEnum {
        instruction_type: "initializePermanentDelegate".to_string(),
        info: json!({
            "mint": account_keys[account_indexes[0] as usize].to_string(),
            "delegate": delegate.to_string(),
        }),
    })
}
