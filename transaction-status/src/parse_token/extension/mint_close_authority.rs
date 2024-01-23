use {
    super::*,
    spl_token_2022::solana_program::{program_option::COption, pubkey::Pubkey},
};

pub(in crate::parse_token) fn parse_initialize_mint_close_authority_instruction(
    close_authority: COption<Pubkey>,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    check_num_token_accounts(account_indexes, 1)?;
    Ok(ParsedInstructionEnum {
        instruction_type: "initializeMintCloseAuthority".to_string(),
        info: json!({
            "mint": account_keys[account_indexes[0] as usize].to_string(),
            "newAuthority": map_coption_pubkey(close_authority),
        }),
    })
}
