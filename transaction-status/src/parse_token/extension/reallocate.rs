use {super::*, spl_token_2022::extension::ExtensionType};

pub(in crate::parse_token) fn parse_reallocate_instruction(
    extension_types: Vec<ExtensionType>,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    check_num_token_accounts(account_indexes, 4)?;
    let mut value = json!({
        "account": account_keys[account_indexes[0] as usize].to_string(),
        "payer": account_keys[account_indexes[1] as usize].to_string(),
        "systemProgram": account_keys[account_indexes[2] as usize].to_string(),
        "extensionTypes": extension_types.into_iter().map(UiExtensionType::from).collect::<Vec<_>>(),
    });
    let map = value.as_object_mut().unwrap();
    parse_signers(
        map,
        3,
        account_keys,
        account_indexes,
        "owner",
        "multisigOwner",
    );
    Ok(ParsedInstructionEnum {
        instruction_type: "reallocate".to_string(),
        info: value,
    })
}
