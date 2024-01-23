use {super::*, spl_token_2022::extension::transfer_fee::instruction::TransferFeeInstruction};

pub(in crate::parse_token) fn parse_transfer_fee_instruction(
    transfer_fee_instruction: TransferFeeInstruction,
    account_indexes: &[u8],
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    match transfer_fee_instruction {
        TransferFeeInstruction::InitializeTransferFeeConfig {
            transfer_fee_config_authority,
            withdraw_withheld_authority,
            transfer_fee_basis_points,
            maximum_fee,
        } => {
            check_num_token_accounts(account_indexes, 1)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
                "transferFeeBasisPoints": transfer_fee_basis_points,
                "maximumFee": maximum_fee,
            });
            let map = value.as_object_mut().unwrap();
            if let COption::Some(transfer_fee_config_authority) = transfer_fee_config_authority {
                map.insert(
                    "transferFeeConfigAuthority".to_string(),
                    json!(transfer_fee_config_authority.to_string()),
                );
            }
            if let COption::Some(withdraw_withheld_authority) = withdraw_withheld_authority {
                map.insert(
                    "withdrawWithheldAuthority".to_string(),
                    json!(withdraw_withheld_authority.to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeTransferFeeConfig".to_string(),
                info: value,
            })
        }
        TransferFeeInstruction::TransferCheckedWithFee {
            amount,
            decimals,
            fee,
        } => {
            check_num_token_accounts(account_indexes, 4)?;
            let mut value = json!({
                "source": account_keys[account_indexes[0] as usize].to_string(),
                "mint": account_keys[account_indexes[1] as usize].to_string(),
                "destination": account_keys[account_indexes[2] as usize].to_string(),
                "tokenAmount": token_amount_to_ui_amount(amount, decimals),
                "feeAmount": token_amount_to_ui_amount(fee, decimals),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                3,
                account_keys,
                account_indexes,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "transferCheckedWithFee".to_string(),
                info: value,
            })
        }
        TransferFeeInstruction::WithdrawWithheldTokensFromMint => {
            check_num_token_accounts(account_indexes, 3)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
                "feeRecipient": account_keys[account_indexes[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                account_indexes,
                "withdrawWithheldAuthority",
                "multisigWithdrawWithheldAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "withdrawWithheldTokensFromMint".to_string(),
                info: value,
            })
        }
        TransferFeeInstruction::WithdrawWithheldTokensFromAccounts { num_token_accounts } => {
            check_num_token_accounts(account_indexes, 3 + num_token_accounts as usize)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
                "feeRecipient": account_keys[account_indexes[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            let mut source_accounts: Vec<String> = vec![];
            let first_source_account_index = account_indexes
                .len()
                .saturating_sub(num_token_accounts as usize);
            for i in account_indexes[first_source_account_index..].iter() {
                source_accounts.push(account_keys[*i as usize].to_string());
            }
            map.insert("sourceAccounts".to_string(), json!(source_accounts));
            parse_signers(
                map,
                2,
                account_keys,
                &account_indexes[..first_source_account_index],
                "withdrawWithheldAuthority",
                "multisigWithdrawWithheldAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "withdrawWithheldTokensFromAccounts".to_string(),
                info: value,
            })
        }
        TransferFeeInstruction::HarvestWithheldTokensToMint => {
            check_num_token_accounts(account_indexes, 1)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            let mut source_accounts: Vec<String> = vec![];
            for i in account_indexes.iter().skip(1) {
                source_accounts.push(account_keys[*i as usize].to_string());
            }
            map.insert("sourceAccounts".to_string(), json!(source_accounts));
            Ok(ParsedInstructionEnum {
                instruction_type: "harvestWithheldTokensToMint".to_string(),
                info: value,
            })
        }
        TransferFeeInstruction::SetTransferFee {
            transfer_fee_basis_points,
            maximum_fee,
        } => {
            check_num_token_accounts(account_indexes, 2)?;
            let mut value = json!({
                "mint": account_keys[account_indexes[0] as usize].to_string(),
                "transferFeeBasisPoints": transfer_fee_basis_points,
                "maximumFee": maximum_fee,
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                1,
                account_keys,
                account_indexes,
                "transferFeeConfigAuthority",
                "multisigtransferFeeConfigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "setTransferFee".to_string(),
                info: value,
            })
        }
    }
}
