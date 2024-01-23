use {
    crate::parse_instruction::{
        check_num_accounts, ParsableProgram, ParseInstructionError, ParsedInstructionEnum,
    },
    extension::{
        confidential_transfer::*, confidential_transfer_fee::*, cpi_guard::*,
        default_account_state::*, group_member_pointer::*, group_pointer::*,
        interest_bearing_mint::*, memo_transfer::*, metadata_pointer::*, mint_close_authority::*,
        permanent_delegate::*, reallocate::*, transfer_fee::*, transfer_hook::*,
    },
    serde_json::{json, Map, Value},
    solana_account_decoder::parse_token::{token_amount_to_ui_amount, UiAccountState},
    solana_sdk::{
        instruction::{AccountMeta, CompiledInstruction, Instruction},
        message::AccountKeys,
    },
    spl_token_2022::{
        extension::ExtensionType,
        instruction::{AuthorityType, TokenInstruction},
        solana_program::{
            instruction::Instruction as SplTokenInstruction, program_option::COption,
            pubkey::Pubkey,
        },
    },
};

mod extension;

pub fn parse_token(
    instruction: &CompiledInstruction,
    account_keys: &AccountKeys,
) -> Result<ParsedInstructionEnum, ParseInstructionError> {
    let token_instruction = TokenInstruction::unpack(&instruction.data)
        .map_err(|_| ParseInstructionError::InstructionNotParsable(ParsableProgram::SplToken))?;
    match instruction.accounts.iter().max() {
        Some(index) if (*index as usize) < account_keys.len() => {}
        _ => {
            // Runtime should prevent this from ever happening
            return Err(ParseInstructionError::InstructionKeyMismatch(
                ParsableProgram::SplToken,
            ));
        }
    }
    match token_instruction {
        TokenInstruction::InitializeMint {
            decimals,
            mint_authority,
            freeze_authority,
        } => {
            check_num_token_accounts(&instruction.accounts, 2)?;
            let mut value = json!({
                "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                "decimals": decimals,
                "mintAuthority": mint_authority.to_string(),
                "rentSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let COption::Some(freeze_authority) = freeze_authority {
                map.insert(
                    "freezeAuthority".to_string(),
                    json!(freeze_authority.to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeMint".to_string(),
                info: value,
            })
        }
        TokenInstruction::InitializeMint2 {
            decimals,
            mint_authority,
            freeze_authority,
        } => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            let mut value = json!({
                "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                "decimals": decimals,
                "mintAuthority": mint_authority.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if let COption::Some(freeze_authority) = freeze_authority {
                map.insert(
                    "freezeAuthority".to_string(),
                    json!(freeze_authority.to_string()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeMint2".to_string(),
                info: value,
            })
        }
        TokenInstruction::InitializeAccount => {
            check_num_token_accounts(&instruction.accounts, 4)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeAccount".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                    "owner": account_keys[instruction.accounts[2] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[3] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::InitializeAccount2 { owner } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeAccount2".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                    "owner": owner.to_string(),
                    "rentSysvar": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::InitializeAccount3 { owner } => {
            check_num_token_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeAccount3".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                    "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                    "owner": owner.to_string(),
                }),
            })
        }
        TokenInstruction::InitializeMultisig { m } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut signers: Vec<String> = vec![];
            for i in instruction.accounts[2..].iter() {
                signers.push(account_keys[*i as usize].to_string());
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeMultisig".to_string(),
                info: json!({
                    "multisig": account_keys[instruction.accounts[0] as usize].to_string(),
                    "rentSysvar": account_keys[instruction.accounts[1] as usize].to_string(),
                    "signers": signers,
                    "m": m,
                }),
            })
        }
        TokenInstruction::InitializeMultisig2 { m } => {
            check_num_token_accounts(&instruction.accounts, 2)?;
            let mut signers: Vec<String> = vec![];
            for i in instruction.accounts[1..].iter() {
                signers.push(account_keys[*i as usize].to_string());
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeMultisig2".to_string(),
                info: json!({
                    "multisig": account_keys[instruction.accounts[0] as usize].to_string(),
                    "signers": signers,
                    "m": m,
                }),
            })
        }
        #[allow(deprecated)]
        TokenInstruction::Transfer { amount } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
                "destination": account_keys[instruction.accounts[1] as usize].to_string(),
                "amount": amount.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "transfer".to_string(),
                info: value,
            })
        }
        TokenInstruction::Approve { amount } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
                "delegate": account_keys[instruction.accounts[1] as usize].to_string(),
                "amount": amount.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "owner",
                "multisigOwner",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "approve".to_string(),
                info: value,
            })
        }
        TokenInstruction::Revoke => {
            check_num_token_accounts(&instruction.accounts, 2)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                1,
                account_keys,
                &instruction.accounts,
                "owner",
                "multisigOwner",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "revoke".to_string(),
                info: value,
            })
        }
        TokenInstruction::SetAuthority {
            authority_type,
            new_authority,
        } => {
            check_num_token_accounts(&instruction.accounts, 2)?;
            let owned = match authority_type {
                AuthorityType::MintTokens
                | AuthorityType::FreezeAccount
                | AuthorityType::TransferFeeConfig
                | AuthorityType::WithheldWithdraw
                | AuthorityType::CloseMint
                | AuthorityType::InterestRate
                | AuthorityType::PermanentDelegate
                | AuthorityType::ConfidentialTransferMint
                | AuthorityType::TransferHookProgramId
                | AuthorityType::ConfidentialTransferFeeConfig
                | AuthorityType::MetadataPointer
                | AuthorityType::GroupPointer
                | AuthorityType::GroupMemberPointer => "mint",
                AuthorityType::AccountOwner | AuthorityType::CloseAccount => "account",
            };
            let mut value = json!({
                owned: account_keys[instruction.accounts[0] as usize].to_string(),
                "authorityType": Into::<UiAuthorityType>::into(authority_type),
                "newAuthority": map_coption_pubkey(new_authority),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                1,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "setAuthority".to_string(),
                info: value,
            })
        }
        TokenInstruction::MintTo { amount } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                "account": account_keys[instruction.accounts[1] as usize].to_string(),
                "amount": amount.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "mintAuthority",
                "multisigMintAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "mintTo".to_string(),
                info: value,
            })
        }
        TokenInstruction::Burn { amount } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "account": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                "amount": amount.to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "burn".to_string(),
                info: value,
            })
        }
        TokenInstruction::CloseAccount => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "account": account_keys[instruction.accounts[0] as usize].to_string(),
                "destination": account_keys[instruction.accounts[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "owner",
                "multisigOwner",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "closeAccount".to_string(),
                info: value,
            })
        }
        TokenInstruction::FreezeAccount => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "account": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "freezeAuthority",
                "multisigFreezeAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "freezeAccount".to_string(),
                info: value,
            })
        }
        TokenInstruction::ThawAccount => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "account": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "freezeAuthority",
                "multisigFreezeAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "thawAccount".to_string(),
                info: value,
            })
        }
        TokenInstruction::TransferChecked { amount, decimals } => {
            check_num_token_accounts(&instruction.accounts, 4)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                "destination": account_keys[instruction.accounts[2] as usize].to_string(),
                "tokenAmount": token_amount_to_ui_amount(amount, decimals),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                3,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "transferChecked".to_string(),
                info: value,
            })
        }
        TokenInstruction::ApproveChecked { amount, decimals } => {
            check_num_token_accounts(&instruction.accounts, 4)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                "delegate": account_keys[instruction.accounts[2] as usize].to_string(),
                "tokenAmount": token_amount_to_ui_amount(amount, decimals),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                3,
                account_keys,
                &instruction.accounts,
                "owner",
                "multisigOwner",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "approveChecked".to_string(),
                info: value,
            })
        }
        TokenInstruction::MintToChecked { amount, decimals } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                "account": account_keys[instruction.accounts[1] as usize].to_string(),
                "tokenAmount": token_amount_to_ui_amount(amount, decimals),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "mintAuthority",
                "multisigMintAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "mintToChecked".to_string(),
                info: value,
            })
        }
        TokenInstruction::BurnChecked { amount, decimals } => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "account": account_keys[instruction.accounts[0] as usize].to_string(),
                "mint": account_keys[instruction.accounts[1] as usize].to_string(),
                "tokenAmount": token_amount_to_ui_amount(amount, decimals),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "burnChecked".to_string(),
                info: value,
            })
        }
        TokenInstruction::SyncNative => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "syncNative".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::GetAccountDataSize { extension_types } => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            let mut value = json!({
                "mint": account_keys[instruction.accounts[0] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            if !extension_types.is_empty() {
                map.insert(
                    "extensionTypes".to_string(),
                    json!(extension_types
                        .into_iter()
                        .map(UiExtensionType::from)
                        .collect::<Vec<_>>()),
                );
            }
            Ok(ParsedInstructionEnum {
                instruction_type: "getAccountDataSize".to_string(),
                info: value,
            })
        }
        TokenInstruction::InitializeImmutableOwner => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeImmutableOwner".to_string(),
                info: json!({
                    "account": account_keys[instruction.accounts[0] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::AmountToUiAmount { amount } => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "amountToUiAmount".to_string(),
                info: json!({
                    "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                    "amount": amount,
                }),
            })
        }
        TokenInstruction::UiAmountToAmount { ui_amount } => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "uiAmountToAmount".to_string(),
                info: json!({
                    "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                    "uiAmount": ui_amount,
                }),
            })
        }
        TokenInstruction::InitializeMintCloseAuthority { close_authority } => {
            parse_initialize_mint_close_authority_instruction(
                close_authority,
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::TransferFeeExtension(transfer_fee_instruction) => {
            parse_transfer_fee_instruction(
                transfer_fee_instruction,
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::ConfidentialTransferExtension => parse_confidential_transfer_instruction(
            &instruction.data[1..],
            &instruction.accounts,
            account_keys,
        ),
        TokenInstruction::DefaultAccountStateExtension => {
            if instruction.data.len() <= 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_default_account_state_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::Reallocate { extension_types } => {
            parse_reallocate_instruction(extension_types, &instruction.accounts, account_keys)
        }
        TokenInstruction::MemoTransferExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_memo_transfer_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::CreateNativeMint => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "createNativeMint".to_string(),
                info: json!({
                    "payer": account_keys[instruction.accounts[0] as usize].to_string(),
                    "nativeMint": account_keys[instruction.accounts[1] as usize].to_string(),
                    "systemProgram": account_keys[instruction.accounts[2] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::InitializeNonTransferableMint => {
            check_num_token_accounts(&instruction.accounts, 1)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "initializeNonTransferableMint".to_string(),
                info: json!({
                    "mint": account_keys[instruction.accounts[0] as usize].to_string(),
                }),
            })
        }
        TokenInstruction::InterestBearingMintExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_interest_bearing_mint_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::CpiGuardExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_cpi_guard_instruction(&instruction.data[1..], &instruction.accounts, account_keys)
        }
        TokenInstruction::InitializePermanentDelegate { delegate } => {
            parse_initialize_permanent_delegate_instruction(
                delegate,
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::TransferHookExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_transfer_hook_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::ConfidentialTransferFeeExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_confidential_transfer_fee_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::WithdrawExcessLamports => {
            check_num_token_accounts(&instruction.accounts, 3)?;
            let mut value = json!({
                "source": account_keys[instruction.accounts[0] as usize].to_string(),
                "destination": account_keys[instruction.accounts[1] as usize].to_string(),
            });
            let map = value.as_object_mut().unwrap();
            parse_signers(
                map,
                2,
                account_keys,
                &instruction.accounts,
                "authority",
                "multisigAuthority",
            );
            Ok(ParsedInstructionEnum {
                instruction_type: "withdrawExcessLamports".to_string(),
                info: value,
            })
        }
        TokenInstruction::MetadataPointerExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_metadata_pointer_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::GroupPointerExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_group_pointer_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
        TokenInstruction::GroupMemberPointerExtension => {
            if instruction.data.len() < 2 {
                return Err(ParseInstructionError::InstructionNotParsable(
                    ParsableProgram::SplToken,
                ));
            }
            parse_group_member_pointer_instruction(
                &instruction.data[1..],
                &instruction.accounts,
                account_keys,
            )
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UiAuthorityType {
    MintTokens,
    FreezeAccount,
    AccountOwner,
    CloseAccount,
    TransferFeeConfig,
    WithheldWithdraw,
    CloseMint,
    InterestRate,
    PermanentDelegate,
    ConfidentialTransferMint,
    TransferHookProgramId,
    ConfidentialTransferFeeConfig,
    MetadataPointer,
    GroupPointer,
    GroupMemberPointer,
}

impl From<AuthorityType> for UiAuthorityType {
    fn from(authority_type: AuthorityType) -> Self {
        match authority_type {
            AuthorityType::MintTokens => UiAuthorityType::MintTokens,
            AuthorityType::FreezeAccount => UiAuthorityType::FreezeAccount,
            AuthorityType::AccountOwner => UiAuthorityType::AccountOwner,
            AuthorityType::CloseAccount => UiAuthorityType::CloseAccount,
            AuthorityType::TransferFeeConfig => UiAuthorityType::TransferFeeConfig,
            AuthorityType::WithheldWithdraw => UiAuthorityType::WithheldWithdraw,
            AuthorityType::CloseMint => UiAuthorityType::CloseMint,
            AuthorityType::InterestRate => UiAuthorityType::InterestRate,
            AuthorityType::PermanentDelegate => UiAuthorityType::PermanentDelegate,
            AuthorityType::ConfidentialTransferMint => UiAuthorityType::ConfidentialTransferMint,
            AuthorityType::TransferHookProgramId => UiAuthorityType::TransferHookProgramId,
            AuthorityType::ConfidentialTransferFeeConfig => {
                UiAuthorityType::ConfidentialTransferFeeConfig
            }
            AuthorityType::MetadataPointer => UiAuthorityType::MetadataPointer,
            AuthorityType::GroupPointer => UiAuthorityType::GroupPointer,
            AuthorityType::GroupMemberPointer => UiAuthorityType::GroupMemberPointer,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UiExtensionType {
    Uninitialized,
    TransferFeeConfig,
    TransferFeeAmount,
    MintCloseAuthority,
    ConfidentialTransferMint,
    ConfidentialTransferAccount,
    DefaultAccountState,
    ImmutableOwner,
    MemoTransfer,
    NonTransferable,
    InterestBearingConfig,
    CpiGuard,
    PermanentDelegate,
    NonTransferableAccount,
    TransferHook,
    TransferHookAccount,
    ConfidentialTransferFeeConfig,
    ConfidentialTransferFeeAmount,
    MetadataPointer,
    TokenMetadata,
    GroupPointer,
    GroupMemberPointer,
    TokenGroup,
    TokenGroupMember,
}

impl From<ExtensionType> for UiExtensionType {
    fn from(extension_type: ExtensionType) -> Self {
        match extension_type {
            ExtensionType::Uninitialized => UiExtensionType::Uninitialized,
            ExtensionType::TransferFeeConfig => UiExtensionType::TransferFeeConfig,
            ExtensionType::TransferFeeAmount => UiExtensionType::TransferFeeAmount,
            ExtensionType::MintCloseAuthority => UiExtensionType::MintCloseAuthority,
            ExtensionType::ConfidentialTransferMint => UiExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferAccount => {
                UiExtensionType::ConfidentialTransferAccount
            }
            ExtensionType::DefaultAccountState => UiExtensionType::DefaultAccountState,
            ExtensionType::ImmutableOwner => UiExtensionType::ImmutableOwner,
            ExtensionType::MemoTransfer => UiExtensionType::MemoTransfer,
            ExtensionType::NonTransferable => UiExtensionType::NonTransferable,
            ExtensionType::InterestBearingConfig => UiExtensionType::InterestBearingConfig,
            ExtensionType::CpiGuard => UiExtensionType::CpiGuard,
            ExtensionType::PermanentDelegate => UiExtensionType::PermanentDelegate,
            ExtensionType::NonTransferableAccount => UiExtensionType::NonTransferableAccount,
            ExtensionType::TransferHook => UiExtensionType::TransferHook,
            ExtensionType::TransferHookAccount => UiExtensionType::TransferHookAccount,
            ExtensionType::ConfidentialTransferFeeConfig => {
                UiExtensionType::ConfidentialTransferFeeConfig
            }
            ExtensionType::ConfidentialTransferFeeAmount => {
                UiExtensionType::ConfidentialTransferFeeAmount
            }
            ExtensionType::MetadataPointer => UiExtensionType::MetadataPointer,
            ExtensionType::TokenMetadata => UiExtensionType::TokenMetadata,
            ExtensionType::GroupPointer => UiExtensionType::GroupPointer,
            ExtensionType::GroupMemberPointer => UiExtensionType::GroupMemberPointer,
            ExtensionType::TokenGroup => UiExtensionType::TokenGroup,
            ExtensionType::TokenGroupMember => UiExtensionType::TokenGroupMember,
        }
    }
}

fn parse_signers(
    map: &mut Map<String, Value>,
    last_nonsigner_index: usize,
    account_keys: &AccountKeys,
    accounts: &[u8],
    owner_field_name: &str,
    multisig_field_name: &str,
) {
    if accounts.len() > last_nonsigner_index + 1 {
        let mut signers: Vec<String> = vec![];
        for i in accounts[last_nonsigner_index + 1..].iter() {
            signers.push(account_keys[*i as usize].to_string());
        }
        map.insert(
            multisig_field_name.to_string(),
            json!(account_keys[accounts[last_nonsigner_index] as usize].to_string()),
        );
        map.insert("signers".to_string(), json!(signers));
    } else {
        map.insert(
            owner_field_name.to_string(),
            json!(account_keys[accounts[last_nonsigner_index] as usize].to_string()),
        );
    }
}

fn check_num_token_accounts(accounts: &[u8], num: usize) -> Result<(), ParseInstructionError> {
    check_num_accounts(accounts, num, ParsableProgram::SplToken)
}

#[deprecated(since = "1.16.0", note = "Instruction conversions no longer needed")]
pub fn spl_token_instruction(instruction: SplTokenInstruction) -> Instruction {
    Instruction {
        program_id: instruction.program_id,
        accounts: instruction
            .accounts
            .iter()
            .map(|meta| AccountMeta {
                pubkey: meta.pubkey,
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data: instruction.data,
    }
}

fn map_coption_pubkey(pubkey: COption<Pubkey>) -> Option<String> {
    match pubkey {
        COption::Some(pubkey) => Some(pubkey.to_string()),
        COption::None => None,
    }
}
