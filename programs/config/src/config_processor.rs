//! Config program

use {
    crate::ConfigKeys,
    bincode::deserialize,
    solana_program_runtime::{declare_process_instruction, ic_msg},
    solana_sdk::{
        instruction::InstructionError, program_utils::limited_deserialize, pubkey::Pubkey,
        transaction_context::IndexOfAccount,
    },
    std::collections::BTreeSet,
};

pub const DEFAULT_COMPUTE_UNITS: u64 = 450;

declare_process_instruction!(Entrypoint, DEFAULT_COMPUTE_UNITS, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let data = instruction_context.get_instruction_data();

    let key_list: ConfigKeys = limited_deserialize(data)?;
    let config_account_key = transaction_context.get_key_of_account_at_index(
        instruction_context.get_index_of_instruction_account_in_transaction(0)?,
    )?;
    let config_account =
        instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let is_config_account_signer = config_account.is_signer();
    let current_data: ConfigKeys = {
        if config_account.get_owner() != &crate::id() {
            return Err(InstructionError::InvalidAccountOwner);
        }

        deserialize(config_account.get_data()).map_err(|err| {
            ic_msg!(
                invoke_context,
                "Unable to deserialize config account: {}",
                err
            );
            InstructionError::InvalidAccountData
        })?
    };
    drop(config_account);

    let current_signer_keys: Vec<Pubkey> = current_data
        .keys
        .iter()
        .filter(|(_, is_signer)| *is_signer)
        .map(|(pubkey, _)| *pubkey)
        .collect();
    if current_signer_keys.is_empty() {
        // Config account keypair must be a signer on account initialization,
        // or when no signers specified in Config data
        if !is_config_account_signer {
            return Err(InstructionError::MissingRequiredSignature);
        }
    }

    let mut counter = 0;
    for (signer, _) in key_list.keys.iter().filter(|(_, is_signer)| *is_signer) {
        counter += 1;
        if signer != config_account_key {
            let signer_account = instruction_context
                .try_borrow_instruction_account(transaction_context, counter as IndexOfAccount)
                .map_err(|_| {
                    ic_msg!(
                        invoke_context,
                        "account {:?} is not in account list",
                        signer,
                    );
                    InstructionError::MissingRequiredSignature
                })?;
            if !signer_account.is_signer() {
                ic_msg!(
                    invoke_context,
                    "account {:?} signer_key().is_none()",
                    signer
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
            if signer_account.get_key() != signer {
                ic_msg!(
                    invoke_context,
                    "account[{:?}].signer_key() does not match Config data)",
                    counter + 1
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
            // If Config account is already initialized, update signatures must match Config data
            if !current_data.keys.is_empty()
                && !current_signer_keys.iter().any(|pubkey| pubkey == signer)
            {
                ic_msg!(
                    invoke_context,
                    "account {:?} is not in stored signer list",
                    signer
                );
                return Err(InstructionError::MissingRequiredSignature);
            }
        } else if !is_config_account_signer {
            ic_msg!(invoke_context, "account[0].signer_key().is_none()");
            return Err(InstructionError::MissingRequiredSignature);
        }
    }

    // dedupe signers
    let total_new_keys = key_list.keys.len();
    let unique_new_keys = key_list.keys.into_iter().collect::<BTreeSet<_>>();
    if unique_new_keys.len() != total_new_keys {
        ic_msg!(invoke_context, "new config contains duplicate keys");
        return Err(InstructionError::InvalidArgument);
    }

    // Check for Config data signers not present in incoming account update
    if current_signer_keys.len() > counter {
        ic_msg!(
            invoke_context,
            "too few signers: {:?}; expected: {:?}",
            counter,
            current_signer_keys.len()
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    let mut config_account =
        instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    if config_account.get_data().len() < data.len() {
        ic_msg!(invoke_context, "instruction data too large");
        return Err(InstructionError::InvalidInstructionData);
    }
    config_account.get_data_mut(&invoke_context.feature_set)?[..data.len()].copy_from_slice(data);
    Ok(())
});
