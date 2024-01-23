//! Runtime features.
//!
//! Runtime features provide a mechanism for features to be simultaneously activated across the
//! network. Since validators may choose when to upgrade, features must remain dormant until a
//! sufficient majority of the network is running a version that would support a given feature.
//!
//! Feature activation is accomplished by:
//! 1. Activation is requested by the feature authority, who issues a transaction to create the
//!    feature account. The newly created feature account will have the value of
//!    `Feature::default()`
//! 2. When the next epoch is entered the runtime will check for new activation requests and
//!    active them.  When this occurs, the activation slot is recorded in the feature account

use crate::{
    account_info::AccountInfo, clock::Slot, instruction::Instruction, program_error::ProgramError,
    pubkey::Pubkey, rent::Rent, system_instruction,
};

crate::declare_id!("Feature111111111111111111111111111111111111");

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Feature {
    pub activated_at: Option<Slot>,
}

impl Feature {
    pub const fn size_of() -> usize {
        9 // see test_feature_size_of.
    }

    pub fn from_account_info(account_info: &AccountInfo) -> Result<Self, ProgramError> {
        if *account_info.owner != id() {
            return Err(ProgramError::InvalidAccountOwner);
        }
        bincode::deserialize(&account_info.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)
    }
}

/// Activate a feature
pub fn activate(feature_id: &Pubkey, funding_address: &Pubkey, rent: &Rent) -> Vec<Instruction> {
    activate_with_lamports(
        feature_id,
        funding_address,
        rent.minimum_balance(Feature::size_of()),
    )
}

pub fn activate_with_lamports(
    feature_id: &Pubkey,
    funding_address: &Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    vec![
        system_instruction::transfer(funding_address, feature_id, lamports),
        system_instruction::allocate(feature_id, Feature::size_of() as u64),
        system_instruction::assign(feature_id, &id()),
    ]
}
