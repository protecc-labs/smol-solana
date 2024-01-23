use {
    crate::parse_account_data::{ParsableAccount, ParseAccountError},
    solana_sdk::{address_lookup_table::state::AddressLookupTable, instruction::InstructionError},
};

pub fn parse_address_lookup_table(
    data: &[u8],
) -> Result<LookupTableAccountType, ParseAccountError> {
    AddressLookupTable::deserialize(data)
        .map(|address_lookup_table| {
            LookupTableAccountType::LookupTable(address_lookup_table.into())
        })
        .or_else(|err| match err {
            InstructionError::UninitializedAccount => Ok(LookupTableAccountType::Uninitialized),
            _ => Err(ParseAccountError::AccountNotParsable(
                ParsableAccount::AddressLookupTable,
            )),
        })
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
pub enum LookupTableAccountType {
    Uninitialized,
    LookupTable(UiLookupTable),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiLookupTable {
    pub deactivation_slot: String,
    pub last_extended_slot: String,
    pub last_extended_slot_start_index: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    pub addresses: Vec<String>,
}

impl<'a> From<AddressLookupTable<'a>> for UiLookupTable {
    fn from(address_lookup_table: AddressLookupTable) -> Self {
        Self {
            deactivation_slot: address_lookup_table.meta.deactivation_slot.to_string(),
            last_extended_slot: address_lookup_table.meta.last_extended_slot.to_string(),
            last_extended_slot_start_index: address_lookup_table
                .meta
                .last_extended_slot_start_index,
            authority: address_lookup_table
                .meta
                .authority
                .map(|authority| authority.to_string()),
            addresses: address_lookup_table
                .addresses
                .iter()
                .map(|address| address.to_string())
                .collect(),
        }
    }
}
