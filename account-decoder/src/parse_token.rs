use {
    crate::{
        parse_account_data::{ParsableAccount, ParseAccountError},
        parse_token_extension::{parse_extension, UiExtension},
        StringAmount, StringDecimals,
    },
    solana_sdk::pubkey::Pubkey,
    spl_token_2022::{
        extension::{BaseStateWithExtensions, StateWithExtensions},
        generic_token_account::GenericTokenAccount,
        solana_program::{
            program_option::COption, program_pack::Pack, pubkey::Pubkey as SplTokenPubkey,
        },
        state::{Account, AccountState, Mint, Multisig},
    },
    std::str::FromStr,
};

// Returns all known SPL Token program ids
pub fn spl_token_ids() -> Vec<Pubkey> {
    vec![spl_token::id(), spl_token_2022::id()]
}

// Check if the provided program id as a known SPL Token program id
pub fn is_known_spl_token_id(program_id: &Pubkey) -> bool {
    *program_id == spl_token::id() || *program_id == spl_token_2022::id()
}

// A helper function to convert spl_token::native_mint::id() as spl_sdk::pubkey::Pubkey to
// solana_sdk::pubkey::Pubkey
#[deprecated(
    since = "1.16.0",
    note = "Pubkey conversions no longer needed. Please use spl_token::native_mint::id() directly"
)]
pub fn spl_token_native_mint() -> Pubkey {
    Pubkey::new_from_array(spl_token::native_mint::id().to_bytes())
}

// The program id of the `spl_token_native_mint` account
#[deprecated(
    since = "1.16.0",
    note = "Pubkey conversions no longer needed. Please use spl_token::id() directly"
)]
pub fn spl_token_native_mint_program_id() -> Pubkey {
    spl_token::id()
}

// A helper function to convert a solana_sdk::pubkey::Pubkey to spl_sdk::pubkey::Pubkey
#[deprecated(since = "1.16.0", note = "Pubkey conversions no longer needed")]
pub fn spl_token_pubkey(pubkey: &Pubkey) -> SplTokenPubkey {
    SplTokenPubkey::new_from_array(pubkey.to_bytes())
}

// A helper function to convert a spl_sdk::pubkey::Pubkey to solana_sdk::pubkey::Pubkey
#[deprecated(since = "1.16.0", note = "Pubkey conversions no longer needed")]
pub fn pubkey_from_spl_token(pubkey: &SplTokenPubkey) -> Pubkey {
    Pubkey::new_from_array(pubkey.to_bytes())
}

pub fn parse_token(
    data: &[u8],
    mint_decimals: Option<u8>,
) -> Result<TokenAccountType, ParseAccountError> {
    if let Ok(account) = StateWithExtensions::<Account>::unpack(data) {
        let decimals = mint_decimals.ok_or_else(|| {
            ParseAccountError::AdditionalDataMissing(
                "no mint_decimals provided to parse spl-token account".to_string(),
            )
        })?;
        let extension_types = account.get_extension_types().unwrap_or_default();
        let ui_extensions = extension_types
            .iter()
            .map(|extension_type| parse_extension::<Account>(extension_type, &account))
            .collect();
        return Ok(TokenAccountType::Account(UiTokenAccount {
            mint: account.base.mint.to_string(),
            owner: account.base.owner.to_string(),
            token_amount: token_amount_to_ui_amount(account.base.amount, decimals),
            delegate: match account.base.delegate {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            state: account.base.state.into(),
            is_native: account.base.is_native(),
            rent_exempt_reserve: match account.base.is_native {
                COption::Some(reserve) => Some(token_amount_to_ui_amount(reserve, decimals)),
                COption::None => None,
            },
            delegated_amount: if account.base.delegate.is_none() {
                None
            } else {
                Some(token_amount_to_ui_amount(
                    account.base.delegated_amount,
                    decimals,
                ))
            },
            close_authority: match account.base.close_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            extensions: ui_extensions,
        }));
    }
    if let Ok(mint) = StateWithExtensions::<Mint>::unpack(data) {
        let extension_types = mint.get_extension_types().unwrap_or_default();
        let ui_extensions = extension_types
            .iter()
            .map(|extension_type| parse_extension::<Mint>(extension_type, &mint))
            .collect();
        return Ok(TokenAccountType::Mint(UiMint {
            mint_authority: match mint.base.mint_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            supply: mint.base.supply.to_string(),
            decimals: mint.base.decimals,
            is_initialized: mint.base.is_initialized,
            freeze_authority: match mint.base.freeze_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            extensions: ui_extensions,
        }));
    }
    if data.len() == Multisig::get_packed_len() {
        let multisig = Multisig::unpack(data)
            .map_err(|_| ParseAccountError::AccountNotParsable(ParsableAccount::SplToken))?;
        Ok(TokenAccountType::Multisig(UiMultisig {
            num_required_signers: multisig.m,
            num_valid_signers: multisig.n,
            is_initialized: multisig.is_initialized,
            signers: multisig
                .signers
                .iter()
                .filter_map(|pubkey| {
                    if pubkey != &SplTokenPubkey::default() {
                        Some(pubkey.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
        }))
    } else {
        Err(ParseAccountError::AccountNotParsable(
            ParsableAccount::SplToken,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
#[allow(clippy::large_enum_variant)]
pub enum TokenAccountType {
    Account(UiTokenAccount),
    Mint(UiMint),
    Multisig(UiMultisig),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiTokenAccount {
    pub mint: String,
    pub owner: String,
    pub token_amount: UiTokenAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegate: Option<String>,
    pub state: UiAccountState,
    pub is_native: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rent_exempt_reserve: Option<UiTokenAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_amount: Option<UiTokenAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_authority: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<UiExtension>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UiAccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

impl From<AccountState> for UiAccountState {
    fn from(state: AccountState) -> Self {
        match state {
            AccountState::Uninitialized => UiAccountState::Uninitialized,
            AccountState::Initialized => UiAccountState::Initialized,
            AccountState::Frozen => UiAccountState::Frozen,
        }
    }
}

pub fn real_number_string(amount: u64, decimals: u8) -> StringDecimals {
    let decimals = decimals as usize;
    if decimals > 0 {
        // Left-pad zeros to decimals + 1, so we at least have an integer zero
        let mut s = format!("{:01$}", amount, decimals + 1);
        // Add the decimal point (Sorry, "," locales!)
        s.insert(s.len() - decimals, '.');
        s
    } else {
        amount.to_string()
    }
}

pub fn real_number_string_trimmed(amount: u64, decimals: u8) -> StringDecimals {
    let mut s = real_number_string(amount, decimals);
    if decimals > 0 {
        let zeros_trimmed = s.trim_end_matches('0');
        s = zeros_trimmed.trim_end_matches('.').to_string();
    }
    s
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiTokenAmount {
    pub ui_amount: Option<f64>,
    pub decimals: u8,
    pub amount: StringAmount,
    pub ui_amount_string: StringDecimals,
}

impl UiTokenAmount {
    pub fn real_number_string(&self) -> String {
        real_number_string(
            u64::from_str(&self.amount).unwrap_or_default(),
            self.decimals,
        )
    }

    pub fn real_number_string_trimmed(&self) -> String {
        if !self.ui_amount_string.is_empty() {
            self.ui_amount_string.clone()
        } else {
            real_number_string_trimmed(
                u64::from_str(&self.amount).unwrap_or_default(),
                self.decimals,
            )
        }
    }
}

pub fn token_amount_to_ui_amount(amount: u64, decimals: u8) -> UiTokenAmount {
    let amount_decimals = 10_usize
        .checked_pow(decimals as u32)
        .map(|dividend| amount as f64 / dividend as f64);
    UiTokenAmount {
        ui_amount: amount_decimals,
        decimals,
        amount: amount.to_string(),
        ui_amount_string: real_number_string_trimmed(amount, decimals),
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiMint {
    pub mint_authority: Option<String>,
    pub supply: StringAmount,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<UiExtension>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiMultisig {
    pub num_required_signers: u8,
    pub num_valid_signers: u8,
    pub is_initialized: bool,
    pub signers: Vec<String>,
}

pub fn get_token_account_mint(data: &[u8]) -> Option<Pubkey> {
    Account::valid_account_data(data)
        .then(|| Pubkey::try_from(data.get(..32)?).ok())
        .flatten()
}
