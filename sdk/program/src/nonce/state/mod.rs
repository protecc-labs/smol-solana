//! State for durable transaction nonces.

mod current;
pub use current::{Data, DurableNonce, State};
use {
    crate::{hash::Hash, pubkey::Pubkey},
    serde_derive::{Deserialize, Serialize},
    std::collections::HashSet,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum Versions {
    Legacy(Box<State>),
    /// Current variants have durable nonce and blockhash domains separated.
    Current(Box<State>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthorizeNonceError {
    MissingRequiredSignature(/*account authority:*/ Pubkey),
    Uninitialized,
}

impl Versions {
    pub fn new(state: State) -> Self {
        Self::Current(Box::new(state))
    }

    pub fn state(&self) -> &State {
        match self {
            Self::Legacy(state) => state,
            Self::Current(state) => state,
        }
    }

    /// Checks if the recent_blockhash field in Transaction verifies, and
    /// returns nonce account data if so.
    pub fn verify_recent_blockhash(
        &self,
        recent_blockhash: &Hash, // Transaction.message.recent_blockhash
    ) -> Option<&Data> {
        match self {
            // Legacy durable nonces are invalid and should not
            // allow durable transactions.
            Self::Legacy(_) => None,
            Self::Current(state) => match **state {
                State::Uninitialized => None,
                State::Initialized(ref data) => {
                    (recent_blockhash == &data.blockhash()).then_some(data)
                }
            },
        }
    }

    /// Upgrades legacy nonces out of chain blockhash domains.
    pub fn upgrade(self) -> Option<Self> {
        match self {
            Self::Legacy(mut state) => {
                match *state {
                    // An Uninitialized legacy nonce cannot verify a durable
                    // transaction. The nonce will be upgraded to Current
                    // version when initialized. Therefore there is no need to
                    // upgrade Uninitialized legacy nonces.
                    State::Uninitialized => None,
                    State::Initialized(ref mut data) => {
                        data.durable_nonce = DurableNonce::from_blockhash(&data.blockhash());
                        Some(Self::Current(state))
                    }
                }
            }
            Self::Current(_) => None,
        }
    }

    /// Updates the authority pubkey on the nonce account.
    pub fn authorize(
        self,
        signers: &HashSet<Pubkey>,
        authority: Pubkey,
    ) -> Result<Self, AuthorizeNonceError> {
        let data = match self.state() {
            State::Uninitialized => return Err(AuthorizeNonceError::Uninitialized),
            State::Initialized(data) => data,
        };
        if !signers.contains(&data.authority) {
            return Err(AuthorizeNonceError::MissingRequiredSignature(
                data.authority,
            ));
        }
        let data = Data::new(
            authority,
            data.durable_nonce,
            data.get_lamports_per_signature(),
        );
        let state = Box::new(State::Initialized(data));
        // Preserve Version variant since cannot
        // change durable_nonce field here.
        Ok(match self {
            Self::Legacy(_) => Self::Legacy,
            Self::Current(_) => Self::Current,
        }(state))
    }
}

impl From<Versions> for State {
    fn from(versions: Versions) -> Self {
        match versions {
            Versions::Legacy(state) => *state,
            Versions::Current(state) => *state,
        }
    }
}
