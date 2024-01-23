use {
    itertools::Itertools,
    serde::ser::{Serialize, Serializer},
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount},
        instruction::InstructionError,
        pubkey::Pubkey,
    },
    solana_vote_program::vote_state::VoteState,
    std::{
        cmp::Ordering,
        collections::{hash_map::Entry, HashMap},
        iter::FromIterator,
        sync::{Arc, OnceLock},
    },
    thiserror::Error,
};

#[derive(Clone, Debug, PartialEq, AbiExample, Deserialize)]
#[serde(try_from = "AccountSharedData")]
pub struct VoteAccount(Arc<VoteAccountInner>);

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    InstructionError(#[from] InstructionError),
    #[error("Invalid vote account owner: {0}")]
    InvalidOwner(/*owner:*/ Pubkey),
}

#[derive(Debug, AbiExample)]
struct VoteAccountInner {
    account: AccountSharedData,
    vote_state: OnceLock<Result<VoteState, Error>>,
}

pub type VoteAccountsHashMap = HashMap<Pubkey, (/*stake:*/ u64, VoteAccount)>;

#[derive(Clone, Debug, Deserialize, AbiExample)]
#[serde(from = "Arc<VoteAccountsHashMap>")]
pub struct VoteAccounts {
    vote_accounts: Arc<VoteAccountsHashMap>,
    // Inner Arc is meant to implement copy-on-write semantics.
    staked_nodes: OnceLock<
        Arc<
            HashMap<
                Pubkey, // VoteAccount.vote_state.node_pubkey.
                u64,    // Total stake across all vote-accounts.
            >,
        >,
    >,
}

impl VoteAccount {
    pub fn account(&self) -> &AccountSharedData {
        &self.0.account
    }

    pub fn lamports(&self) -> u64 {
        self.0.account.lamports()
    }

    pub fn owner(&self) -> &Pubkey {
        self.0.account.owner()
    }

    pub fn vote_state(&self) -> Result<&VoteState, &Error> {
        // VoteState::deserialize deserializes a VoteStateVersions and then
        // calls VoteStateVersions::convert_to_current.
        self.0
            .vote_state
            .get_or_init(|| VoteState::deserialize(self.0.account.data()).map_err(Error::from))
            .as_ref()
    }

    pub fn is_deserialized(&self) -> bool {
        self.0.vote_state.get().is_some()
    }

    /// VoteState.node_pubkey of this vote-account.
    pub fn node_pubkey(&self) -> Option<Pubkey> {
        Some(self.vote_state().ok()?.node_pubkey)
    }
}

impl VoteAccounts {
    pub fn len(&self) -> usize {
        self.vote_accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vote_accounts.is_empty()
    }

    pub fn staked_nodes(&self) -> Arc<HashMap</*node_pubkey:*/ Pubkey, /*stake:*/ u64>> {
        self.staked_nodes
            .get_or_init(|| {
                Arc::new(
                    self.vote_accounts
                        .values()
                        .filter(|(stake, _)| *stake != 0u64)
                        .filter_map(|(stake, vote_account)| {
                            Some((vote_account.node_pubkey()?, stake))
                        })
                        .into_grouping_map()
                        .aggregate(|acc, _node_pubkey, stake| {
                            Some(acc.unwrap_or_default() + stake)
                        }),
                )
            })
            .clone()
    }

    pub fn get(&self, pubkey: &Pubkey) -> Option<&VoteAccount> {
        let (_stake, vote_account) = self.vote_accounts.get(pubkey)?;
        Some(vote_account)
    }

    pub fn get_delegated_stake(&self, pubkey: &Pubkey) -> u64 {
        self.vote_accounts
            .get(pubkey)
            .map(|(stake, _vote_account)| *stake)
            .unwrap_or_default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Pubkey, &VoteAccount)> {
        self.vote_accounts
            .iter()
            .map(|(vote_pubkey, (_stake, vote_account))| (vote_pubkey, vote_account))
    }

    pub fn delegated_stakes(&self) -> impl Iterator<Item = (&Pubkey, u64)> {
        self.vote_accounts
            .iter()
            .map(|(vote_pubkey, (stake, _vote_account))| (vote_pubkey, *stake))
    }

    pub fn find_max_by_delegated_stake(&self) -> Option<&VoteAccount> {
        let key = |(_pubkey, (stake, _vote_account)): &(_, &(u64, _))| *stake;
        let (_pubkey, (_stake, vote_account)) = self.vote_accounts.iter().max_by_key(key)?;
        Some(vote_account)
    }

    pub fn insert(&mut self, pubkey: Pubkey, (stake, vote_account): (u64, VoteAccount)) {
        self.add_node_stake(stake, &vote_account);
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        if let Some((stake, vote_account)) = vote_accounts.insert(pubkey, (stake, vote_account)) {
            self.sub_node_stake(stake, &vote_account);
        }
    }

    pub fn remove(&mut self, pubkey: &Pubkey) -> Option<(u64, VoteAccount)> {
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        let entry = vote_accounts.remove(pubkey);
        if let Some((stake, ref vote_account)) = entry {
            self.sub_node_stake(stake, vote_account);
        }
        entry
    }

    pub fn add_stake(&mut self, pubkey: &Pubkey, delta: u64) {
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        if let Some((stake, vote_account)) = vote_accounts.get_mut(pubkey) {
            *stake += delta;
            let vote_account = vote_account.clone();
            self.add_node_stake(delta, &vote_account);
        }
    }

    pub fn sub_stake(&mut self, pubkey: &Pubkey, delta: u64) {
        let vote_accounts = Arc::make_mut(&mut self.vote_accounts);
        if let Some((stake, vote_account)) = vote_accounts.get_mut(pubkey) {
            *stake = stake
                .checked_sub(delta)
                .expect("subtraction value exceeds account's stake");
            let vote_account = vote_account.clone();
            self.sub_node_stake(delta, &vote_account);
        }
    }

    fn add_node_stake(&mut self, stake: u64, vote_account: &VoteAccount) {
        if stake == 0u64 {
            return;
        }
        let Some(staked_nodes) = self.staked_nodes.get_mut() else {
            return;
        };
        if let Some(node_pubkey) = vote_account.node_pubkey() {
            Arc::make_mut(staked_nodes)
                .entry(node_pubkey)
                .and_modify(|s| *s += stake)
                .or_insert(stake);
        }
    }

    fn sub_node_stake(&mut self, stake: u64, vote_account: &VoteAccount) {
        if stake == 0u64 {
            return;
        }
        let Some(staked_nodes) = self.staked_nodes.get_mut() else {
            return;
        };
        if let Some(node_pubkey) = vote_account.node_pubkey() {
            let Entry::Occupied(mut entry) = Arc::make_mut(staked_nodes).entry(node_pubkey) else {
                panic!("this should not happen!");
            };
            match entry.get().cmp(&stake) {
                Ordering::Less => panic!("subtraction value exceeds node's stake"),
                Ordering::Equal => {
                    entry.remove_entry();
                }
                Ordering::Greater => *entry.get_mut() -= stake,
            }
        }
    }
}

impl Serialize for VoteAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.account.serialize(serializer)
    }
}

impl From<VoteAccount> for AccountSharedData {
    fn from(account: VoteAccount) -> Self {
        account.0.account.clone()
    }
}

impl TryFrom<AccountSharedData> for VoteAccount {
    type Error = Error;
    fn try_from(account: AccountSharedData) -> Result<Self, Self::Error> {
        let vote_account = VoteAccountInner::try_from(account)?;
        Ok(Self(Arc::new(vote_account)))
    }
}

impl TryFrom<AccountSharedData> for VoteAccountInner {
    type Error = Error;
    fn try_from(account: AccountSharedData) -> Result<Self, Self::Error> {
        if !solana_vote_program::check_id(account.owner()) {
            return Err(Error::InvalidOwner(*account.owner()));
        }
        Ok(Self {
            account,
            vote_state: OnceLock::new(),
        })
    }
}

impl PartialEq<VoteAccountInner> for VoteAccountInner {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            account,
            vote_state: _,
        } = self;
        account == &other.account
    }
}

impl Default for VoteAccounts {
    fn default() -> Self {
        Self {
            vote_accounts: Arc::default(),
            staked_nodes: OnceLock::new(),
        }
    }
}

impl PartialEq<VoteAccounts> for VoteAccounts {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            vote_accounts,
            staked_nodes: _,
        } = self;
        vote_accounts == &other.vote_accounts
    }
}

impl From<Arc<VoteAccountsHashMap>> for VoteAccounts {
    fn from(vote_accounts: Arc<VoteAccountsHashMap>) -> Self {
        Self {
            vote_accounts,
            staked_nodes: OnceLock::new(),
        }
    }
}

impl AsRef<VoteAccountsHashMap> for VoteAccounts {
    fn as_ref(&self) -> &VoteAccountsHashMap {
        &self.vote_accounts
    }
}

impl From<&VoteAccounts> for Arc<VoteAccountsHashMap> {
    fn from(vote_accounts: &VoteAccounts) -> Self {
        Arc::clone(&vote_accounts.vote_accounts)
    }
}

impl FromIterator<(Pubkey, (/*stake:*/ u64, VoteAccount))> for VoteAccounts {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (Pubkey, (u64, VoteAccount))>,
    {
        Self::from(Arc::new(HashMap::from_iter(iter)))
    }
}

impl Serialize for VoteAccounts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.vote_accounts.serialize(serializer)
    }
}
