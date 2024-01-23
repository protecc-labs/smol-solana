use {
    clap::ArgMatches,
    solana_clap_utils::{
        input_parsers::{pubkey_of, value_of},
        nonce::*,
        offline::*,
    },
    solana_rpc_client::rpc_client::RpcClient,
    solana_sdk::{
        commitment_config::CommitmentConfig, fee_calculator::FeeCalculator, hash::Hash,
        pubkey::Pubkey,
    },
};

#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Cluster,
    NonceAccount(Pubkey),
}

impl Source {
    #[deprecated(since = "1.9.0", note = "Please use `get_blockhash` instead")]
    pub fn get_blockhash_and_fee_calculator(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<(Hash, FeeCalculator), Box<dyn std::error::Error>> {
        match self {
            Self::Cluster => {
                #[allow(deprecated)]
                let res = rpc_client
                    .get_recent_blockhash_with_commitment(commitment)?
                    .value;
                Ok((res.0, res.1))
            }
            Self::NonceAccount(ref pubkey) => {
                #[allow(clippy::redundant_closure)]
                let data = crate::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .and_then(|ref a| crate::data_from_account(a))?;
                Ok((data.blockhash(), data.fee_calculator))
            }
        }
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    pub fn get_fee_calculator(
        &self,
        rpc_client: &RpcClient,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> Result<Option<FeeCalculator>, Box<dyn std::error::Error>> {
        match self {
            Self::Cluster => {
                #[allow(deprecated)]
                let res = rpc_client
                    .get_fee_calculator_for_blockhash_with_commitment(blockhash, commitment)?
                    .value;
                Ok(res)
            }
            Self::NonceAccount(ref pubkey) => {
                let res = crate::get_account_with_commitment(rpc_client, pubkey, commitment)?;
                let res = crate::data_from_account(&res)?;
                Ok(Some(res)
                    .filter(|d| d.blockhash() == *blockhash)
                    .map(|d| d.fee_calculator))
            }
        }
    }

    pub fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            Self::Cluster => {
                let (blockhash, _) = rpc_client.get_latest_blockhash_with_commitment(commitment)?;
                Ok(blockhash)
            }
            Self::NonceAccount(ref pubkey) => {
                #[allow(clippy::redundant_closure)]
                let data = crate::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .and_then(|ref a| crate::data_from_account(a))?;
                Ok(data.blockhash())
            }
        }
    }

    pub fn is_blockhash_valid(
        &self,
        rpc_client: &RpcClient,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::Cluster => rpc_client.is_blockhash_valid(blockhash, commitment)?,
            Self::NonceAccount(ref pubkey) => {
                #[allow(clippy::redundant_closure)]
                let _ = crate::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .and_then(|ref a| crate::data_from_account(a))?;
                true
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockhashQuery {
    None(Hash),
    FeeCalculator(Source, Hash),
    All(Source),
}

impl BlockhashQuery {
    pub fn new(blockhash: Option<Hash>, sign_only: bool, nonce_account: Option<Pubkey>) -> Self {
        let source = nonce_account
            .map(Source::NonceAccount)
            .unwrap_or(Source::Cluster);
        match blockhash {
            Some(hash) if sign_only => Self::None(hash),
            Some(hash) if !sign_only => Self::FeeCalculator(source, hash),
            None if !sign_only => Self::All(source),
            _ => panic!("Cannot resolve blockhash"),
        }
    }

    pub fn new_from_matches(matches: &ArgMatches<'_>) -> Self {
        let blockhash = value_of(matches, BLOCKHASH_ARG.name);
        let sign_only = matches.is_present(SIGN_ONLY_ARG.name);
        let nonce_account = pubkey_of(matches, NONCE_ARG.name);
        BlockhashQuery::new(blockhash, sign_only, nonce_account)
    }

    #[deprecated(since = "1.9.0", note = "Please use `get_blockhash` instead")]
    pub fn get_blockhash_and_fee_calculator(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<(Hash, FeeCalculator), Box<dyn std::error::Error>> {
        match self {
            BlockhashQuery::None(hash) => Ok((*hash, FeeCalculator::default())),
            BlockhashQuery::FeeCalculator(source, hash) => {
                #[allow(deprecated)]
                let fee_calculator = source
                    .get_fee_calculator(rpc_client, hash, commitment)?
                    .ok_or(format!("Hash has expired {hash:?}"))?;
                Ok((*hash, fee_calculator))
            }
            BlockhashQuery::All(source) =>
            {
                #[allow(deprecated)]
                source.get_blockhash_and_fee_calculator(rpc_client, commitment)
            }
        }
    }

    pub fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            BlockhashQuery::None(hash) => Ok(*hash),
            BlockhashQuery::FeeCalculator(source, hash) => {
                if !source.is_blockhash_valid(rpc_client, hash, commitment)? {
                    return Err(format!("Hash has expired {hash:?}").into());
                }
                Ok(*hash)
            }
            BlockhashQuery::All(source) => source.get_blockhash(rpc_client, commitment),
        }
    }
}

impl Default for BlockhashQuery {
    fn default() -> Self {
        BlockhashQuery::All(Source::Cluster)
    }
}
