use {
    crate::nonblocking,
    clap::ArgMatches,
    solana_clap_utils::{
        input_parsers::{pubkey_of, value_of},
        nonce::*,
        offline::*,
    },
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_sdk::{commitment_config::CommitmentConfig, hash::Hash, pubkey::Pubkey},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Cluster,
    NonceAccount(Pubkey),
}

impl Source {
    pub async fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            Self::Cluster => {
                let (blockhash, _) = rpc_client
                    .get_latest_blockhash_with_commitment(commitment)
                    .await?;
                Ok(blockhash)
            }
            Self::NonceAccount(ref pubkey) => {
                #[allow(clippy::redundant_closure)]
                let data = nonblocking::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .await
                    .and_then(|ref a| nonblocking::data_from_account(a))?;
                Ok(data.blockhash())
            }
        }
    }

    pub async fn is_blockhash_valid(
        &self,
        rpc_client: &RpcClient,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::Cluster => rpc_client.is_blockhash_valid(blockhash, commitment).await?,
            Self::NonceAccount(ref pubkey) => {
                #[allow(clippy::redundant_closure)]
                let _ = nonblocking::get_account_with_commitment(rpc_client, pubkey, commitment)
                    .await
                    .and_then(|ref a| nonblocking::data_from_account(a))?;
                true
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockhashQuery {
    Static(Hash),
    Validated(Source, Hash),
    Rpc(Source),
}

impl BlockhashQuery {
    pub fn new(blockhash: Option<Hash>, sign_only: bool, nonce_account: Option<Pubkey>) -> Self {
        let source = nonce_account
            .map(Source::NonceAccount)
            .unwrap_or(Source::Cluster);
        match blockhash {
            Some(hash) if sign_only => Self::Static(hash),
            Some(hash) if !sign_only => Self::Validated(source, hash),
            None if !sign_only => Self::Rpc(source),
            _ => panic!("Cannot resolve blockhash"),
        }
    }

    pub fn new_from_matches(matches: &ArgMatches<'_>) -> Self {
        let blockhash = value_of(matches, BLOCKHASH_ARG.name);
        let sign_only = matches.is_present(SIGN_ONLY_ARG.name);
        let nonce_account = pubkey_of(matches, NONCE_ARG.name);
        BlockhashQuery::new(blockhash, sign_only, nonce_account)
    }

    pub async fn get_blockhash(
        &self,
        rpc_client: &RpcClient,
        commitment: CommitmentConfig,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        match self {
            BlockhashQuery::Static(hash) => Ok(*hash),
            BlockhashQuery::Validated(source, hash) => {
                if !source
                    .is_blockhash_valid(rpc_client, hash, commitment)
                    .await?
                {
                    return Err(format!("Hash has expired {hash:?}").into());
                }
                Ok(*hash)
            }
            BlockhashQuery::Rpc(source) => source.get_blockhash(rpc_client, commitment).await,
        }
    }
}

impl Default for BlockhashQuery {
    fn default() -> Self {
        BlockhashQuery::Rpc(Source::Cluster)
    }
}
