use {
    crate::keypair::{
        keypair_from_seed_phrase, pubkey_from_path, resolve_signer_from_path, signer_from_path,
        ASK_KEYWORD, SKIP_SEED_PHRASE_VALIDATION_ARG,
    },
    chrono::DateTime,
    clap::ArgMatches,
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_sdk::{
        clock::UnixTimestamp,
        commitment_config::CommitmentConfig,
        genesis_config::ClusterType,
        native_token::sol_to_lamports,
        pubkey::Pubkey,
        signature::{read_keypair_file, Keypair, Signature, Signer},
    },
    std::{rc::Rc, str::FromStr},
};

// Sentinel value used to indicate to write to screen instead of file
pub const STDOUT_OUTFILE_TOKEN: &str = "-";

// Return parsed values from matches at `name`
pub fn values_of<T>(matches: &ArgMatches<'_>, name: &str) -> Option<Vec<T>>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    matches
        .values_of(name)
        .map(|xs| xs.map(|x| x.parse::<T>().unwrap()).collect())
}

// Return a parsed value from matches at `name`
pub fn value_of<T>(matches: &ArgMatches<'_>, name: &str) -> Option<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    if let Some(value) = matches.value_of(name) {
        value.parse::<T>().ok()
    } else {
        None
    }
}

pub fn unix_timestamp_from_rfc3339_datetime(
    matches: &ArgMatches<'_>,
    name: &str,
) -> Option<UnixTimestamp> {
    matches.value_of(name).and_then(|value| {
        DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|date_time| date_time.timestamp())
    })
}

// Return the keypair for an argument with filename `name` or None if not present.
pub fn keypair_of(matches: &ArgMatches<'_>, name: &str) -> Option<Keypair> {
    if let Some(value) = matches.value_of(name) {
        if value == ASK_KEYWORD {
            let skip_validation = matches.is_present(SKIP_SEED_PHRASE_VALIDATION_ARG.name);
            keypair_from_seed_phrase(name, skip_validation, true, None, true).ok()
        } else {
            read_keypair_file(value).ok()
        }
    } else {
        None
    }
}

pub fn keypairs_of(matches: &ArgMatches<'_>, name: &str) -> Option<Vec<Keypair>> {
    matches.values_of(name).map(|values| {
        values
            .filter_map(|value| {
                if value == ASK_KEYWORD {
                    let skip_validation = matches.is_present(SKIP_SEED_PHRASE_VALIDATION_ARG.name);
                    keypair_from_seed_phrase(name, skip_validation, true, None, true).ok()
                } else {
                    read_keypair_file(value).ok()
                }
            })
            .collect()
    })
}

// Return a pubkey for an argument that can itself be parsed into a pubkey,
// or is a filename that can be read as a keypair
pub fn pubkey_of(matches: &ArgMatches<'_>, name: &str) -> Option<Pubkey> {
    value_of(matches, name).or_else(|| keypair_of(matches, name).map(|keypair| keypair.pubkey()))
}

pub fn pubkeys_of(matches: &ArgMatches<'_>, name: &str) -> Option<Vec<Pubkey>> {
    matches.values_of(name).map(|values| {
        values
            .map(|value| {
                value.parse::<Pubkey>().unwrap_or_else(|_| {
                    read_keypair_file(value)
                        .expect("read_keypair_file failed")
                        .pubkey()
                })
            })
            .collect()
    })
}

// Return pubkey/signature pairs for a string of the form pubkey=signature
pub fn pubkeys_sigs_of(matches: &ArgMatches<'_>, name: &str) -> Option<Vec<(Pubkey, Signature)>> {
    matches.values_of(name).map(|values| {
        values
            .map(|pubkey_signer_string| {
                let mut signer = pubkey_signer_string.split('=');
                let key = Pubkey::from_str(signer.next().unwrap()).unwrap();
                let sig = Signature::from_str(signer.next().unwrap()).unwrap();
                (key, sig)
            })
            .collect()
    })
}

// Return a signer from matches at `name`
#[allow(clippy::type_complexity)]
pub fn signer_of(
    matches: &ArgMatches<'_>,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<(Option<Box<dyn Signer>>, Option<Pubkey>), Box<dyn std::error::Error>> {
    if let Some(location) = matches.value_of(name) {
        let signer = signer_from_path(matches, location, name, wallet_manager)?;
        let signer_pubkey = signer.pubkey();
        Ok((Some(signer), Some(signer_pubkey)))
    } else {
        Ok((None, None))
    }
}

pub fn pubkey_of_signer(
    matches: &ArgMatches<'_>,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<Pubkey>, Box<dyn std::error::Error>> {
    if let Some(location) = matches.value_of(name) {
        Ok(Some(pubkey_from_path(
            matches,
            location,
            name,
            wallet_manager,
        )?))
    } else {
        Ok(None)
    }
}

pub fn pubkeys_of_multiple_signers(
    matches: &ArgMatches<'_>,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<Vec<Pubkey>>, Box<dyn std::error::Error>> {
    if let Some(pubkey_matches) = matches.values_of(name) {
        let mut pubkeys: Vec<Pubkey> = vec![];
        for signer in pubkey_matches {
            pubkeys.push(pubkey_from_path(matches, signer, name, wallet_manager)?);
        }
        Ok(Some(pubkeys))
    } else {
        Ok(None)
    }
}

pub fn resolve_signer(
    matches: &ArgMatches<'_>,
    name: &str,
    wallet_manager: &mut Option<Rc<RemoteWalletManager>>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    resolve_signer_from_path(
        matches,
        matches.value_of(name).unwrap(),
        name,
        wallet_manager,
    )
}

pub fn lamports_of_sol(matches: &ArgMatches<'_>, name: &str) -> Option<u64> {
    value_of(matches, name).map(sol_to_lamports)
}

pub fn cluster_type_of(matches: &ArgMatches<'_>, name: &str) -> Option<ClusterType> {
    value_of(matches, name)
}

pub fn commitment_of(matches: &ArgMatches<'_>, name: &str) -> Option<CommitmentConfig> {
    matches
        .value_of(name)
        .map(|value| CommitmentConfig::from_str(value).unwrap_or_default())
}
