use {
    super::Bank,
    crate::accounts::account_rent_state::RentState,
    log::{debug, warn},
    solana_accounts_db::stake_rewards::RewardInfo,
    solana_sdk::{
        account::{ReadableAccount, WritableAccount},
        pubkey::Pubkey,
        reward_type::RewardType,
        system_program,
    },
    solana_vote::vote_account::VoteAccountsHashMap,
    std::{result::Result, sync::atomic::Ordering::Relaxed},
    thiserror::Error,
};

#[derive(Debug)]
struct DepositFeeOptions {
    check_account_owner: bool,
    check_rent_paying: bool,
}

#[derive(Error, Debug, PartialEq)]
enum DepositFeeError {
    #[error("fee account became rent paying")]
    InvalidRentPayingAccount,
    #[error("lamport overflow")]
    LamportOverflow,
    #[error("invalid fee account owner")]
    InvalidAccountOwner,
}

impl Bank {
    // Distribute collected transaction fees for this slot to collector_id (= current leader).
    //
    // Each validator is incentivized to process more transactions to earn more transaction fees.
    // Transaction fees are rewarded for the computing resource utilization cost, directly
    // proportional to their actual processing power.
    //
    // collector_id is rotated according to stake-weighted leader schedule. So the opportunity of
    // earning transaction fees are fairly distributed by stake. And missing the opportunity
    // (not producing a block as a leader) earns nothing. So, being online is incentivized as a
    // form of transaction fees as well.
    //
    // On the other hand, rent fees are distributed under slightly different philosophy, while
    // still being stake-weighted.
    // Ref: distribute_rent_to_validators
    pub(super) fn distribute_transaction_fees(&self) {
        let collector_fees = self.collector_fees.load(Relaxed);
        if collector_fees != 0 {
            let (deposit, mut burn) = self.fee_rate_governor.burn(collector_fees);
            if deposit > 0 {
                let validate_fee_collector = self.validate_fee_collector_account();
                match self.deposit_fees(
                    &self.collector_id,
                    deposit,
                    DepositFeeOptions {
                        check_account_owner: validate_fee_collector,
                        check_rent_paying: validate_fee_collector,
                    },
                ) {
                    Ok(post_balance) => {
                        self.rewards.write().unwrap().push((
                            self.collector_id,
                            RewardInfo {
                                reward_type: RewardType::Fee,
                                lamports: deposit as i64,
                                post_balance,
                                commission: None,
                            },
                        ));
                    }
                    Err(err) => {
                        debug!(
                            "Burned {} lamport tx fee instead of sending to {} due to {}",
                            deposit, self.collector_id, err
                        );
                        datapoint_warn!(
                            "bank-burned_fee",
                            ("slot", self.slot(), i64),
                            ("num_lamports", deposit, i64),
                            ("error", err.to_string(), String),
                        );
                        burn += deposit;
                    }
                }
            }
            self.capitalization.fetch_sub(burn, Relaxed);
        }
    }

    // Deposits fees into a specified account and if successful, returns the new balance of that account
    fn deposit_fees(
        &self,
        pubkey: &Pubkey,
        fees: u64,
        options: DepositFeeOptions,
    ) -> Result<u64, DepositFeeError> {
        let mut account = self.get_account_with_fixed_root(pubkey).unwrap_or_default();

        if options.check_account_owner && !system_program::check_id(account.owner()) {
            return Err(DepositFeeError::InvalidAccountOwner);
        }

        let rent = &self.rent_collector().rent;
        let recipient_pre_rent_state = RentState::from_account(&account, rent);
        let distribution = account.checked_add_lamports(fees);
        if distribution.is_err() {
            return Err(DepositFeeError::LamportOverflow);
        }
        if options.check_rent_paying {
            let recipient_post_rent_state = RentState::from_account(&account, rent);
            let rent_state_transition_allowed =
                recipient_post_rent_state.transition_allowed_from(&recipient_pre_rent_state);
            if !rent_state_transition_allowed {
                return Err(DepositFeeError::InvalidRentPayingAccount);
            }
        }

        self.store_account(pubkey, &account);
        Ok(account.lamports())
    }

    // Distribute collected rent fees for this slot to staked validators (excluding stakers)
    // according to stake.
    //
    // The nature of rent fee is the cost of doing business, every validator has to hold (or have
    // access to) the same list of accounts, so we pay according to stake, which is a rough proxy for
    // value to the network.
    //
    // Currently, rent distribution doesn't consider given validator's uptime at all (this might
    // change). That's because rent should be rewarded for the storage resource utilization cost.
    // It's treated differently from transaction fees, which is for the computing resource
    // utilization cost.
    //
    // We can't use collector_id (which is rotated according to stake-weighted leader schedule)
    // as an approximation to the ideal rent distribution to simplify and avoid this per-slot
    // computation for the distribution (time: N log N, space: N acct. stores; N = # of
    // validators).
    // The reason is that rent fee doesn't need to be incentivized for throughput unlike transaction
    // fees
    //
    // Ref: distribute_transaction_fees
    #[allow(clippy::needless_collect)]
    fn distribute_rent_to_validators(
        &self,
        vote_accounts: &VoteAccountsHashMap,
        rent_to_be_distributed: u64,
    ) {
        let mut total_staked = 0;

        // Collect the stake associated with each validator.
        // Note that a validator may be present in this vector multiple times if it happens to have
        // more than one staked vote account somehow
        let mut validator_stakes = vote_accounts
            .iter()
            .filter_map(|(_vote_pubkey, (staked, account))| {
                if *staked == 0 {
                    None
                } else {
                    total_staked += *staked;
                    Some((account.node_pubkey()?, *staked))
                }
            })
            .collect::<Vec<(Pubkey, u64)>>();

        #[cfg(test)]
        if validator_stakes.is_empty() {
            // some tests bank.freezes() with bad staking state
            self.capitalization
                .fetch_sub(rent_to_be_distributed, Relaxed);
            return;
        }
        #[cfg(not(test))]
        assert!(!validator_stakes.is_empty());

        // Sort first by stake and then by validator identity pubkey for determinism.
        // If two items are still equal, their relative order does not matter since
        // both refer to the same validator.
        validator_stakes.sort_unstable_by(|(pubkey1, staked1), (pubkey2, staked2)| {
            (staked1, pubkey1).cmp(&(staked2, pubkey2)).reverse()
        });

        let mut rent_distributed_in_initial_round = 0;
        let validator_rent_shares = validator_stakes
            .into_iter()
            .map(|(pubkey, staked)| {
                let rent_share = (((staked as u128) * (rent_to_be_distributed as u128))
                    / (total_staked as u128))
                    .try_into()
                    .unwrap();
                rent_distributed_in_initial_round += rent_share;
                (pubkey, rent_share)
            })
            .collect::<Vec<(Pubkey, u64)>>();

        // Leftover lamports after fraction calculation, will be paid to validators starting from highest stake
        // holder
        let mut leftover_lamports = rent_to_be_distributed - rent_distributed_in_initial_round;

        let mut rent_to_burn: u64 = 0;
        let mut rewards = vec![];
        validator_rent_shares
            .into_iter()
            .for_each(|(pubkey, rent_share)| {
                let rent_to_be_paid = if leftover_lamports > 0 {
                    leftover_lamports -= 1;
                    rent_share + 1
                } else {
                    rent_share
                };
                if rent_to_be_paid > 0 {
                    let check_account_owner = self.validate_fee_collector_account();
                    match self.deposit_fees(
                        &pubkey,
                        rent_to_be_paid,
                        DepositFeeOptions {
                            check_account_owner,
                            check_rent_paying: true,
                        },
                    ) {
                        Ok(post_balance) => {
                            rewards.push((
                                pubkey,
                                RewardInfo {
                                    reward_type: RewardType::Rent,
                                    lamports: rent_to_be_paid as i64,
                                    post_balance,
                                    commission: None,
                                },
                            ));
                        }
                        Err(err) => {
                            debug!(
                                "Burned {} lamport rent fee instead of sending to {} due to {}",
                                rent_to_be_paid, pubkey, err
                            );

                            // overflow adding lamports or resulting account is invalid
                            // so burn lamports and track lamports burned per slot
                            rent_to_burn = rent_to_burn.saturating_add(rent_to_be_paid);
                        }
                    }
                }
            });
        self.rewards.write().unwrap().append(&mut rewards);

        if rent_to_burn > 0 {
            self.capitalization.fetch_sub(rent_to_burn, Relaxed);
            datapoint_warn!(
                "bank-burned_rent",
                ("slot", self.slot(), i64),
                ("num_lamports", rent_to_burn, i64)
            );
        }

        assert_eq!(leftover_lamports, 0);
    }

    pub(super) fn distribute_rent_fees(&self) {
        let total_rent_collected = self.collected_rent.load(Relaxed);

        if !self.should_collect_rent() {
            if total_rent_collected != 0 {
                warn!("Rent fees collection is disabled, yet total rent collected was non zero! Total rent collected: {total_rent_collected}");
            }
            return;
        }

        let (burned_portion, rent_to_be_distributed) = self
            .rent_collector
            .rent
            .calculate_burn(total_rent_collected);

        debug!(
            "distributed rent: {} (rounded from: {}, burned: {})",
            rent_to_be_distributed, total_rent_collected, burned_portion
        );
        self.capitalization.fetch_sub(burned_portion, Relaxed);

        if rent_to_be_distributed == 0 {
            return;
        }

        self.distribute_rent_to_validators(&self.vote_accounts(), rent_to_be_distributed);
    }
}
