//! Calculation of transaction fees.

#![allow(clippy::arithmetic_side_effects)]
use {
    crate::{clock::DEFAULT_MS_PER_SLOT, ed25519_program, message::Message, secp256k1_program},
    log::*,
};

#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Copy, Debug, AbiExample)]
#[serde(rename_all = "camelCase")]
pub struct FeeCalculator {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    pub lamports_per_signature: u64,
}

impl FeeCalculator {
    pub fn new(lamports_per_signature: u64) -> Self {
        Self {
            lamports_per_signature,
        }
    }

    #[deprecated(
        since = "1.9.0",
        note = "Please do not use, will no longer be available in the future"
    )]
    pub fn calculate_fee(&self, message: &Message) -> u64 {
        let mut num_signatures: u64 = 0;
        for instruction in &message.instructions {
            let program_index = instruction.program_id_index as usize;
            // Message may not be sanitized here
            if program_index < message.account_keys.len() {
                let id = message.account_keys[program_index];
                if (secp256k1_program::check_id(&id) || ed25519_program::check_id(&id))
                    && !instruction.data.is_empty()
                {
                    num_signatures += instruction.data[0] as u64;
                }
            }
        }

        self.lamports_per_signature
            * (u64::from(message.header.num_required_signatures) + num_signatures)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, AbiExample)]
#[serde(rename_all = "camelCase")]
pub struct FeeRateGovernor {
    // The current cost of a signature  This amount may increase/decrease over time based on
    // cluster processing load.
    #[serde(skip)]
    pub lamports_per_signature: u64,

    // The target cost of a signature when the cluster is operating around target_signatures_per_slot
    // signatures
    pub target_lamports_per_signature: u64,

    // Used to estimate the desired processing capacity of the cluster.  As the signatures for
    // recent slots are fewer/greater than this value, lamports_per_signature will decrease/increase
    // for the next slot.  A value of 0 disables lamports_per_signature fee adjustments
    pub target_signatures_per_slot: u64,

    pub min_lamports_per_signature: u64,
    pub max_lamports_per_signature: u64,

    // What portion of collected fees are to be destroyed, as a fraction of std::u8::MAX
    pub burn_percent: u8,
}

pub const DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE: u64 = 10_000;
pub const DEFAULT_TARGET_SIGNATURES_PER_SLOT: u64 = 50 * DEFAULT_MS_PER_SLOT;

// Percentage of tx fees to burn
pub const DEFAULT_BURN_PERCENT: u8 = 50;

impl Default for FeeRateGovernor {
    fn default() -> Self {
        Self {
            lamports_per_signature: 0,
            target_lamports_per_signature: DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE,
            target_signatures_per_slot: DEFAULT_TARGET_SIGNATURES_PER_SLOT,
            min_lamports_per_signature: 0,
            max_lamports_per_signature: 0,
            burn_percent: DEFAULT_BURN_PERCENT,
        }
    }
}

impl FeeRateGovernor {
    pub fn new(target_lamports_per_signature: u64, target_signatures_per_slot: u64) -> Self {
        let base_fee_rate_governor = Self {
            target_lamports_per_signature,
            lamports_per_signature: target_lamports_per_signature,
            target_signatures_per_slot,
            ..FeeRateGovernor::default()
        };

        Self::new_derived(&base_fee_rate_governor, 0)
    }

    pub fn new_derived(
        base_fee_rate_governor: &FeeRateGovernor,
        latest_signatures_per_slot: u64,
    ) -> Self {
        let mut me = base_fee_rate_governor.clone();

        if me.target_signatures_per_slot > 0 {
            // lamports_per_signature can range from 50% to 1000% of
            // target_lamports_per_signature
            me.min_lamports_per_signature = std::cmp::max(1, me.target_lamports_per_signature / 2);
            me.max_lamports_per_signature = me.target_lamports_per_signature * 10;

            // What the cluster should charge at `latest_signatures_per_slot`
            let desired_lamports_per_signature =
                me.max_lamports_per_signature
                    .min(me.min_lamports_per_signature.max(
                        me.target_lamports_per_signature
                            * std::cmp::min(latest_signatures_per_slot, std::u32::MAX as u64)
                            / me.target_signatures_per_slot,
                    ));

            trace!(
                "desired_lamports_per_signature: {}",
                desired_lamports_per_signature
            );

            let gap = desired_lamports_per_signature as i64
                - base_fee_rate_governor.lamports_per_signature as i64;

            if gap == 0 {
                me.lamports_per_signature = desired_lamports_per_signature;
            } else {
                // Adjust fee by 5% of target_lamports_per_signature to produce a smooth
                // increase/decrease in fees over time.
                let gap_adjust =
                    std::cmp::max(1, me.target_lamports_per_signature / 20) as i64 * gap.signum();

                trace!(
                    "lamports_per_signature gap is {}, adjusting by {}",
                    gap,
                    gap_adjust
                );

                me.lamports_per_signature =
                    me.max_lamports_per_signature
                        .min(me.min_lamports_per_signature.max(
                            (base_fee_rate_governor.lamports_per_signature as i64 + gap_adjust)
                                as u64,
                        ));
            }
        } else {
            me.lamports_per_signature = base_fee_rate_governor.target_lamports_per_signature;
            me.min_lamports_per_signature = me.target_lamports_per_signature;
            me.max_lamports_per_signature = me.target_lamports_per_signature;
        }
        debug!(
            "new_derived(): lamports_per_signature: {}",
            me.lamports_per_signature
        );
        me
    }

    pub fn clone_with_lamports_per_signature(&self, lamports_per_signature: u64) -> Self {
        Self {
            lamports_per_signature,
            ..*self
        }
    }

    /// calculate unburned fee from a fee total, returns (unburned, burned)
    pub fn burn(&self, fees: u64) -> (u64, u64) {
        let burned = fees * u64::from(self.burn_percent) / 100;
        (fees - burned, burned)
    }

    /// create a FeeCalculator based on current cluster signature throughput
    pub fn create_fee_calculator(&self) -> FeeCalculator {
        FeeCalculator::new(self.lamports_per_signature)
    }
}
