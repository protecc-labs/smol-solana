/// A helper for calculating a stake-weighted timestamp estimate from a set of timestamps and epoch
/// stake.
use solana_sdk::{
    clock::{Slot, UnixTimestamp},
    pubkey::Pubkey,
};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    time::Duration,
};

// Obsolete limits
const _MAX_ALLOWABLE_DRIFT_PERCENTAGE: u32 = 50;
const _MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW: u32 = 80;

pub(crate) const MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST: u32 = 25;
pub(crate) const MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2: u32 = 150;

#[derive(Copy, Clone)]
pub(crate) struct MaxAllowableDrift {
    pub fast: u32, // Max allowable drift percentage faster than poh estimate
    pub slow: u32, // Max allowable drift percentage slower than poh estimate
}

pub(crate) fn calculate_stake_weighted_timestamp<I, K, V, T>(
    unique_timestamps: I,
    stakes: &HashMap<Pubkey, (u64, T /*Account|VoteAccount*/)>,
    slot: Slot,
    slot_duration: Duration,
    epoch_start_timestamp: Option<(Slot, UnixTimestamp)>,
    max_allowable_drift: MaxAllowableDrift,
    fix_estimate_into_u64: bool,
) -> Option<UnixTimestamp>
where
    I: IntoIterator<Item = (K, V)>,
    K: Borrow<Pubkey>,
    V: Borrow<(Slot, UnixTimestamp)>,
{
    let mut stake_per_timestamp: BTreeMap<UnixTimestamp, u128> = BTreeMap::new();
    let mut total_stake: u128 = 0;
    for (vote_pubkey, slot_timestamp) in unique_timestamps {
        let (timestamp_slot, timestamp) = slot_timestamp.borrow();
        let offset = slot_duration.saturating_mul(slot.saturating_sub(*timestamp_slot) as u32);
        let estimate = timestamp.saturating_add(offset.as_secs() as i64);
        let stake = stakes
            .get(vote_pubkey.borrow())
            .map(|(stake, _account)| stake)
            .unwrap_or(&0);
        stake_per_timestamp
            .entry(estimate)
            .and_modify(|stake_sum| *stake_sum = stake_sum.saturating_add(*stake as u128))
            .or_insert(*stake as u128);
        total_stake = total_stake.saturating_add(*stake as u128);
    }
    if total_stake == 0 {
        return None;
    }
    let mut stake_accumulator: u128 = 0;
    let mut estimate = 0;
    // Populate `estimate` with stake-weighted median timestamp
    for (timestamp, stake) in stake_per_timestamp.into_iter() {
        stake_accumulator = stake_accumulator.saturating_add(stake);
        if stake_accumulator > total_stake / 2 {
            estimate = timestamp;
            break;
        }
    }
    // Bound estimate by `max_allowable_drift` since the start of the epoch
    if let Some((epoch_start_slot, epoch_start_timestamp)) = epoch_start_timestamp {
        let poh_estimate_offset =
            slot_duration.saturating_mul(slot.saturating_sub(epoch_start_slot) as u32);
        let estimate_offset = Duration::from_secs(if fix_estimate_into_u64 {
            (estimate as u64).saturating_sub(epoch_start_timestamp as u64)
        } else {
            estimate.saturating_sub(epoch_start_timestamp) as u64
        });
        let max_allowable_drift_fast =
            poh_estimate_offset.saturating_mul(max_allowable_drift.fast) / 100;
        let max_allowable_drift_slow =
            poh_estimate_offset.saturating_mul(max_allowable_drift.slow) / 100;
        if estimate_offset > poh_estimate_offset
            && estimate_offset.saturating_sub(poh_estimate_offset) > max_allowable_drift_slow
        {
            // estimate offset since the start of the epoch is higher than
            // `max_allowable_drift_slow`
            estimate = epoch_start_timestamp
                .saturating_add(poh_estimate_offset.as_secs() as i64)
                .saturating_add(max_allowable_drift_slow.as_secs() as i64);
        } else if estimate_offset < poh_estimate_offset
            && poh_estimate_offset.saturating_sub(estimate_offset) > max_allowable_drift_fast
        {
            // estimate offset since the start of the epoch is lower than
            // `max_allowable_drift_fast`
            estimate = epoch_start_timestamp
                .saturating_add(poh_estimate_offset.as_secs() as i64)
                .saturating_sub(max_allowable_drift_fast.as_secs() as i64);
        }
    }
    Some(estimate)
}
