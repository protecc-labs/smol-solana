#[allow(deprecated)]
use solana_sdk::sysvar::{fees::Fees, recent_blockhashes::RecentBlockhashes};
use {
    crate::{
        parse_account_data::{ParsableAccount, ParseAccountError},
        StringAmount, UiFeeCalculator,
    },
    bincode::deserialize,
    bv::BitVec,
    solana_sdk::{
        clock::{Clock, Epoch, Slot, UnixTimestamp},
        epoch_schedule::EpochSchedule,
        pubkey::Pubkey,
        rent::Rent,
        slot_hashes::SlotHashes,
        slot_history::{self, SlotHistory},
        stake_history::{StakeHistory, StakeHistoryEntry},
        sysvar::{
            self, epoch_rewards::EpochRewards, last_restart_slot::LastRestartSlot, rewards::Rewards,
        },
    },
};

pub fn parse_sysvar(data: &[u8], pubkey: &Pubkey) -> Result<SysvarAccountType, ParseAccountError> {
    #[allow(deprecated)]
    let parsed_account = {
        if pubkey == &sysvar::clock::id() {
            deserialize::<Clock>(data)
                .ok()
                .map(|clock| SysvarAccountType::Clock(clock.into()))
        } else if pubkey == &sysvar::epoch_schedule::id() {
            deserialize(data).ok().map(SysvarAccountType::EpochSchedule)
        } else if pubkey == &sysvar::fees::id() {
            deserialize::<Fees>(data)
                .ok()
                .map(|fees| SysvarAccountType::Fees(fees.into()))
        } else if pubkey == &sysvar::recent_blockhashes::id() {
            deserialize::<RecentBlockhashes>(data)
                .ok()
                .map(|recent_blockhashes| {
                    let recent_blockhashes = recent_blockhashes
                        .iter()
                        .map(|entry| UiRecentBlockhashesEntry {
                            blockhash: entry.blockhash.to_string(),
                            fee_calculator: entry.fee_calculator.into(),
                        })
                        .collect();
                    SysvarAccountType::RecentBlockhashes(recent_blockhashes)
                })
        } else if pubkey == &sysvar::rent::id() {
            deserialize::<Rent>(data)
                .ok()
                .map(|rent| SysvarAccountType::Rent(rent.into()))
        } else if pubkey == &sysvar::rewards::id() {
            deserialize::<Rewards>(data)
                .ok()
                .map(|rewards| SysvarAccountType::Rewards(rewards.into()))
        } else if pubkey == &sysvar::slot_hashes::id() {
            deserialize::<SlotHashes>(data).ok().map(|slot_hashes| {
                let slot_hashes = slot_hashes
                    .iter()
                    .map(|slot_hash| UiSlotHashEntry {
                        slot: slot_hash.0,
                        hash: slot_hash.1.to_string(),
                    })
                    .collect();
                SysvarAccountType::SlotHashes(slot_hashes)
            })
        } else if pubkey == &sysvar::slot_history::id() {
            deserialize::<SlotHistory>(data).ok().map(|slot_history| {
                SysvarAccountType::SlotHistory(UiSlotHistory {
                    next_slot: slot_history.next_slot,
                    bits: format!("{:?}", SlotHistoryBits(slot_history.bits)),
                })
            })
        } else if pubkey == &sysvar::stake_history::id() {
            deserialize::<StakeHistory>(data).ok().map(|stake_history| {
                let stake_history = stake_history
                    .iter()
                    .map(|entry| UiStakeHistoryEntry {
                        epoch: entry.0,
                        stake_history: entry.1.clone(),
                    })
                    .collect();
                SysvarAccountType::StakeHistory(stake_history)
            })
        } else if pubkey == &sysvar::last_restart_slot::id() {
            deserialize::<LastRestartSlot>(data)
                .ok()
                .map(|last_restart_slot| {
                    let last_restart_slot = last_restart_slot.last_restart_slot;
                    SysvarAccountType::LastRestartSlot(UiLastRestartSlot { last_restart_slot })
                })
        } else if pubkey == &sysvar::epoch_rewards::id() {
            deserialize::<EpochRewards>(data)
                .ok()
                .map(SysvarAccountType::EpochRewards)
        } else {
            None
        }
    };
    parsed_account.ok_or(ParseAccountError::AccountNotParsable(
        ParsableAccount::Sysvar,
    ))
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
pub enum SysvarAccountType {
    Clock(UiClock),
    EpochSchedule(EpochSchedule),
    #[allow(deprecated)]
    Fees(UiFees),
    #[allow(deprecated)]
    RecentBlockhashes(Vec<UiRecentBlockhashesEntry>),
    Rent(UiRent),
    Rewards(UiRewards),
    SlotHashes(Vec<UiSlotHashEntry>),
    SlotHistory(UiSlotHistory),
    StakeHistory(Vec<UiStakeHistoryEntry>),
    LastRestartSlot(UiLastRestartSlot),
    EpochRewards(EpochRewards),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UiClock {
    pub slot: Slot,
    pub epoch: Epoch,
    pub epoch_start_timestamp: UnixTimestamp,
    pub leader_schedule_epoch: Epoch,
    pub unix_timestamp: UnixTimestamp,
}

impl From<Clock> for UiClock {
    fn from(clock: Clock) -> Self {
        Self {
            slot: clock.slot,
            epoch: clock.epoch,
            epoch_start_timestamp: clock.epoch_start_timestamp,
            leader_schedule_epoch: clock.leader_schedule_epoch,
            unix_timestamp: clock.unix_timestamp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UiFees {
    pub fee_calculator: UiFeeCalculator,
}
#[allow(deprecated)]
impl From<Fees> for UiFees {
    fn from(fees: Fees) -> Self {
        Self {
            fee_calculator: fees.fee_calculator.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UiRent {
    pub lamports_per_byte_year: StringAmount,
    pub exemption_threshold: f64,
    pub burn_percent: u8,
}

impl From<Rent> for UiRent {
    fn from(rent: Rent) -> Self {
        Self {
            lamports_per_byte_year: rent.lamports_per_byte_year.to_string(),
            exemption_threshold: rent.exemption_threshold,
            burn_percent: rent.burn_percent,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UiRewards {
    pub validator_point_value: f64,
}

impl From<Rewards> for UiRewards {
    fn from(rewards: Rewards) -> Self {
        Self {
            validator_point_value: rewards.validator_point_value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiRecentBlockhashesEntry {
    pub blockhash: String,
    pub fee_calculator: UiFeeCalculator,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiSlotHashEntry {
    pub slot: Slot,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiSlotHistory {
    pub next_slot: Slot,
    pub bits: String,
}

struct SlotHistoryBits(BitVec<u64>);

impl std::fmt::Debug for SlotHistoryBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in 0..slot_history::MAX_ENTRIES {
            if self.0.get(i) {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UiStakeHistoryEntry {
    pub epoch: Epoch,
    pub stake_history: StakeHistoryEntry,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct UiLastRestartSlot {
    pub last_restart_slot: Slot,
}
