//! Vote state

#[cfg(test)]
use crate::epoch_schedule::MAX_LEADER_SCHEDULE_EPOCH_OFFSET;
#[cfg(not(target_os = "solana"))]
use bincode::deserialize;
use {
    crate::{
        clock::{Epoch, Slot, UnixTimestamp},
        hash::Hash,
        instruction::InstructionError,
        pubkey::Pubkey,
        rent::Rent,
        sysvar::clock::Clock,
        vote::{authorized_voters::AuthorizedVoters, error::VoteError},
    },
    bincode::{serialize_into, ErrorKind},
    serde_derive::{Deserialize, Serialize},
    std::{collections::VecDeque, fmt::Debug},
};

mod vote_state_0_23_5;
pub mod vote_state_1_14_11;
pub use vote_state_1_14_11::*;
pub mod vote_state_versions;
pub use vote_state_versions::*;

// Maximum number of votes to keep around, tightly coupled with epoch_schedule::MINIMUM_SLOTS_PER_EPOCH
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const INITIAL_LOCKOUT: usize = 2;

// Maximum number of credits history to keep around
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// Offset of VoteState::prior_voters, for determining initialization status without deserialization
const DEFAULT_PRIOR_VOTERS_OFFSET: usize = 114;

// Number of slots of grace period for which maximum vote credits are awarded - votes landing within this number of slots of the slot that is being voted on are awarded full credits.
pub const VOTE_CREDITS_GRACE_SLOTS: u8 = 2;

// Maximum number of credits to award for a vote; this number of credits is awarded to votes on slots that land within the grace period. After that grace period, vote credits are reduced.
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u8 = 8;

#[frozen_abi(digest = "Ch2vVEwos2EjAVqSHCyJjnN2MNX1yrpapZTGhMSCjWUH")]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Clone, AbiExample)]
pub struct Vote {
    /// A stack of votes starting with the oldest vote
    pub slots: Vec<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl Vote {
    pub fn new(slots: Vec<Slot>, hash: Hash) -> Self {
        Self {
            slots,
            hash,
            timestamp: None,
        }
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.slots.last().copied()
    }
}

#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Copy, Clone, AbiExample)]
pub struct Lockout {
    slot: Slot,
    confirmation_count: u32,
}

impl Lockout {
    pub fn new(slot: Slot) -> Self {
        Self::new_with_confirmation_count(slot, 1)
    }

    pub fn new_with_confirmation_count(slot: Slot, confirmation_count: u32) -> Self {
        Self {
            slot,
            confirmation_count,
        }
    }

    // The number of slots for which this vote is locked
    pub fn lockout(&self) -> u64 {
        (INITIAL_LOCKOUT as u64).pow(self.confirmation_count())
    }

    // The last slot at which a vote is still locked out. Validators should not
    // vote on a slot in another fork which is less than or equal to this slot
    // to avoid having their stake slashed.
    pub fn last_locked_out_slot(&self) -> Slot {
        self.slot.saturating_add(self.lockout())
    }

    pub fn is_locked_out_at_slot(&self, slot: Slot) -> bool {
        self.last_locked_out_slot() >= slot
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn confirmation_count(&self) -> u32 {
        self.confirmation_count
    }

    pub fn increase_confirmation_count(&mut self, by: u32) {
        self.confirmation_count = self.confirmation_count.saturating_add(by)
    }
}

#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Copy, Clone, AbiExample)]
pub struct LandedVote {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    pub latency: u8,
    pub lockout: Lockout,
}

impl LandedVote {
    pub fn slot(&self) -> Slot {
        self.lockout.slot
    }

    pub fn confirmation_count(&self) -> u32 {
        self.lockout.confirmation_count
    }
}

impl From<LandedVote> for Lockout {
    fn from(landed_vote: LandedVote) -> Self {
        landed_vote.lockout
    }
}

impl From<Lockout> for LandedVote {
    fn from(lockout: Lockout) -> Self {
        Self {
            latency: 0,
            lockout,
        }
    }
}

#[frozen_abi(digest = "GwJfVFsATSj7nvKwtUkHYzqPRaPY6SLxPGXApuCya3x5")]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq, Clone, AbiExample)]
pub struct VoteStateUpdate {
    /// The proposed tower
    pub lockouts: VecDeque<Lockout>,
    /// The proposed root
    pub root: Option<Slot>,
    /// signature of the bank's state at the last slot
    pub hash: Hash,
    /// processing timestamp of last slot
    pub timestamp: Option<UnixTimestamp>,
}

impl From<Vec<(Slot, u32)>> for VoteStateUpdate {
    fn from(recent_slots: Vec<(Slot, u32)>) -> Self {
        let lockouts: VecDeque<Lockout> = recent_slots
            .into_iter()
            .map(|(slot, confirmation_count)| {
                Lockout::new_with_confirmation_count(slot, confirmation_count)
            })
            .collect();
        Self {
            lockouts,
            root: None,
            hash: Hash::default(),
            timestamp: None,
        }
    }
}

impl VoteStateUpdate {
    pub fn new(lockouts: VecDeque<Lockout>, root: Option<Slot>, hash: Hash) -> Self {
        Self {
            lockouts,
            root,
            hash,
            timestamp: None,
        }
    }

    pub fn slots(&self) -> Vec<Slot> {
        self.lockouts.iter().map(|lockout| lockout.slot()).collect()
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.lockouts.back().map(|l| l.slot())
    }
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub struct VoteInit {
    pub node_pubkey: Pubkey,
    pub authorized_voter: Pubkey,
    pub authorized_withdrawer: Pubkey,
    pub commission: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum VoteAuthorize {
    Voter,
    Withdrawer,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
    pub new_authority: Pubkey,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VoteAuthorizeCheckedWithSeedArgs {
    pub authorization_type: VoteAuthorize,
    pub current_authority_derived_key_owner: Pubkey,
    pub current_authority_derived_key_seed: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct BlockTimestamp {
    pub slot: Slot,
    pub timestamp: UnixTimestamp,
}

// this is how many epochs a voter can be remembered for slashing
const MAX_ITEMS: usize = 32;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct CircBuf<I> {
    buf: [I; MAX_ITEMS],
    /// next pointer
    idx: usize,
    is_empty: bool,
}

impl<I: Default + Copy> Default for CircBuf<I> {
    fn default() -> Self {
        Self {
            buf: [I::default(); MAX_ITEMS],
            idx: MAX_ITEMS
                .checked_sub(1)
                .expect("`MAX_ITEMS` should be positive"),
            is_empty: true,
        }
    }
}

impl<I> CircBuf<I> {
    pub fn append(&mut self, item: I) {
        // remember prior delegate and when we switched, to support later slashing
        self.idx = self
            .idx
            .checked_add(1)
            .and_then(|idx| idx.checked_rem(MAX_ITEMS))
            .expect("`self.idx` should be < `MAX_ITEMS` which should be non-zero");

        self.buf[self.idx] = item;
        self.is_empty = false;
    }

    pub fn buf(&self) -> &[I; MAX_ITEMS] {
        &self.buf
    }

    pub fn last(&self) -> Option<&I> {
        if !self.is_empty {
            Some(&self.buf[self.idx])
        } else {
            None
        }
    }
}

#[frozen_abi(digest = "EeenjJaSrm9hRM39gK6raRNtzG61hnk7GciUCJJRDUSQ")]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, AbiExample)]
pub struct VoteState {
    /// the node that votes in this account
    pub node_pubkey: Pubkey,

    /// the signer for withdrawals
    pub authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    pub commission: u8,

    pub votes: VecDeque<LandedVote>,

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    pub root_slot: Option<Slot>,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// most recent timestamp submitted with a vote
    pub last_timestamp: BlockTimestamp,
}

impl VoteState {
    pub fn new(vote_init: &VoteInit, clock: &Clock) -> Self {
        Self {
            node_pubkey: vote_init.node_pubkey,
            authorized_voters: AuthorizedVoters::new(clock.epoch, vote_init.authorized_voter),
            authorized_withdrawer: vote_init.authorized_withdrawer,
            commission: vote_init.commission,
            ..VoteState::default()
        }
    }

    pub fn get_authorized_voter(&self, epoch: Epoch) -> Option<Pubkey> {
        self.authorized_voters.get_authorized_voter(epoch)
    }

    pub fn authorized_voters(&self) -> &AuthorizedVoters {
        &self.authorized_voters
    }

    pub fn prior_voters(&mut self) -> &CircBuf<(Pubkey, Epoch, Epoch)> {
        &self.prior_voters
    }

    pub fn get_rent_exempt_reserve(rent: &Rent) -> u64 {
        rent.minimum_balance(VoteState::size_of())
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const fn size_of() -> usize {
        3762 // see test_vote_state_size_of.
    }

    #[allow(clippy::used_underscore_binding)]
    pub fn deserialize(_input: &[u8]) -> Result<Self, InstructionError> {
        #[cfg(not(target_os = "solana"))]
        {
            deserialize::<VoteStateVersions>(_input)
                .map(|versioned| versioned.convert_to_current())
                .map_err(|_| InstructionError::InvalidAccountData)
        }
        #[cfg(target_os = "solana")]
        unimplemented!();
    }

    pub fn serialize(
        versioned: &VoteStateVersions,
        output: &mut [u8],
    ) -> Result<(), InstructionError> {
        serialize_into(output, versioned).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }

    /// returns commission split as (voter_portion, staker_portion, was_split) tuple
    ///
    ///  if commission calculation is 100% one way or other,
    ///   indicate with false for was_split
    pub fn commission_split(&self, on: u64) -> (u64, u64, bool) {
        match self.commission.min(100) {
            0 => (0, on, false),
            100 => (on, 0, false),
            split => {
                let on = u128::from(on);
                // Calculate mine and theirs independently and symmetrically instead of
                // using the remainder of the other to treat them strictly equally.
                // This is also to cancel the rewarding if either of the parties
                // should receive only fractional lamports, resulting in not being rewarded at all.
                // Thus, note that we intentionally discard any residual fractional lamports.
                let mine = on
                    .checked_mul(u128::from(split))
                    .expect("multiplication of a u64 and u8 should not overflow")
                    / 100u128;
                let theirs = on
                    .checked_mul(u128::from(
                        100u8
                            .checked_sub(split)
                            .expect("commission cannot be greater than 100"),
                    ))
                    .expect("multiplication of a u64 and u8 should not overflow")
                    / 100u128;

                (mine as u64, theirs as u64, true)
            }
        }
    }

    /// Returns if the vote state contains a slot `candidate_slot`
    pub fn contains_slot(&self, candidate_slot: Slot) -> bool {
        self.votes
            .binary_search_by(|vote| vote.slot().cmp(&candidate_slot))
            .is_ok()
    }

    #[cfg(test)]
    fn get_max_sized_vote_state() -> VoteState {
        let mut authorized_voters = AuthorizedVoters::default();
        for i in 0..=MAX_LEADER_SCHEDULE_EPOCH_OFFSET {
            authorized_voters.insert(i, Pubkey::new_unique());
        }

        VoteState {
            votes: VecDeque::from(vec![LandedVote::default(); MAX_LOCKOUT_HISTORY]),
            root_slot: Some(std::u64::MAX),
            epoch_credits: vec![(0, 0, 0); MAX_EPOCH_CREDITS_HISTORY],
            authorized_voters,
            ..Self::default()
        }
    }

    pub fn process_next_vote_slot(
        &mut self,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) {
        // Ignore votes for slots earlier than we already have votes for
        if self
            .last_voted_slot()
            .map_or(false, |last_voted_slot| next_vote_slot <= last_voted_slot)
        {
            return;
        }

        self.pop_expired_votes(next_vote_slot);

        let landed_vote = LandedVote {
            latency: Self::compute_vote_latency(next_vote_slot, current_slot),
            lockout: Lockout::new(next_vote_slot),
        };

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if self.votes.len() == MAX_LOCKOUT_HISTORY {
            let credits = self.credits_for_vote_at_index(0);
            let landed_vote = self.votes.pop_front().unwrap();
            self.root_slot = Some(landed_vote.slot());

            self.increment_credits(epoch, credits);
        }
        self.votes.push_back(landed_vote);
        self.double_lockouts();
    }

    /// increment credits, record credits for last epoch if new epoch
    pub fn increment_credits(&mut self, epoch: Epoch, credits: u64) {
        // increment credits, record by epoch

        // never seen a credit
        if self.epoch_credits.is_empty() {
            self.epoch_credits.push((epoch, 0, 0));
        } else if epoch != self.epoch_credits.last().unwrap().0 {
            let (_, credits, prev_credits) = *self.epoch_credits.last().unwrap();

            if credits != prev_credits {
                // if credits were earned previous epoch
                // append entry at end of list for the new epoch
                self.epoch_credits.push((epoch, credits, credits));
            } else {
                // else just move the current epoch
                self.epoch_credits.last_mut().unwrap().0 = epoch;
            }

            // Remove too old epoch_credits
            if self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
                self.epoch_credits.remove(0);
            }
        }

        self.epoch_credits.last_mut().unwrap().1 =
            self.epoch_credits.last().unwrap().1.saturating_add(credits);
    }

    // Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
    pub fn compute_vote_latency(voted_for_slot: Slot, current_slot: Slot) -> u8 {
        std::cmp::min(current_slot.saturating_sub(voted_for_slot), u8::MAX as u64) as u8
    }

    /// Returns the credits to award for a vote at the given lockout slot index
    pub fn credits_for_vote_at_index(&self, index: usize) -> u64 {
        let latency = self
            .votes
            .get(index)
            .map_or(0, |landed_vote| landed_vote.latency);

        // If latency is 0, this means that the Lockout was created and stored from a software version that did not
        // store vote latencies; in this case, 1 credit is awarded
        if latency == 0 {
            1
        } else {
            match latency.checked_sub(VOTE_CREDITS_GRACE_SLOTS) {
                None | Some(0) => {
                    // latency was <= VOTE_CREDITS_GRACE_SLOTS, so maximum credits are awarded
                    VOTE_CREDITS_MAXIMUM_PER_SLOT as u64
                }

                Some(diff) => {
                    // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
                    // Subtract diff from VOTE_CREDITS_MAXIMUM_PER_SLOT which is the number of credits to award
                    match VOTE_CREDITS_MAXIMUM_PER_SLOT.checked_sub(diff) {
                        // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
                        None | Some(0) => 1,

                        Some(credits) => credits as u64,
                    }
                }
            }
        }
    }

    pub fn nth_recent_lockout(&self, position: usize) -> Option<&Lockout> {
        if position < self.votes.len() {
            let pos = self
                .votes
                .len()
                .checked_sub(position)
                .and_then(|pos| pos.checked_sub(1))?;
            self.votes.get(pos).map(|vote| &vote.lockout)
        } else {
            None
        }
    }

    pub fn last_lockout(&self) -> Option<&Lockout> {
        self.votes.back().map(|vote| &vote.lockout)
    }

    pub fn last_voted_slot(&self) -> Option<Slot> {
        self.last_lockout().map(|v| v.slot())
    }

    // Upto MAX_LOCKOUT_HISTORY many recent unexpired
    // vote slots pushed onto the stack.
    pub fn tower(&self) -> Vec<Slot> {
        self.votes.iter().map(|v| v.slot()).collect()
    }

    pub fn current_epoch(&self) -> Epoch {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().0
        }
    }

    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteState to the Rewards program to trade credits for lamports.
    pub fn credits(&self) -> u64 {
        if self.epoch_credits.is_empty() {
            0
        } else {
            self.epoch_credits.last().unwrap().1
        }
    }

    /// Number of "credits" owed to this account from the mining pool on a per-epoch basis,
    ///  starting from credits observed.
    /// Each tuple of (Epoch, u64, u64) is read as (epoch, credits, prev_credits), where
    ///   credits for each epoch is credits - prev_credits; while redundant this makes
    ///   calculating rewards over partial epochs nice and simple
    pub fn epoch_credits(&self) -> &Vec<(Epoch, u64, u64)> {
        &self.epoch_credits
    }

    pub fn set_new_authorized_voter<F>(
        &mut self,
        authorized_pubkey: &Pubkey,
        current_epoch: Epoch,
        target_epoch: Epoch,
        verify: F,
    ) -> Result<(), InstructionError>
    where
        F: Fn(Pubkey) -> Result<(), InstructionError>,
    {
        let epoch_authorized_voter = self.get_and_update_authorized_voter(current_epoch)?;
        verify(epoch_authorized_voter)?;

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if self.authorized_voters.contains(target_epoch) {
            return Err(VoteError::TooSoonToReauthorize.into());
        }

        // Get the latest authorized_voter
        let (latest_epoch, latest_authorized_pubkey) = self
            .authorized_voters
            .last()
            .ok_or(InstructionError::InvalidAccountData)?;

        // If we're not setting the same pubkey as authorized pubkey again,
        // then update the list of prior voters to mark the expiration
        // of the old authorized pubkey
        if latest_authorized_pubkey != authorized_pubkey {
            // Update the epoch ranges of authorized pubkeys that will be expired
            let epoch_of_last_authorized_switch =
                self.prior_voters.last().map(|range| range.2).unwrap_or(0);

            // target_epoch must:
            // 1) Be monotonically increasing due to the clock always
            //    moving forward
            // 2) not be equal to latest epoch otherwise this
            //    function would have returned TooSoonToReauthorize error
            //    above
            assert!(target_epoch > *latest_epoch);

            // Commit the new state
            self.prior_voters.append((
                *latest_authorized_pubkey,
                epoch_of_last_authorized_switch,
                target_epoch,
            ));
        }

        self.authorized_voters
            .insert(target_epoch, *authorized_pubkey);

        Ok(())
    }

    pub fn get_and_update_authorized_voter(
        &mut self,
        current_epoch: Epoch,
    ) -> Result<Pubkey, InstructionError> {
        let pubkey = self
            .authorized_voters
            .get_and_cache_authorized_voter_for_epoch(current_epoch)
            .ok_or(InstructionError::InvalidAccountData)?;
        self.authorized_voters
            .purge_authorized_voters(current_epoch);
        Ok(pubkey)
    }

    // Pop all recent votes that are not locked out at the next vote slot.  This
    // allows validators to switch forks once their votes for another fork have
    // expired. This also allows validators continue voting on recent blocks in
    // the same fork without increasing lockouts.
    pub fn pop_expired_votes(&mut self, next_vote_slot: Slot) {
        while let Some(vote) = self.last_lockout() {
            if !vote.is_locked_out_at_slot(next_vote_slot) {
                self.votes.pop_back();
            } else {
                break;
            }
        }
    }

    pub fn double_lockouts(&mut self) {
        let stack_depth = self.votes.len();
        for (i, v) in self.votes.iter_mut().enumerate() {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            if stack_depth >
                i.checked_add(v.confirmation_count() as usize)
                    .expect("`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`")
            {
                v.lockout.increase_confirmation_count(1);
            }
        }
    }

    pub fn process_timestamp(
        &mut self,
        slot: Slot,
        timestamp: UnixTimestamp,
    ) -> Result<(), VoteError> {
        if (slot < self.last_timestamp.slot || timestamp < self.last_timestamp.timestamp)
            || (slot == self.last_timestamp.slot
                && BlockTimestamp { slot, timestamp } != self.last_timestamp
                && self.last_timestamp.slot != 0)
        {
            return Err(VoteError::TimestampTooOld);
        }
        self.last_timestamp = BlockTimestamp { slot, timestamp };
        Ok(())
    }

    pub fn is_correct_size_and_initialized(data: &[u8]) -> bool {
        const VERSION_OFFSET: usize = 4;
        const DEFAULT_PRIOR_VOTERS_END: usize = VERSION_OFFSET + DEFAULT_PRIOR_VOTERS_OFFSET;
        data.len() == VoteState::size_of()
            && data[VERSION_OFFSET..DEFAULT_PRIOR_VOTERS_END] != [0; DEFAULT_PRIOR_VOTERS_OFFSET]
    }
}

pub mod serde_compact_vote_state_update {
    use {
        super::*,
        crate::{
            clock::{Slot, UnixTimestamp},
            serde_varint, short_vec,
            vote::state::Lockout,
        },
        serde::{Deserialize, Deserializer, Serialize, Serializer},
    };

    #[derive(Deserialize, Serialize, AbiExample)]
    struct LockoutOffset {
        #[serde(with = "serde_varint")]
        offset: Slot,
        confirmation_count: u8,
    }

    #[derive(Deserialize, Serialize)]
    struct CompactVoteStateUpdate {
        root: Slot,
        #[serde(with = "short_vec")]
        lockout_offsets: Vec<LockoutOffset>,
        hash: Hash,
        timestamp: Option<UnixTimestamp>,
    }

    pub fn serialize<S>(
        vote_state_update: &VoteStateUpdate,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let lockout_offsets = vote_state_update.lockouts.iter().scan(
            vote_state_update.root.unwrap_or_default(),
            |slot, lockout| {
                let Some(offset) = lockout.slot().checked_sub(*slot) else {
                    return Some(Err(serde::ser::Error::custom("Invalid vote lockout")));
                };
                let Ok(confirmation_count) = u8::try_from(lockout.confirmation_count()) else {
                    return Some(Err(serde::ser::Error::custom("Invalid confirmation count")));
                };
                let lockout_offset = LockoutOffset {
                    offset,
                    confirmation_count,
                };
                *slot = lockout.slot();
                Some(Ok(lockout_offset))
            },
        );
        let compact_vote_state_update = CompactVoteStateUpdate {
            root: vote_state_update.root.unwrap_or(Slot::MAX),
            lockout_offsets: lockout_offsets.collect::<Result<_, _>>()?,
            hash: vote_state_update.hash,
            timestamp: vote_state_update.timestamp,
        };
        compact_vote_state_update.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VoteStateUpdate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CompactVoteStateUpdate {
            root,
            lockout_offsets,
            hash,
            timestamp,
        } = CompactVoteStateUpdate::deserialize(deserializer)?;
        let root = (root != Slot::MAX).then_some(root);
        let lockouts =
            lockout_offsets
                .iter()
                .scan(root.unwrap_or_default(), |slot, lockout_offset| {
                    *slot = match slot.checked_add(lockout_offset.offset) {
                        None => {
                            return Some(Err(serde::de::Error::custom("Invalid lockout offset")))
                        }
                        Some(slot) => slot,
                    };
                    let lockout = Lockout::new_with_confirmation_count(
                        *slot,
                        u32::from(lockout_offset.confirmation_count),
                    );
                    Some(Ok(lockout))
                });
        Ok(VoteStateUpdate {
            root,
            lockouts: lockouts.collect::<Result<_, _>>()?,
            hash,
            timestamp,
        })
    }
}
