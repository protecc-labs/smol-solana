//! A type to hold data for the [`EpochRewards` sysvar][sv].
//!
//! [sv]: https://docs.solanalabs.com/runtime/sysvars#epochrewards
//!
//! The sysvar ID is declared in [`sysvar::epoch_rewards`].
//!
//! [`sysvar::epoch_rewards`]: crate::sysvar::epoch_rewards

use std::ops::AddAssign;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default, Clone, Copy, AbiExample)]
pub struct EpochRewards {
    /// total rewards for the current epoch, in lamports
    pub total_rewards: u64,

    /// distributed rewards for the current epoch, in lamports
    pub distributed_rewards: u64,

    /// distribution of all staking rewards for the current
    /// epoch will be completed at this block height
    pub distribution_complete_block_height: u64,
}

impl EpochRewards {
    pub fn distribute(&mut self, amount: u64) {
        assert!(self.distributed_rewards.saturating_add(amount) <= self.total_rewards);

        self.distributed_rewards.add_assign(amount);
    }
}
