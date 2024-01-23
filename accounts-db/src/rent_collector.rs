//! calculate and collect rent from Accounts
use solana_sdk::{
    account::{AccountSharedData, ReadableAccount, WritableAccount},
    clock::Epoch,
    epoch_schedule::EpochSchedule,
    genesis_config::GenesisConfig,
    incinerator,
    pubkey::Pubkey,
    rent::{Rent, RentDue},
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, AbiExample)]
pub struct RentCollector {
    pub epoch: Epoch,
    pub epoch_schedule: EpochSchedule,
    pub slots_per_year: f64,
    pub rent: Rent,
}

impl Default for RentCollector {
    fn default() -> Self {
        Self {
            epoch: Epoch::default(),
            epoch_schedule: EpochSchedule::default(),
            // derive default value using GenesisConfig::default()
            slots_per_year: GenesisConfig::default().slots_per_year(),
            rent: Rent::default(),
        }
    }
}

/// When rent is collected from an exempt account, rent_epoch is set to this
/// value. The idea is to have a fixed, consistent value for rent_epoch for all accounts that do not collect rent.
/// This enables us to get rid of the field completely.
pub const RENT_EXEMPT_RENT_EPOCH: Epoch = Epoch::MAX;

/// when rent is collected for this account, this is the action to apply to the account
#[derive(Debug)]
enum RentResult {
    /// this account will never have rent collected from it
    Exempt,
    /// maybe we collect rent later, but not now
    NoRentCollectionNow,
    /// collect rent
    CollectRent {
        new_rent_epoch: Epoch,
        rent_due: u64, // lamports, could be 0
    },
}

impl RentCollector {
    pub fn new(
        epoch: Epoch,
        epoch_schedule: EpochSchedule,
        slots_per_year: f64,
        rent: Rent,
    ) -> Self {
        Self {
            epoch,
            epoch_schedule,
            slots_per_year,
            rent,
        }
    }

    pub fn clone_with_epoch(&self, epoch: Epoch) -> Self {
        Self {
            epoch,
            ..self.clone()
        }
    }

    /// true if it is easy to determine this account should consider having rent collected from it
    pub fn should_collect_rent(&self, address: &Pubkey, account: &impl ReadableAccount) -> bool {
        !(account.executable() // executable accounts must be rent-exempt balance
            || *address == incinerator::id())
    }

    /// given an account that 'should_collect_rent'
    /// returns (amount rent due, is_exempt_from_rent)
    pub fn get_rent_due(&self, account: &impl ReadableAccount) -> RentDue {
        if self
            .rent
            .is_exempt(account.lamports(), account.data().len())
        {
            RentDue::Exempt
        } else {
            let account_rent_epoch = account.rent_epoch();
            let slots_elapsed: u64 = (account_rent_epoch..=self.epoch)
                .map(|epoch| self.epoch_schedule.get_slots_in_epoch(epoch + 1))
                .sum();

            // avoid infinite rent in rust 1.45
            let years_elapsed = if self.slots_per_year != 0.0 {
                slots_elapsed as f64 / self.slots_per_year
            } else {
                0.0
            };

            // we know this account is not exempt
            let due = self.rent.due_amount(account.data().len(), years_elapsed);
            RentDue::Paying(due)
        }
    }

    // Updates the account's lamports and status, and returns the amount of rent collected, if any.
    // This is NOT thread safe at some level. If we try to collect from the same account in
    // parallel, we may collect twice.
    #[must_use = "add to Bank::collected_rent"]
    pub fn collect_from_existing_account(
        &self,
        address: &Pubkey,
        account: &mut AccountSharedData,
        set_exempt_rent_epoch_max: bool,
    ) -> CollectedInfo {
        match self.calculate_rent_result(address, account) {
            RentResult::Exempt => {
                if set_exempt_rent_epoch_max {
                    account.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
                }
                CollectedInfo::default()
            }
            RentResult::NoRentCollectionNow => CollectedInfo::default(),
            RentResult::CollectRent {
                new_rent_epoch,
                rent_due,
            } => match account.lamports().checked_sub(rent_due) {
                None | Some(0) => {
                    let account = std::mem::take(account);
                    CollectedInfo {
                        rent_amount: account.lamports(),
                        account_data_len_reclaimed: account.data().len() as u64,
                    }
                }
                Some(lamports) => {
                    account.set_lamports(lamports);
                    account.set_rent_epoch(new_rent_epoch);
                    CollectedInfo {
                        rent_amount: rent_due,
                        account_data_len_reclaimed: 0u64,
                    }
                }
            },
        }
    }

    /// determine what should happen to collect rent from this account
    #[must_use]
    fn calculate_rent_result(
        &self,
        address: &Pubkey,
        account: &impl ReadableAccount,
    ) -> RentResult {
        if account.rent_epoch() == RENT_EXEMPT_RENT_EPOCH || account.rent_epoch() > self.epoch {
            // potentially rent paying account (or known and already marked exempt)
            // Maybe collect rent later, leave account alone for now.
            return RentResult::NoRentCollectionNow;
        }
        if !self.should_collect_rent(address, account) {
            // easy to determine this account should not consider having rent collected from it
            return RentResult::Exempt;
        }
        match self.get_rent_due(account) {
            // account will not have rent collected ever
            RentDue::Exempt => RentResult::Exempt,
            // potentially rent paying account
            // Maybe collect rent later, leave account alone for now.
            RentDue::Paying(0) => RentResult::NoRentCollectionNow,
            // Rent is collected for next epoch.
            RentDue::Paying(rent_due) => RentResult::CollectRent {
                new_rent_epoch: self.epoch + 1,
                rent_due,
            },
        }
    }
}

/// Information computed during rent collection
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct CollectedInfo {
    /// Amount of rent collected from account
    pub rent_amount: u64,
    /// Size of data reclaimed from account (happens when account's lamports go to zero)
    pub account_data_len_reclaimed: u64,
}

impl std::ops::Add for CollectedInfo {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            rent_amount: self.rent_amount + other.rent_amount,
            account_data_len_reclaimed: self.account_data_len_reclaimed
                + other.account_data_len_reclaimed,
        }
    }
}

impl std::ops::AddAssign for CollectedInfo {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}