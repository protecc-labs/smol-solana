//! The `timing` module provides std::time utility functions.
use {
    crate::unchecked_div_by_const,
    std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

pub fn duration_as_ns(d: &Duration) -> u64 {
    d.as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(d.subsec_nanos()))
}

pub fn duration_as_us(d: &Duration) -> u64 {
    d.as_secs()
        .saturating_mul(1_000_000)
        .saturating_add(unchecked_div_by_const!(u64::from(d.subsec_nanos()), 1_000))
}

pub fn duration_as_ms(d: &Duration) -> u64 {
    d.as_secs()
        .saturating_mul(1000)
        .saturating_add(unchecked_div_by_const!(
            u64::from(d.subsec_nanos()),
            1_000_000
        ))
}

pub fn duration_as_s(d: &Duration) -> f32 {
    d.as_secs() as f32 + (d.subsec_nanos() as f32 / 1_000_000_000.0)
}

/// return timestamp as ms
pub fn timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("create timestamp in timing");
    duration_as_ms(&now)
}

pub const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;

/// from years to slots
pub fn years_as_slots(years: f64, tick_duration: &Duration, ticks_per_slot: u64) -> f64 {
    // slots is  years * slots/year
    years       *
    //  slots/year  is  seconds/year ...
        SECONDS_PER_YEAR
    //  * (ns/s)/(ns/tick) / ticks/slot = 1/s/1/tick = ticks/s
        * (1_000_000_000.0 / duration_as_ns(tick_duration) as f64)
    //  / ticks/slot
        / ticks_per_slot as f64
}

/// From slots per year to slot duration
pub fn slot_duration_from_slots_per_year(slots_per_year: f64) -> Duration {
    // Recently, rust changed from infinity as usize being zero to 2^64-1; ensure it's zero here
    let slot_in_ns = if slots_per_year != 0.0 {
        (SECONDS_PER_YEAR * 1_000_000_000.0) / slots_per_year
    } else {
        0.0
    };
    Duration::from_nanos(slot_in_ns as u64)
}

#[derive(Debug, Default)]
pub struct AtomicInterval {
    last_update: AtomicU64,
}

impl AtomicInterval {
    /// true if 'interval_time_ms' has elapsed since last time we returned true as long as it has been 'interval_time_ms' since this struct was created
    pub fn should_update(&self, interval_time_ms: u64) -> bool {
        self.should_update_ext(interval_time_ms, true)
    }

    /// a primary use case is periodic metric reporting, potentially from different threads
    /// true if 'interval_time_ms' has elapsed since last time we returned true
    /// except, if skip_first=false, false until 'interval_time_ms' has elapsed since this struct was created
    pub fn should_update_ext(&self, interval_time_ms: u64, skip_first: bool) -> bool {
        let now = timestamp();
        let last = self.last_update.load(Ordering::Relaxed);
        now.saturating_sub(last) > interval_time_ms
            && self
                .last_update
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                == Ok(last)
            && !(skip_first && last == 0)
    }

    /// return ms elapsed since the last time the time was set
    pub fn elapsed_ms(&self) -> u64 {
        let now = timestamp();
        let last = self.last_update.load(Ordering::Relaxed);
        now.saturating_sub(last) // wrapping somehow?
    }

    /// return ms until the interval_time will have elapsed
    pub fn remaining_until_next_interval(&self, interval_time: u64) -> u64 {
        interval_time.saturating_sub(self.elapsed_ms())
    }
}
