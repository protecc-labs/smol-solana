//! Stats for Accounts Background Services

use {
    solana_metrics::datapoint_info,
    std::time::{Duration, Instant},
};

const SUBMIT_INTERVAL: Duration = Duration::from_secs(60);

/// Manage the Accounts Background Service stats
///
/// Used to record the stats and submit the datapoints.
#[derive(Debug)]
pub(super) struct StatsManager {
    stats: Stats,
    previous_submit: Instant,
}

impl StatsManager {
    /// Make a new StatsManager
    #[must_use]
    pub(super) fn new() -> Self {
        Self {
            stats: Stats::default(),
            previous_submit: Instant::now(),
        }
    }

    /// Record stats from this iteration, and maybe submit the datapoints based on how long it has
    /// been since the previous submission.
    pub(super) fn record_and_maybe_submit(&mut self, runtime: Duration) {
        self.stats.record(runtime);
        self.maybe_submit();
    }

    /// Maybe submit the datapoints based on how long it has been since the previous submission.
    fn maybe_submit(&mut self) {
        let duration_since_previous_submit = Instant::now() - self.previous_submit;
        if duration_since_previous_submit < SUBMIT_INTERVAL {
            return;
        }

        datapoint_info!(
            "accounts_background_service",
            (
                "duration_since_previous_submit_us",
                duration_since_previous_submit.as_micros(),
                i64
            ),
            ("num_iterations", self.stats.num_iterations, i64),
            (
                "cumulative_runtime_us",
                self.stats.cumulative_runtime.as_micros(),
                i64
            ),
            (
                "mean_runtime_us",
                self.stats.mean_runtime().as_micros(),
                i64
            ),
            ("min_runtime_us", self.stats.min_runtime.as_micros(), i64),
            ("max_runtime_us", self.stats.max_runtime.as_micros(), i64),
        );

        // reset the stats back to default
        *self = Self::new();
    }
}

/// Stats for Accounts Background Services
///
/// Intended to record stats for each iteration of the ABS main loop.
#[derive(Debug)]
struct Stats {
    /// Number of iterations recorded
    num_iterations: usize,
    /// Total runtime of all iterations
    cumulative_runtime: Duration,
    /// Minimum runtime seen for one iteration
    min_runtime: Duration,
    /// Maximum runtime seen for one iteration
    max_runtime: Duration,
}

impl Stats {
    /// Record stats from this iteration
    fn record(&mut self, runtime: Duration) {
        self.num_iterations += 1;
        self.cumulative_runtime += runtime;
        self.min_runtime = self.min_runtime.min(runtime);
        self.max_runtime = self.max_runtime.max(runtime);
    }

    /// Calculate the mean runtime of all iterations
    ///
    /// Requires that the number of iterations recorded is in the range [0, u32::MAX].
    fn mean_runtime(&self) -> Duration {
        debug_assert!(self.num_iterations > 0);
        debug_assert!(self.num_iterations <= u32::MAX as usize);
        self.cumulative_runtime / self.num_iterations as u32
    }
}

impl Default for Stats {
    #[must_use]
    fn default() -> Self {
        Self {
            num_iterations: 0,
            cumulative_runtime: Duration::ZERO,
            min_runtime: Duration::MAX,
            max_runtime: Duration::ZERO,
        }
    }
}
