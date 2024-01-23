use {
    crate::{
        nonblocking::quic::ConnectionPeerType,
        quic::{StreamStats, MAX_UNSTAKED_CONNECTIONS},
    },
    percentage::Percentage,
    std::{
        cmp,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, RwLock,
        },
        time::{Duration, Instant},
    },
};

/// Limit to 250K PPS
const MAX_STREAMS_PER_MS: u64 = 250;
const MAX_UNSTAKED_STREAMS_PERCENT: u64 = 20;
const STREAM_THROTTLING_INTERVAL_MS: u64 = 100;
pub const STREAM_STOP_CODE_THROTTLING: u32 = 15;
const STREAM_LOAD_EMA_INTERVAL_MS: u64 = 5;
const STREAM_LOAD_EMA_INTERVAL_COUNT: u64 = 10;
const EMA_WINDOW_MS: u64 = STREAM_LOAD_EMA_INTERVAL_MS * STREAM_LOAD_EMA_INTERVAL_COUNT;

pub(crate) struct StakedStreamLoadEMA {
    current_load_ema: AtomicU64,
    load_in_recent_interval: AtomicU64,
    last_update: RwLock<Instant>,
    stats: Arc<StreamStats>,
    // Maximum number of streams for a staked connection in EMA window
    // Note: EMA window can be different than stream throttling window. EMA is being calculated
    //       specifically for staked connections. Unstaked connections have fixed limit on
    //       stream load, which is tracked by `max_unstaked_load_in_throttling_window` field.
    max_staked_load_in_ema_window: u64,
    // Maximum number of streams for an unstaked connection in stream throttling window
    max_unstaked_load_in_throttling_window: u64,
}

impl StakedStreamLoadEMA {
    pub(crate) fn new(allow_unstaked_streams: bool, stats: Arc<StreamStats>) -> Self {
        let max_staked_load_in_ema_window = if allow_unstaked_streams {
            (MAX_STREAMS_PER_MS
                - Percentage::from(MAX_UNSTAKED_STREAMS_PERCENT).apply_to(MAX_STREAMS_PER_MS))
                * EMA_WINDOW_MS
        } else {
            MAX_STREAMS_PER_MS * EMA_WINDOW_MS
        };

        let max_num_unstaked_connections =
            u64::try_from(MAX_UNSTAKED_CONNECTIONS).unwrap_or_else(|_| {
                error!(
                    "Failed to convert maximum number of unstaked connections {} to u64.",
                    MAX_UNSTAKED_CONNECTIONS
                );
                500
            });

        let max_unstaked_load_in_throttling_window = Percentage::from(MAX_UNSTAKED_STREAMS_PERCENT)
            .apply_to(MAX_STREAMS_PER_MS * STREAM_THROTTLING_INTERVAL_MS)
            .saturating_div(max_num_unstaked_connections);

        Self {
            current_load_ema: AtomicU64::default(),
            load_in_recent_interval: AtomicU64::default(),
            last_update: RwLock::new(Instant::now()),
            stats,
            max_staked_load_in_ema_window,
            max_unstaked_load_in_throttling_window,
        }
    }

    fn ema_function(current_ema: u128, recent_load: u128) -> u128 {
        // Using the EMA multiplier helps in avoiding the floating point math during EMA related calculations
        const STREAM_LOAD_EMA_MULTIPLIER: u128 = 1024;
        let multiplied_smoothing_factor: u128 =
            2 * STREAM_LOAD_EMA_MULTIPLIER / (u128::from(STREAM_LOAD_EMA_INTERVAL_COUNT) + 1);

        // The formula is
        //    updated_ema = recent_load * smoothing_factor + current_ema * (1 - smoothing_factor)
        // To avoid floating point math, we are using STREAM_LOAD_EMA_MULTIPLIER
        //    updated_ema = (recent_load * multiplied_smoothing_factor
        //                   + current_ema * (multiplier - multiplied_smoothing_factor)) / multiplier
        (recent_load * multiplied_smoothing_factor
            + current_ema * (STREAM_LOAD_EMA_MULTIPLIER - multiplied_smoothing_factor))
            / STREAM_LOAD_EMA_MULTIPLIER
    }

    fn update_ema(&self, time_since_last_update_ms: u128) {
        // if time_since_last_update_ms > STREAM_LOAD_EMA_INTERVAL_MS, there might be intervals where ema was not updated.
        // count how many updates (1 + missed intervals) are needed.
        let num_extra_updates =
            time_since_last_update_ms.saturating_sub(1) / u128::from(STREAM_LOAD_EMA_INTERVAL_MS);

        let load_in_recent_interval =
            u128::from(self.load_in_recent_interval.swap(0, Ordering::Relaxed));

        let mut updated_load_ema = Self::ema_function(
            u128::from(self.current_load_ema.load(Ordering::Relaxed)),
            load_in_recent_interval,
        );

        for _ in 0..num_extra_updates {
            updated_load_ema = Self::ema_function(updated_load_ema, load_in_recent_interval);
        }

        let Ok(updated_load_ema) = u64::try_from(updated_load_ema) else {
            error!(
                "Failed to convert EMA {} to a u64. Not updating the load EMA",
                updated_load_ema
            );
            self.stats
                .stream_load_ema_overflow
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        self.current_load_ema
            .store(updated_load_ema, Ordering::Relaxed);
        self.stats
            .stream_load_ema
            .store(updated_load_ema as usize, Ordering::Relaxed);
    }

    pub(crate) fn update_ema_if_needed(&self) {
        const EMA_DURATION: Duration = Duration::from_millis(STREAM_LOAD_EMA_INTERVAL_MS);
        // Read lock enables multiple connection handlers to run in parallel if interval is not expired
        if Instant::now().duration_since(*self.last_update.read().unwrap()) >= EMA_DURATION {
            let mut last_update_w = self.last_update.write().unwrap();
            // Recheck as some other thread might have updated the ema since this thread tried to acquire the write lock.
            let since_last_update = Instant::now().duration_since(*last_update_w);
            if since_last_update >= EMA_DURATION {
                *last_update_w = Instant::now();
                self.update_ema(since_last_update.as_millis());
            }
        }
    }

    pub(crate) fn increment_load(&self, peer_type: ConnectionPeerType) {
        if peer_type.is_staked() {
            self.load_in_recent_interval.fetch_add(1, Ordering::Relaxed);
        }
        self.update_ema_if_needed();
    }

    pub(crate) fn available_load_capacity_in_throttling_duration(
        &self,
        peer_type: ConnectionPeerType,
        total_stake: u64,
    ) -> u64 {
        match peer_type {
            ConnectionPeerType::Unstaked => self.max_unstaked_load_in_throttling_window,
            ConnectionPeerType::Staked(stake) => {
                // If the current load is low, cap it to 25% of max_load.
                let current_load = u128::from(cmp::max(
                    self.current_load_ema.load(Ordering::Relaxed),
                    self.max_staked_load_in_ema_window / 4,
                ));

                // Formula is (max_load ^ 2 / current_load) * (stake / total_stake)
                let capacity_in_ema_window = (u128::from(self.max_staked_load_in_ema_window)
                    * u128::from(self.max_staked_load_in_ema_window)
                    * u128::from(stake))
                    / (current_load * u128::from(total_stake));

                let calculated_capacity = capacity_in_ema_window
                    * u128::from(STREAM_THROTTLING_INTERVAL_MS)
                    / u128::from(EMA_WINDOW_MS);
                let calculated_capacity = u64::try_from(calculated_capacity).unwrap_or_else(|_| {
                    error!(
                        "Failed to convert stream capacity {} to u64. Using minimum load capacity",
                        calculated_capacity
                    );
                    self.stats
                        .stream_load_capacity_overflow
                        .fetch_add(1, Ordering::Relaxed);
                    self.max_unstaked_load_in_throttling_window
                        .saturating_add(1)
                });

                // 1 is added to `max_unstaked_load_in_throttling_window` to guarantee that staked
                // clients get at least 1 more number of streams than unstaked connections.
                cmp::max(
                    calculated_capacity,
                    self.max_unstaked_load_in_throttling_window
                        .saturating_add(1),
                )
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionStreamCounter {
    pub(crate) stream_count: AtomicU64,
    last_throttling_instant: RwLock<tokio::time::Instant>,
}

impl ConnectionStreamCounter {
    pub(crate) fn new() -> Self {
        Self {
            stream_count: AtomicU64::default(),
            last_throttling_instant: RwLock::new(tokio::time::Instant::now()),
        }
    }

    pub(crate) fn reset_throttling_params_if_needed(&self) {
        const THROTTLING_INTERVAL: Duration = Duration::from_millis(STREAM_THROTTLING_INTERVAL_MS);
        if tokio::time::Instant::now().duration_since(*self.last_throttling_instant.read().unwrap())
            > THROTTLING_INTERVAL
        {
            let mut last_throttling_instant = self.last_throttling_instant.write().unwrap();
            // Recheck as some other thread might have done throttling since this thread tried to acquire the write lock.
            if tokio::time::Instant::now().duration_since(*last_throttling_instant)
                > THROTTLING_INTERVAL
            {
                *last_throttling_instant = tokio::time::Instant::now();
                self.stream_count.store(0, Ordering::Relaxed);
            }
        }
    }
}
