use {
    crate::metrics::submit_counter,
    log::*,
    solana_sdk::timing,
    std::{
        env,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
        time::SystemTime,
    },
};

const DEFAULT_LOG_RATE: usize = 1000;
// Submit a datapoint every second by default
const DEFAULT_METRICS_RATE: u64 = 1000;

pub struct Counter {
    pub name: &'static str,
    /// total accumulated value
    pub counts: AtomicUsize,
    pub times: AtomicUsize,
    /// last accumulated value logged
    pub lastlog: AtomicUsize,
    pub lograte: AtomicUsize,
    pub metricsrate: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct CounterPoint {
    pub name: &'static str,
    pub count: i64,
    pub timestamp: SystemTime,
}

impl CounterPoint {
    pub fn new(name: &'static str) -> Self {
        CounterPoint {
            name,
            count: 0,
            timestamp: std::time::UNIX_EPOCH,
        }
    }
}

#[macro_export]
macro_rules! create_counter {
    ($name:expr, $lograte:expr, $metricsrate:expr) => {
        $crate::counter::Counter {
            name: $name,
            counts: std::sync::atomic::AtomicUsize::new(0),
            times: std::sync::atomic::AtomicUsize::new(0),
            lastlog: std::sync::atomic::AtomicUsize::new(0),
            lograte: std::sync::atomic::AtomicUsize::new($lograte),
            metricsrate: std::sync::atomic::AtomicU64::new($metricsrate),
        }
    };
}

#[macro_export]
macro_rules! inc_counter {
    ($name:expr, $level:expr, $count:expr) => {
        unsafe { $name.inc($level, $count) };
    };
}

#[macro_export]
macro_rules! inc_counter_info {
    ($name:expr, $count:expr) => {
        unsafe {
            if log_enabled!(log::Level::Info) {
                $name.inc(log::Level::Info, $count)
            }
        };
    };
}

#[macro_export]
macro_rules! inc_new_counter {
    ($name:expr, $count:expr, $level:expr, $lograte:expr, $metricsrate:expr) => {{
        if log_enabled!($level) {
            static mut INC_NEW_COUNTER: $crate::counter::Counter =
                create_counter!($name, $lograte, $metricsrate);
            static INIT_HOOK: std::sync::Once = std::sync::Once::new();
            unsafe {
                INIT_HOOK.call_once(|| {
                    INC_NEW_COUNTER.init();
                });
            }
            inc_counter!(INC_NEW_COUNTER, $level, $count);
        }
    }};
}

#[macro_export]
macro_rules! inc_new_counter_error {
    ($name:expr, $count:expr) => {{
        inc_new_counter!($name, $count, log::Level::Error, 0, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr) => {{
        inc_new_counter!($name, $count, log::Level::Error, $lograte, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr, $metricsrate:expr) => {{
        inc_new_counter!($name, $count, log::Level::Error, $lograte, $metricsrate);
    }};
}

#[macro_export]
macro_rules! inc_new_counter_warn {
    ($name:expr, $count:expr) => {{
        inc_new_counter!($name, $count, log::Level::Warn, 0, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr) => {{
        inc_new_counter!($name, $count, log::Level::Warn, $lograte, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr, $metricsrate:expr) => {{
        inc_new_counter!($name, $count, log::Level::Warn, $lograte, $metricsrate);
    }};
}

#[macro_export]
macro_rules! inc_new_counter_info {
    ($name:expr, $count:expr) => {{
        inc_new_counter!($name, $count, log::Level::Info, 0, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr) => {{
        inc_new_counter!($name, $count, log::Level::Info, $lograte, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr, $metricsrate:expr) => {{
        inc_new_counter!($name, $count, log::Level::Info, $lograte, $metricsrate);
    }};
}

#[macro_export]
macro_rules! inc_new_counter_debug {
    ($name:expr, $count:expr) => {{
        inc_new_counter!($name, $count, log::Level::Debug, 0, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr) => {{
        inc_new_counter!($name, $count, log::Level::Debug, $lograte, 0);
    }};
    ($name:expr, $count:expr, $lograte:expr, $metricsrate:expr) => {{
        inc_new_counter!($name, $count, log::Level::Debug, $lograte, $metricsrate);
    }};
}

impl Counter {
    fn default_metrics_rate() -> u64 {
        let v = env::var("SOLANA_DEFAULT_METRICS_RATE")
            .map(|x| x.parse().unwrap_or(0))
            .unwrap_or(0);
        if v == 0 {
            DEFAULT_METRICS_RATE
        } else {
            v
        }
    }
    fn default_log_rate() -> usize {
        let v = env::var("SOLANA_DEFAULT_LOG_RATE")
            .map(|x| x.parse().unwrap_or(DEFAULT_LOG_RATE))
            .unwrap_or(DEFAULT_LOG_RATE);
        if v == 0 {
            DEFAULT_LOG_RATE
        } else {
            v
        }
    }
    pub fn init(&mut self) {
        #![allow(deprecated)]
        self.lograte
            .compare_and_swap(0, Self::default_log_rate(), Ordering::Relaxed);
        self.metricsrate
            .compare_and_swap(0, Self::default_metrics_rate(), Ordering::Relaxed);
    }
    pub fn inc(&mut self, level: log::Level, events: usize) {
        let now = timing::timestamp();
        let counts = self.counts.fetch_add(events, Ordering::Relaxed);
        let times = self.times.fetch_add(1, Ordering::Relaxed);
        let lograte = self.lograte.load(Ordering::Relaxed);
        let metricsrate = self.metricsrate.load(Ordering::Relaxed);

        if times % lograte == 0 && times > 0 && log_enabled!(level) {
            log!(level,
                "COUNTER:{{\"name\": \"{}\", \"counts\": {}, \"samples\": {},  \"now\": {}, \"events\": {}}}",
                self.name,
                counts + events,
                times,
                now,
                events,
            );
        }

        let lastlog = self.lastlog.load(Ordering::Relaxed);
        #[allow(deprecated)]
        let prev = self
            .lastlog
            .compare_and_swap(lastlog, counts, Ordering::Relaxed);
        if prev == lastlog {
            let bucket = now / metricsrate;
            let counter = CounterPoint {
                name: self.name,
                count: counts as i64 - lastlog as i64,
                timestamp: SystemTime::now(),
            };
            submit_counter(counter, level, bucket);
        }
    }
}