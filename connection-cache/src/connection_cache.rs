use {
    crate::{
        client_connection::ClientConnection as BlockingClientConnection,
        connection_cache_stats::{ConnectionCacheStats, CONNECTION_STAT_SUBMISSION_INTERVAL},
        nonblocking::client_connection::ClientConnection as NonblockingClientConnection,
    },
    crossbeam_channel::{Receiver, RecvError, Sender},
    indexmap::map::IndexMap,
    log::*,
    rand::{thread_rng, Rng},
    solana_measure::measure::Measure,
    solana_sdk::{signature::Keypair, timing::AtomicInterval},
    std::{
        net::SocketAddr,
        sync::{atomic::Ordering, Arc, RwLock},
        thread::{Builder, JoinHandle},
    },
    thiserror::Error,
};

// Should be non-zero
const MAX_CONNECTIONS: usize = 1024;

/// Default connection pool size per remote address
pub const DEFAULT_CONNECTION_POOL_SIZE: usize = 2;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum Protocol {
    UDP,
    QUIC,
}

pub trait ConnectionManager: Send + Sync + 'static {
    type ConnectionPool: ConnectionPool;
    type NewConnectionConfig: NewConnectionConfig;

    const PROTOCOL: Protocol;

    fn new_connection_pool(&self) -> Self::ConnectionPool;
    fn new_connection_config(&self) -> Self::NewConnectionConfig;
    fn update_key(&self, _key: &Keypair) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct ConnectionCache<
    R, // ConnectionPool
    S, // ConnectionManager
    T, // NewConnectionConfig
> {
    name: &'static str,
    map: Arc<RwLock<IndexMap<SocketAddr, /*ConnectionPool:*/ R>>>,
    connection_manager: Arc<S>,
    stats: Arc<ConnectionCacheStats>,
    last_stats: AtomicInterval,
    connection_pool_size: usize,
    connection_config: Arc<T>,
    sender: Sender<(usize, SocketAddr)>,
}

impl<P, M, C> ConnectionCache<P, M, C>
where
    P: ConnectionPool<NewConnectionConfig = C>,
    M: ConnectionManager<ConnectionPool = P, NewConnectionConfig = C>,
    C: NewConnectionConfig,
{
    pub fn new(
        name: &'static str,
        connection_manager: M,
        connection_pool_size: usize,
    ) -> Result<Self, ClientError> {
        let config = connection_manager.new_connection_config();
        Ok(Self::new_with_config(
            name,
            connection_pool_size,
            config,
            connection_manager,
        ))
    }

    pub fn new_with_config(
        name: &'static str,
        connection_pool_size: usize,
        connection_config: C,
        connection_manager: M,
    ) -> Self {
        info!("Creating ConnectionCache {name}, pool size: {connection_pool_size}");
        let (sender, receiver) = crossbeam_channel::unbounded();

        let map = Arc::new(RwLock::new(IndexMap::with_capacity(MAX_CONNECTIONS)));
        let config = Arc::new(connection_config);
        let connection_manager = Arc::new(connection_manager);
        let connection_pool_size = 1.max(connection_pool_size); // The minimum pool size is 1.

        let stats = Arc::new(ConnectionCacheStats::default());

        let _async_connection_thread =
            Self::create_connection_async_thread(map.clone(), receiver, stats.clone());
        Self {
            name,
            map,
            stats,
            connection_manager,
            last_stats: AtomicInterval::default(),
            connection_pool_size,
            connection_config: config,
            sender,
        }
    }

    /// This actually triggers the connection creation by sending empty data
    fn create_connection_async_thread(
        map: Arc<RwLock<IndexMap<SocketAddr, /*ConnectionPool:*/ P>>>,
        receiver: Receiver<(usize, SocketAddr)>,
        stats: Arc<ConnectionCacheStats>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("solQAsynCon".to_string())
            .spawn(move || loop {
                let recv_result = receiver.recv();
                match recv_result {
                    Err(RecvError) => {
                        break;
                    }
                    Ok((idx, addr)) => {
                        let map = map.read().unwrap();
                        let pool = map.get(&addr);
                        if let Some(pool) = pool {
                            let conn = pool.get(idx);
                            if let Ok(conn) = conn {
                                drop(map);
                                let conn = conn.new_blocking_connection(addr, stats.clone());
                                let result = conn.send_data(&[]);
                                debug!("Create async connection result {result:?} for {addr}");
                            }
                        }
                    }
                }
            })
            .unwrap()
    }

    pub fn update_key(&self, key: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = self.map.write().unwrap();
        map.clear();
        self.connection_manager.update_key(key)
    }
    /// Create a lazy connection object under the exclusive lock of the cache map if there is not
    /// enough used connections in the connection pool for the specified address.
    /// Returns CreateConnectionResult.
    fn create_connection(
        &self,
        lock_timing_ms: &mut u64,
        addr: &SocketAddr,
    ) -> CreateConnectionResult<<P as ConnectionPool>::BaseClientConnection> {
        let mut get_connection_map_lock_measure = Measure::start("get_connection_map_lock_measure");
        let mut map = self.map.write().unwrap();
        get_connection_map_lock_measure.stop();
        *lock_timing_ms = lock_timing_ms.saturating_add(get_connection_map_lock_measure.as_ms());
        // Read again, as it is possible that between read lock dropped and the write lock acquired
        // another thread could have setup the connection.

        let pool_status = map
            .get(addr)
            .map(|pool| pool.check_pool_status(self.connection_pool_size))
            .unwrap_or(PoolStatus::Empty);

        let (cache_hit, num_evictions, eviction_timing_ms) =
            if matches!(pool_status, PoolStatus::Empty) {
                Self::create_connection_internal(
                    &self.connection_config,
                    &self.connection_manager,
                    &mut map,
                    addr,
                    self.connection_pool_size,
                    None,
                )
            } else {
                (true, 0, 0)
            };

        if matches!(pool_status, PoolStatus::PartiallyFull) {
            // trigger an async connection create
            debug!("Triggering async connection for {addr:?}");
            Self::create_connection_internal(
                &self.connection_config,
                &self.connection_manager,
                &mut map,
                addr,
                self.connection_pool_size,
                Some(&self.sender),
            );
        }

        let pool = map.get(addr).unwrap();
        let connection = pool.borrow_connection();

        CreateConnectionResult {
            connection,
            cache_hit,
            connection_cache_stats: self.stats.clone(),
            num_evictions,
            eviction_timing_ms,
        }
    }

    fn create_connection_internal(
        config: &C,
        connection_manager: &M,
        map: &mut std::sync::RwLockWriteGuard<'_, IndexMap<SocketAddr, P>>,
        addr: &SocketAddr,
        connection_pool_size: usize,
        async_connection_sender: Option<&Sender<(usize, SocketAddr)>>,
    ) -> (bool, u64, u64) {
        // evict a connection if the cache is reaching upper bounds
        let mut num_evictions = 0;
        let mut get_connection_cache_eviction_measure =
            Measure::start("get_connection_cache_eviction_measure");
        let existing_index = map.get_index_of(addr);
        while map.len() >= MAX_CONNECTIONS {
            let mut rng = thread_rng();
            let n = rng.gen_range(0..MAX_CONNECTIONS);
            if let Some(index) = existing_index {
                if n == index {
                    continue;
                }
            }
            map.swap_remove_index(n);
            num_evictions += 1;
        }
        get_connection_cache_eviction_measure.stop();

        let mut hit_cache = false;
        map.entry(*addr)
            .and_modify(|pool| {
                if matches!(
                    pool.check_pool_status(connection_pool_size),
                    PoolStatus::PartiallyFull
                ) {
                    let idx = pool.add_connection(config, addr);
                    if let Some(sender) = async_connection_sender {
                        debug!(
                            "Sending async connection creation {} for {addr}",
                            pool.num_connections() - 1
                        );
                        sender.send((idx, *addr)).unwrap();
                    };
                } else {
                    hit_cache = true;
                }
            })
            .or_insert_with(|| {
                let mut pool = connection_manager.new_connection_pool();
                pool.add_connection(config, addr);
                pool
            });
        (
            hit_cache,
            num_evictions,
            get_connection_cache_eviction_measure.as_ms(),
        )
    }

    fn get_or_add_connection(
        &self,
        addr: &SocketAddr,
    ) -> GetConnectionResult<<P as ConnectionPool>::BaseClientConnection> {
        let mut get_connection_map_lock_measure = Measure::start("get_connection_map_lock_measure");
        let map = self.map.read().unwrap();
        get_connection_map_lock_measure.stop();

        let mut lock_timing_ms = get_connection_map_lock_measure.as_ms();

        let report_stats = self
            .last_stats
            .should_update(CONNECTION_STAT_SUBMISSION_INTERVAL);

        let mut get_connection_map_measure = Measure::start("get_connection_hit_measure");
        let CreateConnectionResult {
            connection,
            cache_hit,
            connection_cache_stats,
            num_evictions,
            eviction_timing_ms,
        } = match map.get(addr) {
            Some(pool) => {
                let pool_status = pool.check_pool_status(self.connection_pool_size);
                match pool_status {
                    PoolStatus::Empty => {
                        // create more connection and put it in the pool
                        drop(map);
                        self.create_connection(&mut lock_timing_ms, addr)
                    }
                    PoolStatus::PartiallyFull | PoolStatus::Full => {
                        let connection = pool.borrow_connection();
                        if matches!(pool_status, PoolStatus::PartiallyFull) {
                            debug!("Creating connection async for {addr}");
                            drop(map);
                            let mut map = self.map.write().unwrap();
                            Self::create_connection_internal(
                                &self.connection_config,
                                &self.connection_manager,
                                &mut map,
                                addr,
                                self.connection_pool_size,
                                Some(&self.sender),
                            );
                        }
                        CreateConnectionResult {
                            connection,
                            cache_hit: true,
                            connection_cache_stats: self.stats.clone(),
                            num_evictions: 0,
                            eviction_timing_ms: 0,
                        }
                    }
                }
            }
            None => {
                // Upgrade to write access by dropping read lock and acquire write lock
                drop(map);
                self.create_connection(&mut lock_timing_ms, addr)
            }
        };
        get_connection_map_measure.stop();

        GetConnectionResult {
            connection,
            cache_hit,
            report_stats,
            map_timing_ms: get_connection_map_measure.as_ms(),
            lock_timing_ms,
            connection_cache_stats,
            num_evictions,
            eviction_timing_ms,
        }
    }

    fn get_connection_and_log_stats(
        &self,
        addr: &SocketAddr,
    ) -> (
        Arc<<P as ConnectionPool>::BaseClientConnection>,
        Arc<ConnectionCacheStats>,
    ) {
        let mut get_connection_measure = Measure::start("get_connection_measure");
        let GetConnectionResult {
            connection,
            cache_hit,
            report_stats,
            map_timing_ms,
            lock_timing_ms,
            connection_cache_stats,
            num_evictions,
            eviction_timing_ms,
        } = self.get_or_add_connection(addr);

        if report_stats {
            connection_cache_stats.report(self.name);
        }

        if cache_hit {
            connection_cache_stats
                .cache_hits
                .fetch_add(1, Ordering::Relaxed);
            connection_cache_stats
                .get_connection_hit_ms
                .fetch_add(map_timing_ms, Ordering::Relaxed);
        } else {
            connection_cache_stats
                .cache_misses
                .fetch_add(1, Ordering::Relaxed);
            connection_cache_stats
                .get_connection_miss_ms
                .fetch_add(map_timing_ms, Ordering::Relaxed);
            connection_cache_stats
                .cache_evictions
                .fetch_add(num_evictions, Ordering::Relaxed);
            connection_cache_stats
                .eviction_time_ms
                .fetch_add(eviction_timing_ms, Ordering::Relaxed);
        }

        get_connection_measure.stop();
        connection_cache_stats
            .get_connection_lock_ms
            .fetch_add(lock_timing_ms, Ordering::Relaxed);
        connection_cache_stats
            .get_connection_ms
            .fetch_add(get_connection_measure.as_ms(), Ordering::Relaxed);

        (connection, connection_cache_stats)
    }

    pub fn get_connection(&self, addr: &SocketAddr) -> Arc<<<P as ConnectionPool>::BaseClientConnection as BaseClientConnection>::BlockingClientConnection>{
        let (connection, connection_cache_stats) = self.get_connection_and_log_stats(addr);
        connection.new_blocking_connection(*addr, connection_cache_stats)
    }

    pub fn get_nonblocking_connection(
        &self,
        addr: &SocketAddr,
    ) -> Arc<<<P as ConnectionPool>::BaseClientConnection as BaseClientConnection>::NonblockingClientConnection>{
        let (connection, connection_cache_stats) = self.get_connection_and_log_stats(addr);
        connection.new_nonblocking_connection(*addr, connection_cache_stats)
    }
}

#[derive(Error, Debug)]
pub enum ConnectionPoolError {
    #[error("connection index is out of range of the pool")]
    IndexOutOfRange,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Certificate error: {0}")]
    CertificateError(#[from] rcgen::Error),

    #[error("IO error: {0:?}")]
    IoError(#[from] std::io::Error),
}

pub trait NewConnectionConfig: Sized + Send + Sync + 'static {
    fn new() -> Result<Self, ClientError>;
}

pub enum PoolStatus {
    Empty,
    PartiallyFull,
    Full,
}

pub trait ConnectionPool: Send + Sync + 'static {
    type NewConnectionConfig: NewConnectionConfig;
    type BaseClientConnection: BaseClientConnection;

    /// Add a connection to the pool and return its index
    fn add_connection(&mut self, config: &Self::NewConnectionConfig, addr: &SocketAddr) -> usize;

    /// Get the number of current connections in the pool
    fn num_connections(&self) -> usize;

    /// Get a connection based on its index in the pool, without checking if the
    fn get(&self, index: usize) -> Result<Arc<Self::BaseClientConnection>, ConnectionPoolError>;

    /// Get a connection from the pool. It must have at least one connection in the pool.
    /// This randomly picks a connection in the pool.
    fn borrow_connection(&self) -> Arc<Self::BaseClientConnection> {
        let mut rng = thread_rng();
        let n = rng.gen_range(0..self.num_connections());
        self.get(n).expect("index is within num_connections")
    }

    /// Check if we need to create a new connection. If the count of the connections
    /// is smaller than the pool size and if there is no connection at all.
    fn check_pool_status(&self, required_pool_size: usize) -> PoolStatus {
        if self.num_connections() == 0 {
            PoolStatus::Empty
        } else if self.num_connections() < required_pool_size {
            PoolStatus::PartiallyFull
        } else {
            PoolStatus::Full
        }
    }

    fn create_pool_entry(
        &self,
        config: &Self::NewConnectionConfig,
        addr: &SocketAddr,
    ) -> Arc<Self::BaseClientConnection>;
}

pub trait BaseClientConnection {
    type BlockingClientConnection: BlockingClientConnection;
    type NonblockingClientConnection: NonblockingClientConnection;

    fn new_blocking_connection(
        &self,
        addr: SocketAddr,
        stats: Arc<ConnectionCacheStats>,
    ) -> Arc<Self::BlockingClientConnection>;

    fn new_nonblocking_connection(
        &self,
        addr: SocketAddr,
        stats: Arc<ConnectionCacheStats>,
    ) -> Arc<Self::NonblockingClientConnection>;
}

struct GetConnectionResult<T> {
    connection: Arc</*BaseClientConnection:*/ T>,
    cache_hit: bool,
    report_stats: bool,
    map_timing_ms: u64,
    lock_timing_ms: u64,
    connection_cache_stats: Arc<ConnectionCacheStats>,
    num_evictions: u64,
    eviction_timing_ms: u64,
}

struct CreateConnectionResult<T> {
    connection: Arc</*BaseClientConnection:*/ T>,
    cache_hit: bool,
    connection_cache_stats: Arc<ConnectionCacheStats>,
    num_evictions: u64,
    eviction_timing_ms: u64,
}
