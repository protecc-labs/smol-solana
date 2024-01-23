//! Utility to deduplicate baches of incoming network packets.

use {
    crate::packet::{Packet, PacketBatch},
    ahash::RandomState,
    rand::Rng,
    std::{
        hash::{BuildHasher, Hash, Hasher},
        iter::repeat_with,
        marker::PhantomData,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    },
};

pub struct Deduper<const K: usize, T: ?Sized> {
    num_bits: u64,
    bits: Vec<AtomicU64>,
    state: [RandomState; K],
    clock: Instant,
    popcount: AtomicU64, // Number of one bits in self.bits.
    _phantom: PhantomData<T>,
}

impl<const K: usize, T: ?Sized + Hash> Deduper<K, T> {
    pub fn new<R: Rng>(rng: &mut R, num_bits: u64) -> Self {
        let size = num_bits.checked_add(63).unwrap() / 64;
        let size = usize::try_from(size).unwrap();
        Self {
            num_bits,
            state: std::array::from_fn(|_| new_random_state(rng)),
            clock: Instant::now(),
            bits: repeat_with(AtomicU64::default).take(size).collect(),
            popcount: AtomicU64::default(),
            _phantom: PhantomData::<T>,
        }
    }

    fn false_positive_rate(&self) -> f64 {
        let popcount = self.popcount.load(Ordering::Relaxed);
        let ones_ratio = popcount.min(self.num_bits) as f64 / self.num_bits as f64;
        ones_ratio.powi(K as i32)
    }

    /// Resets the Deduper if either it is older than the reset_cycle or it is
    /// saturated enough that false positive rate exceeds specified threshold.
    /// Returns true if the deduper was saturated.
    pub fn maybe_reset<R: Rng>(
        &mut self,
        rng: &mut R,
        false_positive_rate: f64,
        reset_cycle: Duration,
    ) -> bool {
        assert!(0.0 < false_positive_rate && false_positive_rate < 1.0);
        let saturated = self.false_positive_rate() >= false_positive_rate;
        if saturated || self.clock.elapsed() >= reset_cycle {
            self.state = std::array::from_fn(|_| new_random_state(rng));
            self.clock = Instant::now();
            self.bits.fill_with(AtomicU64::default);
            self.popcount = AtomicU64::default();
        }
        saturated
    }

    // Returns true if the data is duplicate.
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn dedup(&self, data: &T) -> bool {
        let mut out = true;
        let hashers = self.state.iter().map(RandomState::build_hasher);
        for mut hasher in hashers {
            data.hash(&mut hasher);
            let hash: u64 = hasher.finish() % self.num_bits;
            let index = (hash >> 6) as usize;
            let mask: u64 = 1u64 << (hash & 63);
            let old = self.bits[index].fetch_or(mask, Ordering::Relaxed);
            if old & mask == 0u64 {
                self.popcount.fetch_add(1, Ordering::Relaxed);
                out = false;
            }
        }
        out
    }
}

fn new_random_state<R: Rng>(rng: &mut R) -> RandomState {
    RandomState::with_seeds(rng.gen(), rng.gen(), rng.gen(), rng.gen())
}

pub fn dedup_packets_and_count_discards<const K: usize>(
    deduper: &Deduper<K, [u8]>,
    batches: &mut [PacketBatch],
    mut process_received_packet: impl FnMut(&mut Packet, bool, bool),
) -> u64 {
    batches
        .iter_mut()
        .flat_map(PacketBatch::iter_mut)
        .map(|packet| {
            if packet.meta().discard() {
                process_received_packet(packet, true, false);
            } else if packet
                .data(..)
                .map(|data| deduper.dedup(data))
                .unwrap_or(true)
            {
                packet.meta_mut().set_discard(true);
                process_received_packet(packet, false, true);
            } else {
                process_received_packet(packet, false, false);
            }
            u64::from(packet.meta().discard())
        })
        .sum()
}
