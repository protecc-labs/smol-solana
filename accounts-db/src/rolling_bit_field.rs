//! functionally similar to a hashset
//! Relies on there being a sliding window of key values. The key values continue to increase.
//! Old key values are removed from the lesser values and do not accumulate.

mod iterators;
use {
    bv::BitVec, iterators::RollingBitFieldOnesIter, solana_nohash_hasher::IntSet,
    solana_sdk::clock::Slot,
};

#[derive(Debug, AbiExample, Clone)]
pub struct RollingBitField {
    max_width: u64,
    min: u64,
    max_exclusive: u64,
    bits: BitVec,
    count: usize,
    // These are items that are true and lower than min.
    // They would cause us to exceed max_width if we stored them in our bit field.
    // We only expect these items in conditions where there is some other bug in the system
    //  or in testing when large ranges are created.
    excess: IntSet<u64>,
}

impl PartialEq<RollingBitField> for RollingBitField {
    fn eq(&self, other: &Self) -> bool {
        // 2 instances could have different internal data for the same values,
        // so we have to compare data.
        self.len() == other.len() && {
            for item in self.get_all() {
                if !other.contains(&item) {
                    return false;
                }
            }
            true
        }
    }
}

/// functionally similar to a hashset
/// Relies on there being a sliding window of key values. The key values continue to increase.
/// Old key values are removed from the lesser values and do not accumulate.
impl RollingBitField {
    pub fn new(max_width: u64) -> Self {
        assert!(max_width > 0);
        assert!(max_width.is_power_of_two()); // power of 2 to make dividing a shift
        let bits = BitVec::new_fill(false, max_width);
        Self {
            max_width,
            bits,
            count: 0,
            min: 0,
            max_exclusive: 0,
            excess: IntSet::default(),
        }
    }

    // find the array index
    fn get_address(&self, key: &u64) -> u64 {
        key % self.max_width
    }

    pub fn range_width(&self) -> u64 {
        // note that max isn't updated on remove, so it can be above the current max
        self.max_exclusive - self.min
    }

    pub fn min(&self) -> Option<u64> {
        if self.is_empty() {
            None
        } else if self.excess.is_empty() {
            Some(self.min)
        } else {
            let excess_min = self.excess.iter().min().copied();
            if self.all_items_in_excess() {
                excess_min
            } else {
                Some(std::cmp::min(self.min, excess_min.unwrap_or(u64::MAX)))
            }
        }
    }

    pub fn insert(&mut self, key: u64) {
        let mut bits_empty = self.count == 0 || self.all_items_in_excess();
        let update_bits = if bits_empty {
            true // nothing in bits, so in range
        } else if key < self.min {
            // bits not empty and this insert is before min, so add to excess
            if self.excess.insert(key) {
                self.count += 1;
            }
            false
        } else if key < self.max_exclusive {
            true // fits current bit field range
        } else {
            // key is >= max
            let new_max = key + 1;
            loop {
                let new_width = new_max.saturating_sub(self.min);
                if new_width <= self.max_width {
                    // this key will fit the max range
                    break;
                }

                // move the min item from bits to excess and then purge from min to make room for this new max
                let inserted = self.excess.insert(self.min);
                assert!(inserted);

                let key = self.min;
                let address = self.get_address(&key);
                self.bits.set(address, false);
                self.purge(&key);

                if self.all_items_in_excess() {
                    // if we moved the last existing item to excess, then we are ready to insert the new item in the bits
                    bits_empty = true;
                    break;
                }
            }

            true // moved things to excess if necessary, so update bits with the new entry
        };

        if update_bits {
            let address = self.get_address(&key);
            let value = self.bits.get(address);
            if !value {
                self.bits.set(address, true);
                if bits_empty {
                    self.min = key;
                    self.max_exclusive = key + 1;
                } else {
                    self.min = std::cmp::min(self.min, key);
                    self.max_exclusive = std::cmp::max(self.max_exclusive, key + 1);
                    assert!(
                        self.min + self.max_width >= self.max_exclusive,
                        "min: {}, max: {}, max_width: {}",
                        self.min,
                        self.max_exclusive,
                        self.max_width
                    );
                }
                self.count += 1;
            }
        }
    }

    /// remove key from set, return if item was in the set
    pub fn remove(&mut self, key: &u64) -> bool {
        if key >= &self.min {
            // if asked to remove something bigger than max, then no-op
            if key < &self.max_exclusive {
                let address = self.get_address(key);
                let get = self.bits.get(address);
                if get {
                    self.count -= 1;
                    self.bits.set(address, false);
                    self.purge(key);
                }
                get
            } else {
                false
            }
        } else {
            // asked to remove something < min. would be in excess if it exists
            let remove = self.excess.remove(key);
            if remove {
                self.count -= 1;
            }
            remove
        }
    }

    fn all_items_in_excess(&self) -> bool {
        self.excess.len() == self.count
    }

    // after removing 'key' where 'key' = min, make min the correct new min value
    fn purge(&mut self, key: &u64) {
        if self.count > 0 && !self.all_items_in_excess() {
            if key == &self.min {
                let start = self.min + 1; // min just got removed
                for key in start..self.max_exclusive {
                    if self.contains_assume_in_range(&key) {
                        self.min = key;
                        break;
                    }
                }
            }
        } else {
            // The idea is that there are no items in the bitfield anymore.
            // But, there MAY be items in excess. The model works such that items < min go into excess.
            // So, after purging all items from bitfield, we hold max to be what it previously was, but set min to max.
            // Thus, if we lookup >= max, answer is always false without having to look in excess.
            // If we changed max here to 0, we would lose the ability to know the range of items in excess (if any).
            // So, now, with min updated = max:
            // If we lookup < max, then we first check min.
            // If >= min, then we look in bitfield.
            // Otherwise, we look in excess since the request is < min.
            // So, resetting min like this after a remove results in the correct behavior for the model.
            // Later, if we insert and there are 0 items total (excess + bitfield), then we reset min/max to reflect the new item only.
            self.min = self.max_exclusive;
        }
    }

    fn contains_assume_in_range(&self, key: &u64) -> bool {
        // the result may be aliased. Caller is responsible for determining key is in range.
        let address = self.get_address(key);
        self.bits.get(address)
    }

    // This is the 99% use case.
    // This needs be fast for the most common case of asking for key >= min.
    pub fn contains(&self, key: &u64) -> bool {
        if key < &self.max_exclusive {
            if key >= &self.min {
                // in the bitfield range
                self.contains_assume_in_range(key)
            } else {
                self.excess.contains(key)
            }
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn max_exclusive(&self) -> u64 {
        self.max_exclusive
    }

    pub fn max_inclusive(&self) -> u64 {
        self.max_exclusive.saturating_sub(1)
    }

    /// return all items < 'max_slot_exclusive'
    pub fn get_all_less_than(&self, max_slot_exclusive: Slot) -> Vec<u64> {
        let mut all = Vec::with_capacity(self.count);
        self.excess.iter().for_each(|slot| {
            if slot < &max_slot_exclusive {
                all.push(*slot)
            }
        });
        for key in self.min..self.max_exclusive {
            if key >= max_slot_exclusive {
                break;
            }

            if self.contains_assume_in_range(&key) {
                all.push(key);
            }
        }
        all
    }

    /// return highest item < 'max_slot_exclusive'
    pub fn get_prior(&self, max_slot_exclusive: Slot) -> Option<Slot> {
        let mut slot = max_slot_exclusive.saturating_sub(1);
        self.min().and_then(|min| {
            loop {
                if self.contains(&slot) {
                    return Some(slot);
                }
                slot = slot.saturating_sub(1);
                if slot == 0 || slot < min {
                    break;
                }
            }
            None
        })
    }

    pub fn get_all(&self) -> Vec<u64> {
        let mut all = Vec::with_capacity(self.count);
        self.excess.iter().for_each(|slot| all.push(*slot));
        for key in self.min..self.max_exclusive {
            if self.contains_assume_in_range(&key) {
                all.push(key);
            }
        }
        all
    }

    /// Returns an iterator over the rolling bit field
    ///
    /// The iterator yields all the 'set' bits.
    /// Note, the iteration order of the bits in 'excess' is not deterministic.
    pub fn iter_ones(&self) -> RollingBitFieldOnesIter<'_> {
        RollingBitFieldOnesIter::new(self)
    }
}
