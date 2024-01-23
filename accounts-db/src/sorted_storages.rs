use {
    crate::accounts_db::AccountStorageEntry,
    log::*,
    solana_measure::measure::Measure,
    solana_sdk::clock::Slot,
    std::{
        collections::HashMap,
        ops::{Bound, Range, RangeBounds},
        sync::Arc,
    },
};

/// Provide access to SnapshotStorageOnes by slot
pub struct SortedStorages<'a> {
    /// range of slots where storages exist (likely sparse)
    range: Range<Slot>,
    /// the actual storages
    /// A HashMap allows sparse storage and fast lookup of Slot -> Storage.
    /// We expect ~432k slots.
    storages: HashMap<Slot, &'a Arc<AccountStorageEntry>>,
}

impl<'a> SortedStorages<'a> {
    /// containing nothing
    pub fn empty() -> Self {
        SortedStorages {
            range: Range::default(),
            storages: HashMap::default(),
        }
    }

    /// primary method of retrieving [`(Slot, Arc<AccountStorageEntry>)`]
    pub fn iter_range<R>(&'a self, range: &R) -> SortedStoragesIter<'a>
    where
        R: RangeBounds<Slot>,
    {
        SortedStoragesIter::new(self, range)
    }

    fn get(&self, slot: Slot) -> Option<&Arc<AccountStorageEntry>> {
        self.storages.get(&slot).copied()
    }

    pub fn range_width(&self) -> Slot {
        self.range.end - self.range.start
    }

    pub fn range(&self) -> &Range<Slot> {
        &self.range
    }

    pub fn max_slot_inclusive(&self) -> Slot {
        self.range.end.saturating_sub(1)
    }

    pub fn slot_count(&self) -> usize {
        self.storages.len()
    }

    pub fn storage_count(&self) -> usize {
        self.storages.len()
    }

    // assumption:
    // source.slot() is unique from all other items in 'source'
    pub fn new(source: &'a [Arc<AccountStorageEntry>]) -> Self {
        let slots = source.iter().map(|storage| {
            storage.slot() // this must be unique. Will be enforced in new_with_slots
        });
        Self::new_with_slots(source.iter().zip(slots), None, None)
    }

    /// create [`SortedStorages`] from `source` iterator.
    /// `source` contains a [`Arc<AccountStorageEntry>`] and its associated slot
    /// `source` does not have to be sorted in any way, but is assumed to not have duplicate slot #s
    pub fn new_with_slots(
        source: impl Iterator<Item = (&'a Arc<AccountStorageEntry>, Slot)> + Clone,
        // A slot used as a lower bound, but potentially smaller than the smallest slot in the given 'source' iterator
        min_slot: Option<Slot>,
        // highest valid slot. Only matters if source array does not contain a slot >= max_slot_inclusive.
        // An example is a slot that has accounts in the write cache at slots <= 'max_slot_inclusive' but no storages at those slots.
        // None => self.range.end = source.1.max() + 1
        // Some(slot) => self.range.end = std::cmp::max(slot, source.1.max())
        max_slot_inclusive: Option<Slot>,
    ) -> Self {
        let mut min = Slot::MAX;
        let mut max = Slot::MIN;
        let mut adjust_min_max = |slot| {
            min = std::cmp::min(slot, min);
            max = std::cmp::max(slot + 1, max);
        };
        // none, either, or both of min/max could be specified
        if let Some(slot) = min_slot {
            adjust_min_max(slot);
        }
        if let Some(slot) = max_slot_inclusive {
            adjust_min_max(slot);
        }

        let mut slot_count = 0;
        let mut time = Measure::start("get slot");
        let source_ = source.clone();
        let mut storage_count = 0;
        source_.for_each(|(_, slot)| {
            storage_count += 1;
            slot_count += 1;
            adjust_min_max(slot);
        });
        time.stop();
        let mut time2 = Measure::start("sort");
        let range;
        let mut storages = HashMap::default();
        if min > max {
            range = Range::default();
        } else {
            range = Range {
                start: min,
                end: max,
            };
            source.for_each(|(original_storages, slot)| {
                assert!(
                    storages.insert(slot, original_storages).is_none(),
                    "slots are not unique"
                ); // we should not encounter the same slot twice
            });
        }
        time2.stop();
        debug!("SortedStorages, times: {}, {}", time.as_us(), time2.as_us());
        Self { range, storages }
    }
}

/// Iterator over successive slots in 'storages' within 'range'.
/// This enforces sequential access so that random access does not have to be implemented.
/// Random access could be expensive with large sparse sets.
pub struct SortedStoragesIter<'a> {
    /// range for the iterator to iterate over (start_inclusive..end_exclusive)
    range: Range<Slot>,
    /// the data to return per slot
    storages: &'a SortedStorages<'a>,
    /// the slot to be returned the next time 'Next' is called
    next_slot: Slot,
}

impl<'a> Iterator for SortedStoragesIter<'a> {
    type Item = (Slot, Option<&'a Arc<AccountStorageEntry>>);

    fn next(&mut self) -> Option<Self::Item> {
        let slot = self.next_slot;
        if slot < self.range.end {
            // iterator is still in range. Storage may or may not exist at this slot, but the iterator still needs to return the slot
            self.next_slot += 1;
            Some((slot, self.storages.get(slot)))
        } else {
            // iterator passed the end of the range, so from now on it returns None
            None
        }
    }
}

impl<'a> SortedStoragesIter<'a> {
    pub fn new<R: RangeBounds<Slot>>(
        storages: &'a SortedStorages<'a>,
        range: &R,
    ) -> SortedStoragesIter<'a> {
        let storage_range = storages.range();
        let next_slot = match range.start_bound() {
            Bound::Unbounded => {
                storage_range.start // unbounded beginning starts with the min known slot (which is inclusive)
            }
            Bound::Included(x) => *x,
            Bound::Excluded(x) => *x + 1, // make inclusive
        };
        let end_exclusive_slot = match range.end_bound() {
            Bound::Unbounded => {
                storage_range.end // unbounded end ends with the max known slot (which is exclusive)
            }
            Bound::Included(x) => *x + 1, // make exclusive
            Bound::Excluded(x) => *x,
        };
        // Note that the range can be outside the range of known storages.
        // This is because the storages may not be the only source of valid slots.
        // The write cache is another source of slots that 'storages' knows nothing about.
        let range = next_slot..end_exclusive_slot;
        SortedStoragesIter {
            range,
            storages,
            next_slot,
        }
    }
}
