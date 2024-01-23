//! Iterators for RollingBitField

use {super::RollingBitField, std::ops::Range};

/// Iterate over the 'set' bits of a RollingBitField
#[derive(Debug)]
pub struct RollingBitFieldOnesIter<'a> {
    rolling_bit_field: &'a RollingBitField,
    excess_iter: std::collections::hash_set::Iter<'a, u64>,
    bit_range: Range<u64>,
}

impl<'a> RollingBitFieldOnesIter<'a> {
    #[must_use]
    pub fn new(rolling_bit_field: &'a RollingBitField) -> Self {
        Self {
            rolling_bit_field,
            excess_iter: rolling_bit_field.excess.iter(),
            bit_range: rolling_bit_field.min..rolling_bit_field.max_exclusive,
        }
    }
}

impl Iterator for RollingBitFieldOnesIter<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate over the excess first
        if let Some(excess) = self.excess_iter.next() {
            return Some(*excess);
        }

        // Then iterate over the bit vec
        loop {
            // If there are no more bits in the range, then we've iterated over everything and are done
            let bit = self.bit_range.next()?;

            if self.rolling_bit_field.contains_assume_in_range(&bit) {
                break Some(bit);
            }
        }
    }
}
