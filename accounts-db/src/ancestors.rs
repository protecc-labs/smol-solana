use {
    crate::rolling_bit_field::RollingBitField,
    core::fmt::{Debug, Formatter},
    solana_sdk::clock::Slot,
    std::collections::HashMap,
};

pub type AncestorsForSerialization = HashMap<Slot, usize>;

#[derive(Clone, PartialEq, AbiExample)]
pub struct Ancestors {
    ancestors: RollingBitField,
}

impl Debug for Ancestors {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.keys())
    }
}

// some tests produce ancestors ranges that are too large such
// that we prefer to implement them in a sparse HashMap
const ANCESTORS_HASH_MAP_SIZE: u64 = 8192;

impl Default for Ancestors {
    fn default() -> Self {
        Self {
            ancestors: RollingBitField::new(ANCESTORS_HASH_MAP_SIZE),
        }
    }
}

impl From<Vec<Slot>> for Ancestors {
    fn from(mut source: Vec<Slot>) -> Ancestors {
        // bitfield performs optimally when we insert the minimum value first so that it knows the correct start/end values
        source.sort_unstable();
        let mut result = Ancestors::default();
        source.into_iter().for_each(|slot| {
            result.ancestors.insert(slot);
        });

        result
    }
}

impl From<&HashMap<Slot, usize>> for Ancestors {
    fn from(source: &HashMap<Slot, usize>) -> Ancestors {
        let vec = source.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        Ancestors::from(vec)
    }
}

impl From<&Ancestors> for HashMap<Slot, usize> {
    fn from(source: &Ancestors) -> HashMap<Slot, usize> {
        let mut result = HashMap::with_capacity(source.len());
        source.keys().iter().for_each(|slot| {
            result.insert(*slot, 0);
        });
        result
    }
}

impl Ancestors {
    pub fn keys(&self) -> Vec<Slot> {
        self.ancestors.get_all()
    }

    pub fn remove(&mut self, slot: &Slot) {
        self.ancestors.remove(slot);
    }

    pub fn contains_key(&self, slot: &Slot) -> bool {
        self.ancestors.contains(slot)
    }

    pub fn len(&self) -> usize {
        self.ancestors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn min_slot(&self) -> Slot {
        self.ancestors.min().unwrap_or_default()
    }

    pub fn max_slot(&self) -> Slot {
        self.ancestors.max_exclusive().saturating_sub(1)
    }
}

// These functions/fields are only usable from a dev context (i.e. tests and benches)
#[cfg(feature = "dev-context-only-utils")]
impl std::iter::FromIterator<(Slot, usize)> for Ancestors {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (Slot, usize)>,
    {
        let mut data = Vec::new();
        for i in iter {
            data.push(i);
        }
        Ancestors::from(data)
    }
}

#[cfg(feature = "dev-context-only-utils")]
impl From<Vec<(Slot, usize)>> for Ancestors {
    fn from(source: Vec<(Slot, usize)>) -> Ancestors {
        Ancestors::from(source.into_iter().map(|(slot, _)| slot).collect::<Vec<_>>())
    }
}

#[cfg(feature = "dev-context-only-utils")]
impl Ancestors {
    pub fn insert(&mut self, slot: Slot, _size: usize) {
        self.ancestors.insert(slot);
    }
}
