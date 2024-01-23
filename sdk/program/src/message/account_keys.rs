use {
    crate::{
        instruction::{CompiledInstruction, Instruction},
        message::{v0::LoadedAddresses, CompileError},
        pubkey::Pubkey,
    },
    std::{collections::BTreeMap, iter::zip, ops::Index},
};

/// Collection of static and dynamically loaded keys used to load accounts
/// during transaction processing.
#[derive(Clone, Default, Debug, Eq)]
pub struct AccountKeys<'a> {
    static_keys: &'a [Pubkey],
    dynamic_keys: Option<&'a LoadedAddresses>,
}

impl Index<usize> for AccountKeys<'_> {
    type Output = Pubkey;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index is invalid")
    }
}

impl<'a> AccountKeys<'a> {
    pub fn new(static_keys: &'a [Pubkey], dynamic_keys: Option<&'a LoadedAddresses>) -> Self {
        Self {
            static_keys,
            dynamic_keys,
        }
    }

    /// Returns an iterator of account key segments. The ordering of segments
    /// affects how account indexes from compiled instructions are resolved and
    /// so should not be changed.
    fn key_segment_iter(&self) -> impl Iterator<Item = &'a [Pubkey]> {
        if let Some(dynamic_keys) = self.dynamic_keys {
            [
                self.static_keys,
                &dynamic_keys.writable,
                &dynamic_keys.readonly,
            ]
            .into_iter()
        } else {
            // empty segments added for branch type compatibility
            [self.static_keys, &[], &[]].into_iter()
        }
    }

    /// Returns the address of the account at the specified index of the list of
    /// message account keys constructed from static keys, followed by dynamically
    /// loaded writable addresses, and lastly the list of dynamically loaded
    /// readonly addresses.
    pub fn get(&self, mut index: usize) -> Option<&'a Pubkey> {
        for key_segment in self.key_segment_iter() {
            if index < key_segment.len() {
                return Some(&key_segment[index]);
            }
            index = index.saturating_sub(key_segment.len());
        }

        None
    }

    /// Returns the total length of loaded accounts for a message
    pub fn len(&self) -> usize {
        let mut len = 0usize;
        for key_segment in self.key_segment_iter() {
            len = len.saturating_add(key_segment.len());
        }
        len
    }

    /// Returns true if this collection of account keys is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterator for the addresses of the loaded accounts for a message
    pub fn iter(&self) -> impl Iterator<Item = &'a Pubkey> {
        self.key_segment_iter().flatten()
    }

    /// Compile instructions using the order of account keys to determine
    /// compiled instruction account indexes.
    ///
    /// # Panics
    ///
    /// Panics when compiling fails. See [`AccountKeys::try_compile_instructions`]
    /// for a full description of failure scenarios.
    pub fn compile_instructions(&self, instructions: &[Instruction]) -> Vec<CompiledInstruction> {
        self.try_compile_instructions(instructions)
            .expect("compilation failure")
    }

    /// Compile instructions using the order of account keys to determine
    /// compiled instruction account indexes.
    ///
    /// # Errors
    ///
    /// Compilation will fail if any `instructions` use account keys which are not
    /// present in this account key collection.
    ///
    /// Compilation will fail if any `instructions` use account keys which are located
    /// at an index which cannot be cast to a `u8` without overflow.
    pub fn try_compile_instructions(
        &self,
        instructions: &[Instruction],
    ) -> Result<Vec<CompiledInstruction>, CompileError> {
        let mut account_index_map = BTreeMap::<&Pubkey, u8>::new();
        for (index, key) in self.iter().enumerate() {
            let index = u8::try_from(index).map_err(|_| CompileError::AccountIndexOverflow)?;
            account_index_map.insert(key, index);
        }

        let get_account_index = |key: &Pubkey| -> Result<u8, CompileError> {
            account_index_map
                .get(key)
                .cloned()
                .ok_or(CompileError::UnknownInstructionKey(*key))
        };

        instructions
            .iter()
            .map(|ix| {
                let accounts: Vec<u8> = ix
                    .accounts
                    .iter()
                    .map(|account_meta| get_account_index(&account_meta.pubkey))
                    .collect::<Result<Vec<u8>, CompileError>>()?;

                Ok(CompiledInstruction {
                    program_id_index: get_account_index(&ix.program_id)?,
                    data: ix.data.clone(),
                    accounts,
                })
            })
            .collect()
    }
}

impl PartialEq for AccountKeys<'_> {
    fn eq(&self, other: &Self) -> bool {
        zip(self.iter(), other.iter()).all(|(a, b)| a == b)
    }
}
