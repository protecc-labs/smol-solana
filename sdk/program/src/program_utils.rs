//! Contains a single utility function for deserializing from [bincode].
//!
//! [bincode]: https://docs.rs/bincode

use {crate::instruction::InstructionError, bincode::config::Options};

/// Deserialize with a limit based the maximum amount of data a program can expect to get.
/// This function should be used in place of direct deserialization to help prevent OOM errors
pub fn limited_deserialize<T>(instruction_data: &[u8], limit: u64) -> Result<T, InstructionError>
where
    T: serde::de::DeserializeOwned,
{
    bincode::options()
        .with_limit(limit)
        .with_fixint_encoding() // As per https://github.com/servo/bincode/issues/333, these two options are needed
        .allow_trailing_bytes() // to retain the behavior of bincode::deserialize with the new `options()` method
        .deserialize_from(instruction_data)
        .map_err(|_| InstructionError::InvalidInstructionData)
}
