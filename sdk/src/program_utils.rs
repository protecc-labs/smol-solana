//! Contains a single utility function for deserializing from [bincode].
//!
//! [bincode]: https://docs.rs/bincode

use crate::instruction::InstructionError;

/// Deserialize with a limit based the maximum amount of data a program can expect to get.
/// This function should be used in place of direct deserialization to help prevent OOM errors
pub fn limited_deserialize<T>(instruction_data: &[u8]) -> Result<T, InstructionError>
where
    T: serde::de::DeserializeOwned,
{
    solana_program::program_utils::limited_deserialize(
        instruction_data,
        crate::packet::PACKET_DATA_SIZE as u64,
    )
}
