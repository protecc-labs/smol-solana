//! Serde helpers.

use serde::{Deserialize, Deserializer};

/// This helper function enables successful deserialization of versioned structs; new structs may
/// include additional fields if they impl Default and are added to the end of the struct. Right
/// now, this function is targeted at `bincode` deserialization; the error match may need to be
/// updated if another package needs to be used in the future.
pub fn default_on_eof<'de, T, D>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let result = T::deserialize(d);
    ignore_eof_error::<'de, T, D::Error>(result)
}

pub fn ignore_eof_error<'de, T, D>(result: Result<T, D>) -> Result<T, D>
where
    T: Deserialize<'de> + Default,
    D: std::fmt::Display,
{
    match result {
        Err(err) if err.to_string() == "io error: unexpected end of file" => Ok(T::default()),
        Err(err) if err.to_string() == "io error: failed to fill whole buffer" => Ok(T::default()),
        result => result,
    }
}
