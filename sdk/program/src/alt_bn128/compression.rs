pub mod prelude {
    pub use crate::alt_bn128::compression::{
        alt_bn128_compression_size::*, consts::*, target_arch::*, AltBn128CompressionError,
    };
}

use thiserror::Error;

mod consts {
    pub const ALT_BN128_G1_COMPRESS: u64 = 0;
    pub const ALT_BN128_G1_DECOMPRESS: u64 = 1;
    pub const ALT_BN128_G2_COMPRESS: u64 = 2;
    pub const ALT_BN128_G2_DECOMPRESS: u64 = 3;
}

mod alt_bn128_compression_size {
    pub const G1: usize = 64;
    pub const G2: usize = 128;
    pub const G1_COMPRESSED: usize = 32;
    pub const G2_COMPRESSED: usize = 64;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AltBn128CompressionError {
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Failed to decompress g1")]
    G1DecompressionFailed,
    #[error("Failed to decompress g2")]
    G2DecompressionFailed,
    #[error("Failed to compress affine g1")]
    G1CompressionFailed,
    #[error("Failed to compress affine g2")]
    G2CompressionFailed,
    #[error("Invalid input size")]
    InvalidInputSize,
}

impl From<u64> for AltBn128CompressionError {
    fn from(v: u64) -> AltBn128CompressionError {
        match v {
            1 => AltBn128CompressionError::G1DecompressionFailed,
            2 => AltBn128CompressionError::G2DecompressionFailed,
            3 => AltBn128CompressionError::G1CompressionFailed,
            4 => AltBn128CompressionError::G2CompressionFailed,
            5 => AltBn128CompressionError::InvalidInputSize,
            _ => AltBn128CompressionError::UnexpectedError,
        }
    }
}

impl From<AltBn128CompressionError> for u64 {
    fn from(v: AltBn128CompressionError) -> u64 {
        match v {
            AltBn128CompressionError::G1DecompressionFailed => 1,
            AltBn128CompressionError::G2DecompressionFailed => 2,
            AltBn128CompressionError::G1CompressionFailed => 3,
            AltBn128CompressionError::G2CompressionFailed => 4,
            AltBn128CompressionError::InvalidInputSize => 5,
            AltBn128CompressionError::UnexpectedError => 0,
        }
    }
}

#[cfg(not(target_os = "solana"))]
mod target_arch {

    use {
        super::*,
        crate::alt_bn128::compression::alt_bn128_compression_size,
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
    };

    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;

    pub fn alt_bn128_g1_decompress(
        g1_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G1], AltBn128CompressionError> {
        let g1_bytes: [u8; alt_bn128_compression_size::G1_COMPRESSED] = g1_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g1_bytes == [0u8; alt_bn128_compression_size::G1_COMPRESSED] {
            return Ok([0u8; alt_bn128_compression_size::G1]);
        }
        let decompressed_g1 = G1::deserialize_with_mode(
            convert_endianness::<32, 32>(&g1_bytes).as_slice(),
            Compress::Yes,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        let mut decompressed_g1_bytes = [0u8; alt_bn128_compression_size::G1];
        decompressed_g1
            .x
            .serialize_with_mode(&mut decompressed_g1_bytes[..32], Compress::No)
            .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        decompressed_g1
            .y
            .serialize_with_mode(&mut decompressed_g1_bytes[32..], Compress::No)
            .map_err(|_| AltBn128CompressionError::G1DecompressionFailed)?;
        Ok(convert_endianness::<32, 64>(&decompressed_g1_bytes))
    }

    pub fn alt_bn128_g1_compress(
        g1_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G1_COMPRESSED], AltBn128CompressionError> {
        let g1_bytes: [u8; alt_bn128_compression_size::G1] = g1_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g1_bytes == [0u8; alt_bn128_compression_size::G1] {
            return Ok([0u8; alt_bn128_compression_size::G1_COMPRESSED]);
        }
        let g1 = G1::deserialize_with_mode(
            convert_endianness::<32, 64>(&g1_bytes).as_slice(),
            Compress::No,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G1CompressionFailed)?;
        let mut g1_bytes = [0u8; alt_bn128_compression_size::G1_COMPRESSED];
        G1::serialize_compressed(&g1, g1_bytes.as_mut_slice())
            .map_err(|_| AltBn128CompressionError::G2CompressionFailed)?;
        Ok(convert_endianness::<32, 32>(&g1_bytes))
    }

    pub fn alt_bn128_g2_decompress(
        g2_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G2], AltBn128CompressionError> {
        let g2_bytes: [u8; alt_bn128_compression_size::G2_COMPRESSED] = g2_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g2_bytes == [0u8; alt_bn128_compression_size::G2_COMPRESSED] {
            return Ok([0u8; alt_bn128_compression_size::G2]);
        }
        let decompressed_g2 =
            G2::deserialize_compressed(convert_endianness::<64, 64>(&g2_bytes).as_slice())
                .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        let mut decompressed_g2_bytes = [0u8; alt_bn128_compression_size::G2];
        decompressed_g2
            .x
            .serialize_with_mode(&mut decompressed_g2_bytes[..64], Compress::No)
            .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        decompressed_g2
            .y
            .serialize_with_mode(&mut decompressed_g2_bytes[64..128], Compress::No)
            .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        Ok(convert_endianness::<64, 128>(&decompressed_g2_bytes))
    }

    pub fn alt_bn128_g2_compress(
        g2_bytes: &[u8],
    ) -> Result<[u8; alt_bn128_compression_size::G2_COMPRESSED], AltBn128CompressionError> {
        let g2_bytes: [u8; alt_bn128_compression_size::G2] = g2_bytes
            .try_into()
            .map_err(|_| AltBn128CompressionError::InvalidInputSize)?;
        if g2_bytes == [0u8; alt_bn128_compression_size::G2] {
            return Ok([0u8; alt_bn128_compression_size::G2_COMPRESSED]);
        }
        let g2 = G2::deserialize_with_mode(
            convert_endianness::<64, 128>(&g2_bytes).as_slice(),
            Compress::No,
            Validate::No,
        )
        .map_err(|_| AltBn128CompressionError::G2DecompressionFailed)?;
        let mut g2_bytes = [0u8; alt_bn128_compression_size::G2_COMPRESSED];
        G2::serialize_compressed(&g2, g2_bytes.as_mut_slice())
            .map_err(|_| AltBn128CompressionError::G2CompressionFailed)?;
        Ok(convert_endianness::<64, 64>(&g2_bytes))
    }

    pub fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
        bytes: &[u8; ARRAY_SIZE],
    ) -> [u8; ARRAY_SIZE] {
        let reversed: [_; ARRAY_SIZE] = bytes
            .chunks_exact(CHUNK_SIZE)
            .flat_map(|chunk| chunk.iter().rev().copied())
            .enumerate()
            .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
                acc[i] = v;
                acc
            });
        reversed
    }
}

#[cfg(target_os = "solana")]
mod target_arch {
    use {
        super::*,
        alt_bn128_compression_size::{G1, G1_COMPRESSED, G2, G2_COMPRESSED},
        prelude::*,
    };

    pub fn alt_bn128_g1_compress(
        input: &[u8],
    ) -> Result<[u8; G1_COMPRESSED], AltBn128CompressionError> {
        let mut result_buffer = [0; G1_COMPRESSED];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G1_COMPRESS,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer),
            error => Err(AltBn128CompressionError::from(error)),
        }
    }

    pub fn alt_bn128_g1_decompress(input: &[u8]) -> Result<[u8; G1], AltBn128CompressionError> {
        let mut result_buffer = [0; G1];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G1_DECOMPRESS,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer),
            error => Err(AltBn128CompressionError::from(error)),
        }
    }

    pub fn alt_bn128_g2_compress(
        input: &[u8],
    ) -> Result<[u8; G2_COMPRESSED], AltBn128CompressionError> {
        let mut result_buffer = [0; G2_COMPRESSED];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G2_COMPRESS,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer),
            error => Err(AltBn128CompressionError::from(error)),
        }
    }

    pub fn alt_bn128_g2_decompress(
        input: &[u8; G2_COMPRESSED],
    ) -> Result<[u8; G2], AltBn128CompressionError> {
        let mut result_buffer = [0; G2];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G2_DECOMPRESS,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer),
            error => Err(AltBn128CompressionError::from(error)),
        }
    }
}
