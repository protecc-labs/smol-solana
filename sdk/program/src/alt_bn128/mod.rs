pub mod compression;
pub mod prelude {
    pub use crate::alt_bn128::{consts::*, target_arch::*, AltBn128Error};
}

use {
    bytemuck::{Pod, Zeroable},
    consts::*,
    thiserror::Error,
};

mod consts {
    /// Input length for the add operation.
    pub const ALT_BN128_ADDITION_INPUT_LEN: usize = 128;

    /// Input length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_INPUT_LEN: usize = 128;

    /// Pair element length.
    pub const ALT_BN128_PAIRING_ELEMENT_LEN: usize = 192;

    /// Output length for the add operation.
    pub const ALT_BN128_ADDITION_OUTPUT_LEN: usize = 64;

    /// Output length for the multiplication operation.
    pub const ALT_BN128_MULTIPLICATION_OUTPUT_LEN: usize = 64;

    /// Output length for pairing operation.
    pub const ALT_BN128_PAIRING_OUTPUT_LEN: usize = 32;

    /// Size of the EC point field, in bytes.
    pub const ALT_BN128_FIELD_SIZE: usize = 32;

    /// Size of the EC point. `alt_bn128` point contains
    /// the consistently united x and y fields as 64 bytes.
    pub const ALT_BN128_POINT_SIZE: usize = 64;

    pub const ALT_BN128_ADD: u64 = 0;
    pub const ALT_BN128_SUB: u64 = 1;
    pub const ALT_BN128_MUL: u64 = 2;
    pub const ALT_BN128_PAIRING: u64 = 3;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AltBn128Error {
    #[error("The input data is invalid")]
    InvalidInputData,
    #[error("Invalid group data")]
    GroupError,
    #[error("Slice data is going out of input data bounds")]
    SliceOutOfBounds,
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Failed to convert a byte slice into a vector {0:?}")]
    TryIntoVecError(Vec<u8>),
    #[error("Failed to convert projective to affine g1")]
    ProjectiveToG1Failed,
}

impl From<u64> for AltBn128Error {
    fn from(v: u64) -> AltBn128Error {
        match v {
            1 => AltBn128Error::InvalidInputData,
            2 => AltBn128Error::GroupError,
            3 => AltBn128Error::SliceOutOfBounds,
            4 => AltBn128Error::TryIntoVecError(Vec::new()),
            5 => AltBn128Error::ProjectiveToG1Failed,
            _ => AltBn128Error::UnexpectedError,
        }
    }
}

impl From<AltBn128Error> for u64 {
    fn from(v: AltBn128Error) -> u64 {
        match v {
            AltBn128Error::InvalidInputData => 1,
            AltBn128Error::GroupError => 2,
            AltBn128Error::SliceOutOfBounds => 3,
            AltBn128Error::TryIntoVecError(_) => 4,
            AltBn128Error::ProjectiveToG1Failed => 5,
            AltBn128Error::UnexpectedError => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1(pub [u8; 64]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2(pub [u8; 128]);

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        ark_bn254::{self, Config},
        ark_ec::{self, models::bn::Bn, pairing::Pairing, AffineRepr},
        ark_ff::{BigInteger, BigInteger256, One},
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
    };

    type G1 = ark_bn254::g1::G1Affine;
    type G2 = ark_bn254::g2::G2Affine;

    impl TryFrom<PodG1> for G1 {
        type Error = AltBn128Error;

        fn try_from(bytes: PodG1) -> Result<Self, Self::Error> {
            if bytes.0 == [0u8; 64] {
                return Ok(G1::zero());
            }
            let g1 = Self::deserialize_with_mode(
                &*[&bytes.0[..], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            );

            match g1 {
                Ok(g1) => {
                    if !g1.is_on_curve() {
                        Err(AltBn128Error::GroupError)
                    } else {
                        Ok(g1)
                    }
                }
                Err(_) => Err(AltBn128Error::InvalidInputData),
            }
        }
    }

    impl TryFrom<PodG2> for G2 {
        type Error = AltBn128Error;

        fn try_from(bytes: PodG2) -> Result<Self, Self::Error> {
            if bytes.0 == [0u8; 128] {
                return Ok(G2::zero());
            }
            let g2 = Self::deserialize_with_mode(
                &*[&bytes.0[..], &[0u8][..]].concat(),
                Compress::No,
                Validate::Yes,
            );

            match g2 {
                Ok(g2) => {
                    if !g2.is_on_curve() {
                        Err(AltBn128Error::GroupError)
                    } else {
                        Ok(g2)
                    }
                }
                Err(_) => Err(AltBn128Error::InvalidInputData),
            }
        }
    }

    pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > ALT_BN128_ADDITION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }

        let mut input = input.to_vec();
        input.resize(ALT_BN128_ADDITION_INPUT_LEN, 0);

        let p: G1 = PodG1(
            convert_edianness_64(&input[..64])
                .try_into()
                .map_err(AltBn128Error::TryIntoVecError)?,
        )
        .try_into()?;
        let q: G1 = PodG1(
            convert_edianness_64(&input[64..ALT_BN128_ADDITION_INPUT_LEN])
                .try_into()
                .map_err(AltBn128Error::TryIntoVecError)?,
        )
        .try_into()?;

        #[allow(clippy::arithmetic_side_effects)]
        let result_point = p + q;

        let mut result_point_data = [0u8; ALT_BN128_ADDITION_OUTPUT_LEN];
        let result_point_affine: G1 = result_point.into();
        result_point_affine
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point_affine
            .y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        Ok(convert_edianness_64(&result_point_data[..]).to_vec())
    }

    pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > ALT_BN128_MULTIPLICATION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }

        let mut input = input.to_vec();
        input.resize(ALT_BN128_MULTIPLICATION_INPUT_LEN, 0);

        let p: G1 = PodG1(
            convert_edianness_64(&input[..64])
                .try_into()
                .map_err(AltBn128Error::TryIntoVecError)?,
        )
        .try_into()?;
        let fr = BigInteger256::deserialize_uncompressed_unchecked(
            &convert_edianness_64(&input[64..96])[..],
        )
        .map_err(|_| AltBn128Error::InvalidInputData)?;

        let result_point: G1 = p.mul_bigint(fr).into();

        let mut result_point_data = [0u8; ALT_BN128_MULTIPLICATION_OUTPUT_LEN];

        result_point
            .x
            .serialize_with_mode(&mut result_point_data[..32], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;
        result_point
            .y
            .serialize_with_mode(&mut result_point_data[32..], Compress::No)
            .map_err(|_| AltBn128Error::InvalidInputData)?;

        Ok(
            convert_edianness_64(&result_point_data[..ALT_BN128_MULTIPLICATION_OUTPUT_LEN])
                .to_vec(),
        )
    }

    pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input
            .len()
            .checked_rem(consts::ALT_BN128_PAIRING_ELEMENT_LEN)
            .is_none()
        {
            return Err(AltBn128Error::InvalidInputData);
        }

        let ele_len = input.len().saturating_div(ALT_BN128_PAIRING_ELEMENT_LEN);

        let mut vec_pairs: Vec<(G1, G2)> = Vec::new();
        for i in 0..ele_len {
            vec_pairs.push((
                PodG1(
                    convert_edianness_64(
                        &input[i.saturating_mul(ALT_BN128_PAIRING_ELEMENT_LEN)
                            ..i.saturating_mul(ALT_BN128_PAIRING_ELEMENT_LEN)
                                .saturating_add(ALT_BN128_POINT_SIZE)],
                    )
                    .try_into()
                    .map_err(AltBn128Error::TryIntoVecError)?,
                )
                .try_into()?,
                PodG2(
                    convert_edianness_128(
                        &input[i
                            .saturating_mul(ALT_BN128_PAIRING_ELEMENT_LEN)
                            .saturating_add(ALT_BN128_POINT_SIZE)
                            ..i.saturating_mul(ALT_BN128_PAIRING_ELEMENT_LEN)
                                .saturating_add(ALT_BN128_PAIRING_ELEMENT_LEN)],
                    )
                    .try_into()
                    .map_err(AltBn128Error::TryIntoVecError)?,
                )
                .try_into()?,
            ));
        }

        let mut result = BigInteger256::from(0u64);
        let res = <Bn<Config> as Pairing>::multi_pairing(
            vec_pairs.iter().map(|pair| pair.0),
            vec_pairs.iter().map(|pair| pair.1),
        );

        if res.0 == ark_bn254::Fq12::one() {
            result = BigInteger256::from(1u64);
        }

        let output = result.to_bytes_be();
        Ok(output)
    }

    fn convert_edianness_64(bytes: &[u8]) -> Vec<u8> {
        bytes
            .chunks(32)
            .flat_map(|b| b.iter().copied().rev().collect::<Vec<u8>>())
            .collect::<Vec<u8>>()
    }

    fn convert_edianness_128(bytes: &[u8]) -> Vec<u8> {
        bytes
            .chunks(64)
            .flat_map(|b| b.iter().copied().rev().collect::<Vec<u8>>())
            .collect::<Vec<u8>>()
    }
}

#[cfg(target_os = "solana")]
mod target_arch {
    use super::*;
    pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > ALT_BN128_ADDITION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0; ALT_BN128_ADDITION_OUTPUT_LEN];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_ADD,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer.to_vec()),
            error => Err(AltBn128Error::from(error)),
        }
    }

    pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input.len() > ALT_BN128_MULTIPLICATION_INPUT_LEN {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; ALT_BN128_POINT_SIZE];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_MUL,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer.to_vec()),
            error => Err(AltBn128Error::from(error)),
        }
    }

    pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, AltBn128Error> {
        if input
            .len()
            .checked_rem(consts::ALT_BN128_PAIRING_ELEMENT_LEN)
            .is_none()
        {
            return Err(AltBn128Error::InvalidInputData);
        }
        let mut result_buffer = [0u8; 32];
        let result = unsafe {
            crate::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING,
                input as *const _ as *const u8,
                input.len() as u64,
                &mut result_buffer as *mut _ as *mut u8,
            )
        };

        match result {
            0 => Ok(result_buffer.to_vec()),
            error => Err(AltBn128Error::from(error)),
        }
    }
}
