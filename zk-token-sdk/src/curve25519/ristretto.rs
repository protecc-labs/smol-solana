use bytemuck::{Pod, Zeroable};
pub use target_arch::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodRistrettoPoint(pub [u8; 32]);

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::curve25519::{
            curve_syscall_traits::{GroupOperations, MultiScalarMultiplication, PointValidation},
            errors::Curve25519Error,
            scalar::PodScalar,
        },
        curve25519_dalek::{
            ristretto::{CompressedRistretto, RistrettoPoint},
            scalar::Scalar,
            traits::VartimeMultiscalarMul,
        },
    };

    pub fn validate_ristretto(point: &PodRistrettoPoint) -> bool {
        point.validate_point()
    }

    pub fn add_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::add(left_point, right_point)
    }

    pub fn subtract_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::subtract(left_point, right_point)
    }

    pub fn multiply_ristretto(
        scalar: &PodScalar,
        point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::multiply(scalar, point)
    }

    pub fn multiscalar_multiply_ristretto(
        scalars: &[PodScalar],
        points: &[PodRistrettoPoint],
    ) -> Option<PodRistrettoPoint> {
        PodRistrettoPoint::multiscalar_multiply(scalars, points)
    }

    impl From<&RistrettoPoint> for PodRistrettoPoint {
        fn from(point: &RistrettoPoint) -> Self {
            Self(point.compress().to_bytes())
        }
    }

    impl TryFrom<&PodRistrettoPoint> for RistrettoPoint {
        type Error = Curve25519Error;

        fn try_from(pod: &PodRistrettoPoint) -> Result<Self, Self::Error> {
            CompressedRistretto::from_slice(&pod.0)
                .unwrap()
                .decompress()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl PointValidation for PodRistrettoPoint {
        type Point = Self;

        fn validate_point(&self) -> bool {
            CompressedRistretto::from_slice(&self.0)
                .unwrap()
                .decompress()
                .is_some()
        }
    }

    impl GroupOperations for PodRistrettoPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: RistrettoPoint = left_point.try_into().ok()?;
            let right_point: RistrettoPoint = right_point.try_into().ok()?;

            let result = &left_point + &right_point;
            Some((&result).into())
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: RistrettoPoint = left_point.try_into().ok()?;
            let right_point: RistrettoPoint = right_point.try_into().ok()?;

            let result = &left_point - &right_point;
            Some((&result).into())
        }

        #[cfg(not(target_os = "solana"))]
        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let scalar: Scalar = scalar.try_into().ok()?;
            let point: RistrettoPoint = point.try_into().ok()?;

            let result = &scalar * &point;
            Some((&result).into())
        }
    }

    impl MultiScalarMultiplication for PodRistrettoPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn multiscalar_multiply(scalars: &[PodScalar], points: &[Self]) -> Option<Self> {
            let scalars = scalars
                .iter()
                .map(|scalar| Scalar::try_from(scalar).ok())
                .collect::<Option<Vec<_>>>()?;

            RistrettoPoint::optional_multiscalar_mul(
                scalars,
                points
                    .iter()
                    .map(|point| RistrettoPoint::try_from(point).ok()),
            )
            .map(|result| PodRistrettoPoint::from(&result))
        }
    }
}

#[cfg(target_os = "solana")]
#[allow(unused_variables)]
mod target_arch {
    use {
        super::*,
        crate::curve25519::{
            curve_syscall_traits::{ADD, CURVE25519_RISTRETTO, MUL, SUB},
            scalar::PodScalar,
        },
    };

    pub fn validate_ristretto(point: &PodRistrettoPoint) -> bool {
        let mut validate_result = 0u8;
        let result = unsafe {
            solana_program::syscalls::sol_curve_validate_point(
                CURVE25519_RISTRETTO,
                &point.0 as *const u8,
                &mut validate_result,
            )
        };

        result == 0
    }

    pub fn add_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        let mut result_point = PodRistrettoPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_RISTRETTO,
                ADD,
                &left_point.0 as *const u8,
                &right_point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn subtract_ristretto(
        left_point: &PodRistrettoPoint,
        right_point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        let mut result_point = PodRistrettoPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_RISTRETTO,
                SUB,
                &left_point.0 as *const u8,
                &right_point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn multiply_ristretto(
        scalar: &PodScalar,
        point: &PodRistrettoPoint,
    ) -> Option<PodRistrettoPoint> {
        let mut result_point = PodRistrettoPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_RISTRETTO,
                MUL,
                &scalar.0 as *const u8,
                &point.0 as *const u8,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }

    pub fn multiscalar_multiply_ristretto(
        scalars: &[PodScalar],
        points: &[PodRistrettoPoint],
    ) -> Option<PodRistrettoPoint> {
        let mut result_point = PodRistrettoPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_multiscalar_mul(
                CURVE25519_RISTRETTO,
                scalars.as_ptr() as *const u8,
                points.as_ptr() as *const u8,
                points.len() as u64,
                &mut result_point.0 as *mut u8,
            )
        };

        if result == 0 {
            Some(result_point)
        } else {
            None
        }
    }
}
