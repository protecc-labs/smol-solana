use bytemuck::{Pod, Zeroable};
pub use target_arch::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodEdwardsPoint(pub [u8; 32]);

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
            edwards::{CompressedEdwardsY, EdwardsPoint},
            scalar::Scalar,
            traits::VartimeMultiscalarMul,
        },
    };

    pub fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        point.validate_point()
    }

    pub fn add_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::add(left_point, right_point)
    }

    pub fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::subtract(left_point, right_point)
    }

    pub fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::multiply(scalar, point)
    }

    pub fn multiscalar_multiply_edwards(
        scalars: &[PodScalar],
        points: &[PodEdwardsPoint],
    ) -> Option<PodEdwardsPoint> {
        PodEdwardsPoint::multiscalar_multiply(scalars, points)
    }

    impl From<&EdwardsPoint> for PodEdwardsPoint {
        fn from(point: &EdwardsPoint) -> Self {
            Self(point.compress().to_bytes())
        }
    }

    impl TryFrom<&PodEdwardsPoint> for EdwardsPoint {
        type Error = Curve25519Error;

        fn try_from(pod: &PodEdwardsPoint) -> Result<Self, Self::Error> {
            CompressedEdwardsY::from_slice(&pod.0)
                .unwrap()
                .decompress()
                .ok_or(Curve25519Error::PodConversion)
        }
    }

    impl PointValidation for PodEdwardsPoint {
        type Point = Self;

        fn validate_point(&self) -> bool {
            CompressedEdwardsY::from_slice(&self.0)
                .unwrap()
                .decompress()
                .is_some()
        }
    }

    impl GroupOperations for PodEdwardsPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: EdwardsPoint = left_point.try_into().ok()?;
            let right_point: EdwardsPoint = right_point.try_into().ok()?;

            let result = &left_point + &right_point;
            Some((&result).into())
        }

        fn subtract(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: EdwardsPoint = left_point.try_into().ok()?;
            let right_point: EdwardsPoint = right_point.try_into().ok()?;

            let result = &left_point - &right_point;
            Some((&result).into())
        }

        #[cfg(not(target_os = "solana"))]
        fn multiply(scalar: &PodScalar, point: &Self) -> Option<Self> {
            let scalar: Scalar = scalar.try_into().ok()?;
            let point: EdwardsPoint = point.try_into().ok()?;

            let result = &scalar * &point;
            Some((&result).into())
        }
    }

    impl MultiScalarMultiplication for PodEdwardsPoint {
        type Scalar = PodScalar;
        type Point = Self;

        fn multiscalar_multiply(scalars: &[PodScalar], points: &[Self]) -> Option<Self> {
            let scalars = scalars
                .iter()
                .map(|scalar| Scalar::try_from(scalar).ok())
                .collect::<Option<Vec<_>>>()?;

            EdwardsPoint::optional_multiscalar_mul(
                scalars,
                points
                    .iter()
                    .map(|point| EdwardsPoint::try_from(point).ok()),
            )
            .map(|result| PodEdwardsPoint::from(&result))
        }
    }
}

#[cfg(target_os = "solana")]
mod target_arch {
    use {
        super::*,
        crate::curve25519::{
            curve_syscall_traits::{ADD, CURVE25519_EDWARDS, MUL, SUB},
            scalar::PodScalar,
        },
    };

    pub fn validate_edwards(point: &PodEdwardsPoint) -> bool {
        let mut validate_result = 0u8;
        let result = unsafe {
            solana_program::syscalls::sol_curve_validate_point(
                CURVE25519_EDWARDS,
                &point.0 as *const u8,
                &mut validate_result,
            )
        };
        result == 0
    }

    pub fn add_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_EDWARDS,
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

    pub fn subtract_edwards(
        left_point: &PodEdwardsPoint,
        right_point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_EDWARDS,
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

    pub fn multiply_edwards(
        scalar: &PodScalar,
        point: &PodEdwardsPoint,
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_group_op(
                CURVE25519_EDWARDS,
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

    pub fn multiscalar_multiply_edwards(
        scalars: &[PodScalar],
        points: &[PodEdwardsPoint],
    ) -> Option<PodEdwardsPoint> {
        let mut result_point = PodEdwardsPoint::zeroed();
        let result = unsafe {
            solana_program::syscalls::sol_curve_multiscalar_mul(
                CURVE25519_EDWARDS,
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
