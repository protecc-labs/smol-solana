use {super::pod, crate::curve25519::ristretto::PodRistrettoPoint};

impl From<(pod::PedersenCommitment, pod::DecryptHandle)> for pod::ElGamalCiphertext {
    fn from((commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle)) -> Self {
        let mut buf = [0_u8; 64];
        buf[..32].copy_from_slice(&commitment.0);
        buf[32..].copy_from_slice(&handle.0);
        pod::ElGamalCiphertext(buf)
    }
}

impl From<pod::ElGamalCiphertext> for (pod::PedersenCommitment, pod::DecryptHandle) {
    fn from(ciphertext: pod::ElGamalCiphertext) -> Self {
        let commitment: [u8; 32] = ciphertext.0[..32].try_into().unwrap();
        let handle: [u8; 32] = ciphertext.0[32..].try_into().unwrap();

        (
            pod::PedersenCommitment(commitment),
            pod::DecryptHandle(handle),
        )
    }
}

impl From<pod::PedersenCommitment> for PodRistrettoPoint {
    fn from(commitment: pod::PedersenCommitment) -> Self {
        PodRistrettoPoint(commitment.0)
    }
}

impl From<PodRistrettoPoint> for pod::PedersenCommitment {
    fn from(point: PodRistrettoPoint) -> Self {
        pod::PedersenCommitment(point.0)
    }
}

impl From<pod::DecryptHandle> for PodRistrettoPoint {
    fn from(handle: pod::DecryptHandle) -> Self {
        PodRistrettoPoint(handle.0)
    }
}

impl From<PodRistrettoPoint> for pod::DecryptHandle {
    fn from(point: PodRistrettoPoint) -> Self {
        pod::DecryptHandle(point.0)
    }
}

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::pod,
        crate::{curve25519::scalar::PodScalar, encryption::elgamal::ElGamalError},
        curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
        std::convert::TryFrom,
        subtle::CtOption,
    };

    impl From<Scalar> for PodScalar {
        fn from(scalar: Scalar) -> Self {
            Self(scalar.to_bytes())
        }
    }

    impl TryFrom<PodScalar> for Scalar {
        type Error = ElGamalError;

        fn try_from(pod: PodScalar) -> Result<Self, Self::Error> {
            Scalar::from_canonical_bytes(pod.0).or_else(|| Err(ElGamalError::InvalidScalar))
        }
    }

    impl From<CompressedRistretto> for pod::CompressedRistretto {
        fn from(cr: CompressedRistretto) -> Self {
            Self(cr.to_bytes())
        }
    }

    impl From<pod::CompressedRistretto> for CompressedRistretto {
        fn from(pod: pod::CompressedRistretto) -> Self {
            Self(pod.0)
        }
    }
}

#[cfg(target_os = "solana")]
#[allow(unused_variables)]
mod target_arch {}
