use crate::{
    curve25519::{
        ristretto::{add_ristretto, multiply_ristretto, subtract_ristretto, PodRistrettoPoint},
        scalar::PodScalar,
    },
    zk_token_elgamal::pod,
};

const SHIFT_BITS: usize = 16;

const G: PodRistrettoPoint = PodRistrettoPoint([
    226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11, 106, 165,
    130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
]);

/// Add two ElGamal ciphertexts
pub fn add(
    left_ciphertext: &pod::ElGamalCiphertext,
    right_ciphertext: &pod::ElGamalCiphertext,
) -> Option<pod::ElGamalCiphertext> {
    let (left_commitment, left_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
        (*left_ciphertext).into();
    let (right_commitment, right_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
        (*right_ciphertext).into();

    let result_commitment: pod::PedersenCommitment =
        add_ristretto(&left_commitment.into(), &right_commitment.into())?.into();
    let result_handle: pod::DecryptHandle =
        add_ristretto(&left_handle.into(), &right_handle.into())?.into();

    Some((result_commitment, result_handle).into())
}

/// Multiply an ElGamal ciphertext by a scalar
pub fn multiply(
    scalar: &PodScalar,
    ciphertext: &pod::ElGamalCiphertext,
) -> Option<pod::ElGamalCiphertext> {
    let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) = (*ciphertext).into();

    let commitment_point: PodRistrettoPoint = commitment.into();
    let handle_point: PodRistrettoPoint = handle.into();

    let result_commitment: pod::PedersenCommitment =
        multiply_ristretto(scalar, &commitment_point)?.into();
    let result_handle: pod::DecryptHandle = multiply_ristretto(scalar, &handle_point)?.into();

    Some((result_commitment, result_handle).into())
}

/// Compute `left_ciphertext + (right_ciphertext_lo + 2^16 * right_ciphertext_hi)`
pub fn add_with_lo_hi(
    left_ciphertext: &pod::ElGamalCiphertext,
    right_ciphertext_lo: &pod::ElGamalCiphertext,
    right_ciphertext_hi: &pod::ElGamalCiphertext,
) -> Option<pod::ElGamalCiphertext> {
    let shift_scalar = to_scalar(1_u64 << SHIFT_BITS);
    let shifted_right_ciphertext_hi = multiply(&shift_scalar, right_ciphertext_hi)?;
    let combined_right_ciphertext = add(right_ciphertext_lo, &shifted_right_ciphertext_hi)?;
    add(left_ciphertext, &combined_right_ciphertext)
}

/// Subtract two ElGamal ciphertexts
pub fn subtract(
    left_ciphertext: &pod::ElGamalCiphertext,
    right_ciphertext: &pod::ElGamalCiphertext,
) -> Option<pod::ElGamalCiphertext> {
    let (left_commitment, left_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
        (*left_ciphertext).into();
    let (right_commitment, right_handle): (pod::PedersenCommitment, pod::DecryptHandle) =
        (*right_ciphertext).into();

    let result_commitment: pod::PedersenCommitment =
        subtract_ristretto(&left_commitment.into(), &right_commitment.into())?.into();
    let result_handle: pod::DecryptHandle =
        subtract_ristretto(&left_handle.into(), &right_handle.into())?.into();

    Some((result_commitment, result_handle).into())
}

/// Compute `left_ciphertext - (right_ciphertext_lo + 2^16 * right_ciphertext_hi)`
pub fn subtract_with_lo_hi(
    left_ciphertext: &pod::ElGamalCiphertext,
    right_ciphertext_lo: &pod::ElGamalCiphertext,
    right_ciphertext_hi: &pod::ElGamalCiphertext,
) -> Option<pod::ElGamalCiphertext> {
    let shift_scalar = to_scalar(1_u64 << SHIFT_BITS);
    let shifted_right_ciphertext_hi = multiply(&shift_scalar, right_ciphertext_hi)?;
    let combined_right_ciphertext = add(right_ciphertext_lo, &shifted_right_ciphertext_hi)?;
    subtract(left_ciphertext, &combined_right_ciphertext)
}

/// Add a constant amount to a ciphertext
pub fn add_to(ciphertext: &pod::ElGamalCiphertext, amount: u64) -> Option<pod::ElGamalCiphertext> {
    let amount_scalar = to_scalar(amount);
    let amount_point = multiply_ristretto(&amount_scalar, &G)?;

    let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) = (*ciphertext).into();
    let commitment_point: PodRistrettoPoint = commitment.into();

    let result_commitment: pod::PedersenCommitment =
        add_ristretto(&commitment_point, &amount_point)?.into();
    Some((result_commitment, handle).into())
}

/// Subtract a constant amount to a ciphertext
pub fn subtract_from(
    ciphertext: &pod::ElGamalCiphertext,
    amount: u64,
) -> Option<pod::ElGamalCiphertext> {
    let amount_scalar = to_scalar(amount);
    let amount_point = multiply_ristretto(&amount_scalar, &G)?;

    let (commitment, handle): (pod::PedersenCommitment, pod::DecryptHandle) = (*ciphertext).into();
    let commitment_point: PodRistrettoPoint = commitment.into();

    let result_commitment: pod::PedersenCommitment =
        subtract_ristretto(&commitment_point, &amount_point)?.into();
    Some((result_commitment, handle).into())
}

/// Convert a `u64` amount into a curve25519 scalar
fn to_scalar(amount: u64) -> PodScalar {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&amount.to_le_bytes());
    PodScalar(bytes)
}
