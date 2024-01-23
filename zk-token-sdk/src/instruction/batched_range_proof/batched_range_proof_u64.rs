//! The 64-bit batched range proof instruction.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        errors::{ProofGenerationError, ProofVerificationError},
        instruction::batched_range_proof::MAX_COMMITMENTS,
        range_proof::RangeProof,
    },
    std::convert::TryInto,
};
use {
    crate::{
        instruction::{batched_range_proof::BatchedRangeProofContext, ProofType, ZkProofData},
        zk_token_elgamal::pod,
    },
    bytemuck::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyBatchedRangeProofU64` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofU64Data {
    /// The context data for a batched range proof
    pub context: BatchedRangeProofContext,

    /// The batched range proof
    pub proof: pod::RangeProofU64,
}

#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofU64Data {
    pub fn new(
        commitments: Vec<&PedersenCommitment>,
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        openings: Vec<&PedersenOpening>,
    ) -> Result<Self, ProofGenerationError> {
        // the sum of the bit lengths must be 64
        let batched_bit_length = bit_lengths
            .iter()
            .try_fold(0_usize, |acc, &x| acc.checked_add(x))
            .ok_or(ProofGenerationError::IllegalAmountBitLength)?;

        // `u64::BITS` is 64, which fits in a single byte and should not overflow to `usize` for an
        // overwhelming number of platforms. However, to be extra cautious, use `try_from` and
        // `unwrap` here. A simple case `u64::BITS as usize` can silently overflow.
        let expected_bit_length = usize::try_from(u64::BITS).unwrap();
        if batched_bit_length != expected_bit_length {
            return Err(ProofGenerationError::IllegalAmountBitLength);
        }

        let context =
            BatchedRangeProofContext::new(&commitments, &amounts, &bit_lengths, &openings)?;

        let mut transcript = context.new_transcript();
        let proof = RangeProof::new(amounts, bit_lengths, openings, &mut transcript)?
            .try_into()
            .map_err(|_| ProofGenerationError::ProofLength)?;

        Ok(Self { context, proof })
    }
}

impl ZkProofData<BatchedRangeProofContext> for BatchedRangeProofU64Data {
    const PROOF_TYPE: ProofType = ProofType::BatchedRangeProofU64;

    fn context_data(&self) -> &BatchedRangeProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let (commitments, bit_lengths) = self.context.try_into()?;
        let num_commitments = commitments.len();

        if num_commitments > MAX_COMMITMENTS || num_commitments != bit_lengths.len() {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        let mut transcript = self.context_data().new_transcript();
        let proof: RangeProof = self.proof.try_into()?;

        proof
            .verify(commitments.iter().collect(), bit_lengths, &mut transcript)
            .map_err(|e| e.into())
    }
}
