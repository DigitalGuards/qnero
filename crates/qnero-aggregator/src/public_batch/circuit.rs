//! The public batch circuit: verify `n_inner` private-batch proofs and
//! republish their public inputs under one aggregator address.
//!
//! # What this layer is for
//!
//! Amortizing on-chain verification across wallets. A private batch is one
//! wallet's transaction; an aggregator collects many and proves them into one
//! artifact the chain verifies once.
//!
//! # Forwarding is order preserving
//!
//! Each inner proof's public inputs are forwarded verbatim into one contiguous
//! segment, in slot order. Nothing is shuffled, grouped or summed. The chain
//! needs to attribute a settlement failure to one inner proof, and a shuffle
//! here would buy no privacy: the private batch below already blinded, and the
//! values being forwarded are the ones the chain is about to act on.
//!
//! A padding inner is a private batch over nothing but padding leaves, which
//! carries the sentinel block hash. Its header is forwarded unchanged, so the
//! chain recognises the segment and skips it, and its slot region is zeroed.
//! The zeroing is load bearing: the padding template is a fixed artifact
//! cloned into every empty slot, so its nullifiers would otherwise repeat
//! across slots and across batches.
//!
//! # The aggregator address
//!
//! Four felts of pure witness, registered as the first four public inputs and
//! constrained by nothing in circuit. It names who may claim the batch's fees
//! on chain. Whoever holds the proof can re-prove it under another address, so
//! an aggregator that accepts a proof from elsewhere has to compare the
//! exposed address against its own off circuit; see
//! [`QneroPublicBatchProver::verify`](super::QneroPublicBatchProver::verify).

use anyhow::{ensure, Result};
use plonky2::field::types::Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
    VerifierOnlyCircuitData,
};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use qnero_circuit::batch_layout::{
    private_batch_pi_len, public_batch_pi_len, AGGREGATOR_ADDRESS_LEN, BLOCK_HASH_START,
    BLOCK_NUMBER_INDEX, DIGEST_FELTS, HEADER_LEN,
};
use qnero_circuit::config::{ensure_zk_supported, validate_circuit_config};
use qnero_circuit::gadgets::digests_are_equal;
use qnero_circuit::padding::{padding_block_hash_target, PADDING_BLOCK_NUMBER};
use qnero_circuit::{C, D, F};

use crate::config::validate_proof_count;
use crate::recursive::add_recursive_verifiers;

/// Every witness target of the public batch circuit.
#[derive(Debug, Clone)]
pub struct PublicBatchTargets {
    /// One private-batch proof per slot.
    pub private_batch_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// The aggregator's address. Witnessed, and registered verbatim as the
    /// first four public inputs.
    pub aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN],
}

/// The public batch circuit, before it is built.
pub struct QneroPublicBatchCircuit {
    builder: CircuitBuilder<F, D>,
    targets: PublicBatchTargets,
    num_inner: usize,
    num_leaves: usize,
}

impl core::fmt::Debug for QneroPublicBatchCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroPublicBatchCircuit")
            .field("num_inner", &self.num_inner)
            .field("num_leaves", &self.num_leaves)
            .field("num_gates", &self.builder.num_gates())
            .finish()
    }
}

impl QneroPublicBatchCircuit {
    /// Build the constraint system over `num_inner` private batches of
    /// `num_leaves` slots each.
    ///
    /// The private-batch verifier key is baked in as constants. The inner
    /// public-input count is checked at runtime rather than asserted, because
    /// every offset below is derived from `num_leaves` and an inner circuit of
    /// another shape would index out of bounds in a release build.
    pub fn new(
        config: CircuitConfig,
        private_batch_common: &CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_inner: usize,
        num_leaves: usize,
    ) -> Result<Self> {
        validate_circuit_config(&config)?;
        ensure_zk_supported(&config)?;
        validate_proof_count(num_inner, "num_private_batch_proofs")?;
        validate_proof_count(num_leaves, "num_leaf_proofs")?;

        let expected = private_batch_pi_len(num_leaves);
        ensure!(
            private_batch_common.num_public_inputs == expected,
            "the inner circuit has {} public inputs, but a private batch over {} leaves has {}",
            private_batch_common.num_public_inputs,
            num_leaves,
            expected
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let private_batch_proofs = add_recursive_verifiers(
            &mut builder,
            private_batch_common,
            private_batch_verifier_only,
            num_inner,
        )?;
        let aggregator_address: [Target; AGGREGATOR_ADDRESS_LEN] =
            core::array::from_fn(|_| builder.add_virtual_target());

        let targets = PublicBatchTargets {
            private_batch_proofs,
            aggregator_address,
        };
        build_public_batch_constraints(&mut builder, &targets, num_inner, num_leaves);

        Ok(Self {
            builder,
            targets,
            num_inner,
            num_leaves,
        })
    }

    pub fn targets(&self) -> PublicBatchTargets {
        self.targets.clone()
    }

    pub fn num_inner(&self) -> usize {
        self.num_inner
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn num_gates(&self) -> usize {
        self.builder.num_gates()
    }

    pub fn build(self) -> CircuitData<F, C, D> {
        self.builder.build::<C>()
    }

    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover::<C>()
    }

    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier::<C>()
    }
}

fn build_public_batch_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &PublicBatchTargets,
    num_inner: usize,
    num_leaves: usize,
) {
    let zero = builder.zero();
    let one = builder.one();
    let inner_len = private_batch_pi_len(num_leaves);

    let inner_pis: Vec<&[Target]> = targets
        .private_batch_proofs
        .iter()
        .map(|proof| proof.public_inputs.as_slice())
        .collect();
    debug_assert!(inner_pis.iter().all(|pis| pis.len() == inner_len));

    // A padding inner is an all-padding private batch, which keeps the
    // sentinel as its block reference.
    let sentinel = padding_block_hash_target(builder);
    let mut is_padding: Vec<BoolTarget> = Vec::with_capacity(num_inner);
    let mut block_hashes: Vec<[Target; DIGEST_FELTS]> = Vec::with_capacity(num_inner);
    for pis in &inner_pis {
        let block_hash: [Target; DIGEST_FELTS] =
            core::array::from_fn(|i| pis[BLOCK_HASH_START + i]);
        is_padding.push(digests_are_equal(builder, block_hash, sentinel.elements));
        block_hashes.push(block_hash);
    }

    // One block per public batch, taken from the first non-padding inner.
    // Restricting a batch to one block is what lets the chain resolve a single
    // block hash for the whole settlement; an aggregator therefore buckets the
    // proofs it pools by block.
    //
    // The reference is not published. Each inner's header is forwarded as it
    // stands, so the chain reads the block off any segment; what the reference
    // exists for is the agreement check below.
    let mut found_real = builder._false();
    let mut block_ref = sentinel.elements;
    let mut block_number_ref = builder.constant(F::from_canonical_u32(PADDING_BLOCK_NUMBER));
    for inner in 0..num_inner {
        let is_real = builder.not(is_padding[inner]);
        let not_found_yet = builder.not(found_real);
        let take = builder.and(is_real, not_found_yet);
        for limb in 0..DIGEST_FELTS {
            block_ref[limb] = builder.select(take, block_hashes[inner][limb], block_ref[limb]);
        }
        block_number_ref =
            builder.select(take, inner_pis[inner][BLOCK_NUMBER_INDEX], block_number_ref);
        found_real = builder.or(found_real, is_real);
    }
    for inner in 0..num_inner {
        let hash_matches = digests_are_equal(builder, block_hashes[inner], block_ref);
        let hash_ok = builder.or(is_padding[inner], hash_matches);
        builder.connect(hash_ok.target, one);

        let number_matches =
            builder.is_equal(inner_pis[inner][BLOCK_NUMBER_INDEX], block_number_ref);
        let number_ok = builder.or(is_padding[inner], number_matches);
        builder.connect(number_ok.target, one);
    }

    let mut output: Vec<Target> = Vec::with_capacity(public_batch_pi_len(num_inner, num_leaves));
    output.extend_from_slice(&targets.aggregator_address);

    for inner in 0..num_inner {
        let pis = inner_pis[inner];
        // The header goes through untouched, padding inner included: a segment
        // that carries the sentinel is one the chain skips, and forwarding it
        // as it stands is what makes the sentinel readable at this layer.
        output.extend_from_slice(&pis[..HEADER_LEN]);
        for forwarded in &pis[HEADER_LEN..inner_len] {
            let masked = builder.select(is_padding[inner], zero, *forwarded);
            output.push(masked);
        }
    }

    assert_eq!(
        output.len(),
        public_batch_pi_len(num_inner, num_leaves),
        "the public batch emitted {} public inputs, but the layout says {}",
        output.len(),
        public_batch_pi_len(num_inner, num_leaves)
    );
    builder.register_public_inputs(&output);
}
