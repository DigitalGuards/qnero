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
//! # What binds one segment to another
//!
//! One rule: no non-padding inner proof appears twice, keyed by the first
//! nullifier of its first slot. Order is free, sizes are free, and the values
//! inside a segment are the inner proof's own. A nullifier shared between two
//! *different* inner proofs is not caught here, and is left to
//! [`QneroPublicBatchProver::prove_batch`](super::QneroPublicBatchProver::prove_batch)
//! and to the chain's settled-nullifier set; `docs/CIRCUIT.md` section 8.3
//! says which half is which and why.
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
    private_batch_pi_len, public_batch_pi_len, slot_nullifier_index, AGGREGATOR_ADDRESS_LEN,
    BLOCK_HASH_START, BLOCK_NUMBER_INDEX, DIGEST_FELTS, HEADER_LEN,
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
    /// public-input count is checked at runtime, because a debug assertion
    /// compiles out and every offset below is derived from `num_leaves`: an
    /// inner circuit of another shape would index out of bounds in a release
    /// build.
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

    // No non-padding inner proof appears twice.
    //
    // Each inner is keyed by the first nullifier of its first slot. That
    // digest is a Poseidon2 output whichever kind of slot it came from: a real
    // slot publishes a note's nullifier, a padding slot publishes a hash of
    // randomness the private-batch prover drew for that run. So two distinct
    // inner proofs share a key only on a collision, and a repeated one shares
    // it by construction.
    //
    // Padding inners are exempt because they are all the same published
    // artifact, cloned into every empty slot, and their whole slot region is
    // zeroed below.
    //
    // What this closes is the duplicated segment, which is the case the chain
    // cannot price: a proof anyone can lift off the mempool, republished `n`
    // times in one batch. A nullifier repeated between two *different* inners
    // stays an admission rule and a settlement rule, because comparing every
    // inner's `2N` nullifiers against every other's is 742 digests at the
    // chain defaults; one key per inner is `n * (n - 1) / 2` equality checks
    // against `n` recursive verifiers, which is noise. The keys are compared
    // for equality: a lexicographic ordering would need the canonical 64-bit
    // split `qnero_circuit::gadgets` deliberately does not carry, and
    // distinctness is all an ordering would have bought here.
    let is_real: Vec<BoolTarget> = is_padding
        .iter()
        .map(|padding| builder.not(*padding))
        .collect();
    let keys: Vec<[Target; DIGEST_FELTS]> = inner_pis
        .iter()
        .map(|pis| core::array::from_fn(|i| pis[slot_nullifier_index(0, 0) + i]))
        .collect();
    for (i, left) in keys.iter().enumerate() {
        for (j, right) in keys.iter().enumerate().skip(i + 1) {
            let both_real = builder.and(is_real[i], is_real[j]);
            let equal = digests_are_equal(builder, *left, *right);
            let collision = builder.and(both_real, equal);
            builder.connect(collision.target, zero);
        }
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

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use plonky2::field::types::PrimeField64;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitData;
    use qnero_circuit::batch_layout::public_batch_inner_start;
    use qnero_circuit::config::{
        qnero_private_batch_circuit_config, qnero_public_batch_circuit_config,
    };
    use qnero_circuit::padding::PADDING_BLOCK_HASH;
    use qnero_note_core::Digest;

    use super::*;
    use crate::padding_proof::generate_padding_leaf_proof;
    use crate::private_batch::QneroPrivateBatchProver;
    use crate::public_batch::witness::fill_public_batch_witness;
    use crate::test_fixtures::{leaf_circuit, leaf_proof};
    use crate::Proof;

    /// One leaf per private batch and two private batches per public batch:
    /// the cheapest circuit that can exercise every cross-inner rule.
    const NUM_LEAVES: usize = 1;
    const NUM_INNER: usize = 2;

    fn private_batch_prover() -> &'static QneroPrivateBatchProver {
        static PROVER: OnceLock<QneroPrivateBatchProver> = OnceLock::new();
        PROVER.get_or_init(|| {
            let (targets, leaf) = leaf_circuit();
            let padding = generate_padding_leaf_proof(leaf, targets).expect("the padding leaf");
            QneroPrivateBatchProver::new(
                qnero_private_batch_circuit_config(),
                leaf.common.clone(),
                &leaf.verifier_only,
                NUM_LEAVES,
                padding,
            )
            .expect("the private batch prover builds")
        })
    }

    fn public_batch_circuit() -> &'static (PublicBatchTargets, CircuitData<F, C, D>) {
        static CIRCUIT: OnceLock<(PublicBatchTargets, CircuitData<F, C, D>)> = OnceLock::new();
        CIRCUIT.get_or_init(|| {
            let inner = private_batch_prover().verifier_data();
            let circuit = QneroPublicBatchCircuit::new(
                qnero_public_batch_circuit_config(),
                &inner.common,
                &inner.verifier_only,
                NUM_INNER,
                NUM_LEAVES,
            )
            .expect("the public batch circuit builds");
            let targets = circuit.targets();
            (targets, circuit.build())
        })
    }

    /// One real private batch anchored at the block named by `tag`.
    fn inner_proof(tag: &str) -> Proof {
        private_batch_prover()
            .aggregate(vec![leaf_proof(tag)])
            .expect("the private batch proves")
    }

    fn address() -> Digest {
        Digest::hash_bytes(&[b"public-batch-circuit/aggregator"])
    }

    /// Fill the public batch's slots directly and prove, past the prover's
    /// admission checks.
    ///
    /// That path is the point. `QneroPublicBatchCircuit` and
    /// `PublicBatchTargets` are both public with public fields, so a caller can
    /// reach the circuit with plonky2's own witness API and never touch
    /// `prove_batch`. A cross-inner constraint that only the preflight enforces
    /// would let such a caller produce a proof the chain then accepts.
    fn prove_directly(inners: &[Proof]) -> Result<Proof> {
        let (targets, data) = public_batch_circuit();
        let mut pw = PartialWitness::<F>::new();
        fill_public_batch_witness(&mut pw, targets, inners, &address())
            .expect("witness filling must succeed, so only the circuit can reject the batch");
        data.prove(pw)
            .map_err(|e| anyhow::anyhow!("the public batch did not prove: {}", e))
    }

    /// Inner batches anchored at two different blocks cannot be aggregated,
    /// and the circuit is what says so.
    ///
    /// The end-to-end test for this stops at `prove_batch`'s preflight, so
    /// without this one the constraint could be deleted with every gate still
    /// green. The chain resolves one block hash per settlement, and a batch
    /// mixing blocks would settle notes against a tree root it never checked.
    #[test]
    fn the_circuit_refuses_inner_batches_from_two_blocks() {
        let inners = [inner_proof("block-a"), inner_proof("block-b")];
        let (_, data) = public_batch_circuit();
        if let Ok(proof) = prove_directly(&inners) {
            assert!(
                data.verify(proof).is_err(),
                "two blocks in one public batch: the circuit produced a proof that verified"
            );
        }
    }

    /// The same inner proof in two slots cannot be aggregated.
    ///
    /// The admission check in `prove_batch` refuses this too, and it is the
    /// one an honest aggregator meets. This test goes past it, because the
    /// circuit is public and a caller willing to fill the witness through
    /// plonky2's own API never reaches that check: without a constraint here,
    /// such a caller republishes one wallet's nullifiers, commitments and fee
    /// `n` times in a proof that verifies against the published
    /// `public_batch_verifier.bin`.
    #[test]
    fn the_circuit_refuses_a_replayed_inner_batch() {
        let inner = inner_proof("replayed");
        let inners = [inner.clone(), inner];
        let (_, data) = public_batch_circuit();
        if let Ok(proof) = prove_directly(&inners) {
            assert!(
                data.verify(proof).is_err(),
                "one inner proof in both slots: the circuit produced a proof that verified"
            );
        }
    }

    /// Two padding inners are the same proof twice, and that has to stay
    /// provable: padding is one published artifact cloned into every empty
    /// slot, so every batch an aggregator pads carries it more than once.
    #[test]
    fn the_circuit_accepts_the_padding_template_in_several_slots() {
        let padding = private_batch_prover()
            .prove_padding_batch()
            .expect("the all-padding private batch proves");
        let inners = [padding.clone(), padding];
        let (_, data) = public_batch_circuit();
        let proof = prove_directly(&inners).expect("a batch of nothing but padding proves");
        data.verify(proof).expect("and verifies");
    }

    /// A padding inner's slot region is zeroed in circuit, header apart.
    ///
    /// The header goes through so the chain recognises a segment to skip; the
    /// zeroing is what stops one published padding template, cloned into every
    /// empty slot of every batch, from republishing the same nullifiers.
    #[test]
    fn the_circuit_zeroes_a_padding_inner_past_its_header() {
        let padding = private_batch_prover()
            .prove_padding_batch()
            .expect("the all-padding private batch proves");
        let inners = [inner_proof("masking"), padding];

        let (_, data) = public_batch_circuit();
        let proof = prove_directly(&inners).expect("a real inner plus a padding inner proves");
        data.verify(proof.clone()).expect("and verifies");

        let inner_len = private_batch_pi_len(NUM_LEAVES);
        let start = public_batch_inner_start(1, NUM_LEAVES);
        let segment = &proof.public_inputs[start..start + inner_len];

        let sentinel: [u64; DIGEST_FELTS] =
            core::array::from_fn(|i| segment[BLOCK_HASH_START + i].to_canonical_u64());
        assert_eq!(
            sentinel, PADDING_BLOCK_HASH,
            "a padding inner keeps its sentinel header"
        );
        assert!(
            segment[HEADER_LEN..]
                .iter()
                .all(|felt| felt.to_canonical_u64() == 0),
            "every felt of a padding inner past the header must be zero"
        );

        // The real segment is untouched, so the masking is per inner.
        let real = &proof.public_inputs[public_batch_inner_start(0, NUM_LEAVES)..][..inner_len];
        assert!(
            real[HEADER_LEN..]
                .iter()
                .any(|felt| felt.to_canonical_u64() != 0),
            "the real inner segment must be forwarded unchanged"
        );
    }
}
