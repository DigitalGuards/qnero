//! The private batch circuit: verify `N` leaf proofs recursively, agree on one
//! block, mask the padding slots, and republish every real slot's values.
//!
//! This is the layer that blinds (`qnero_private_batch_circuit_config`), and
//! its proof is the transaction unit a wallet submits.
//!
//! # The constraints, in order
//!
//! 1. Each slot's leaf proof verifies against the constant leaf verifier key.
//! 2. A slot is padding exactly when its leaf published the sentinel block
//!    hash. The flag is read off the leaf's public inputs; nothing is
//!    witnessed.
//! 3. The batch's block reference is the first non-padding slot's, chosen by a
//!    prefix scan, so slot order carries no meaning and the prover may shuffle
//!    uniformly.
//! 4. Every non-padding slot agrees with that reference on block hash and
//!    block number.
//! 5. Every slot's six published values are forwarded, masked when the slot is
//!    padding: nullifiers become hashes of caller-supplied fresh randomness,
//!    while commitments, fee and `ct_digest` become zero.
//! 6. The `2N` nullifiers the batch publishes are pairwise distinct, padding
//!    slots included.
//!
//! # Why the `2N` in constraint 6
//!
//! A Qnero leaf publishes two nullifiers, one per input slot, and either may
//! belong to a dummy input. Constraining only one per leaf would let the same
//! leaf proof occupy several batch slots: the chain settles the one nullifier
//! it sees twice and refuses the second, but only after the batch has been
//! accepted as a whole. Constraining all `2N` makes such a batch unprovable.
//! The chain's persistent nullifier set remains the cross-batch boundary.
//!
//! The comparison is on the emitted values, and no slot is exempt. A padding
//! slot's emitted nullifiers are hashes of free witness targets, so a caller
//! filling the witness through plonky2's own API could otherwise repeat one
//! preimage across two padding slots and publish one nullifier twice inside
//! one segment. A chain settling the segment by one rule would then insert a
//! duplicate or take an error path mid-settlement.
//!
//! # Why the fees are not summed here
//!
//! Each leaf's fee is a 62-bit value, so `N` of them can overflow the
//! Goldilocks field for `N` above 3. The wrapper forwards each fee and the
//! pallet sums them in native arithmetic, where the total is a `u128`. This is
//! the one place Qnero's wrapper does less than upstream's, which enforces a
//! volume fee over 32-bit amounts in circuit.

use anyhow::{ensure, Result};
use plonky2::field::types::Field;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, ProverCircuitData, VerifierCircuitData,
    VerifierOnlyCircuitData,
};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use qnero_circuit::batch_layout::{private_batch_pi_len, DIGEST_FELTS};
use qnero_circuit::config::{ensure_zk_supported, validate_circuit_config};
use qnero_circuit::convert::felt_to_plonky2;
use qnero_circuit::gadgets::digests_are_equal;
use qnero_circuit::layout::{
    commitment_index, nullifier_index, BLOCK_HASH_START, BLOCK_NUMBER_INDEX, CT_DIGEST_START,
    FEE_INDEX, NUM_INPUTS, NUM_OUTPUTS, PUBLIC_INPUT_LEN,
};
use qnero_circuit::padding::{padding_block_hash_target, PADDING_BLOCK_NUMBER};
use qnero_circuit::{C, D, F};
use qnero_note_core::digest::domain;

use crate::config::validate_proof_count;
use crate::recursive::add_recursive_verifiers;

/// Nullifier replacements a padding slot publishes: one preimage per input
/// slot of the padded leaf.
pub type PaddingNullifierPreimages = [[Target; DIGEST_FELTS]; NUM_INPUTS];

/// Every witness target of the private batch circuit.
#[derive(Debug, Clone)]
pub struct PrivateBatchTargets {
    /// One leaf proof per slot.
    pub leaf_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Two nullifier preimages per slot, used only when the slot is padding.
    pub padding_nullifier_preimages: Vec<PaddingNullifierPreimages>,
}

/// The private batch circuit, before it is built.
pub struct QneroPrivateBatchCircuit {
    builder: CircuitBuilder<F, D>,
    targets: PrivateBatchTargets,
    num_leaves: usize,
}

impl core::fmt::Debug for QneroPrivateBatchCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroPrivateBatchCircuit")
            .field("num_leaves", &self.num_leaves)
            .field("num_gates", &self.builder.num_gates())
            .finish()
    }
}

impl QneroPrivateBatchCircuit {
    /// Build the constraint system over `num_leaves` slots.
    ///
    /// `leaf_verifier_only` is baked in as constants, so this circuit only
    /// ever accepts proofs of that one leaf circuit.
    ///
    /// The checks run before `CircuitBuilder::new`, in the order a failure is
    /// cheapest: the config policy, the slot count, then the inner circuit's
    /// public-input count. The last one is a runtime check, because a debug
    /// assertion compiles out and the constraints below index fixed offsets
    /// into each leaf's public inputs: a leaf of another shape would read a
    /// commitment where a nullifier should be.
    pub fn new(
        config: CircuitConfig,
        leaf_common: &CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_leaves: usize,
    ) -> Result<Self> {
        validate_circuit_config(&config)?;
        ensure_zk_supported(&config)?;
        validate_proof_count(num_leaves, "num_leaves")?;
        ensure!(
            leaf_common.num_public_inputs == PUBLIC_INPUT_LEN,
            "the inner circuit has {} public inputs, but a Qnero leaf has {}; refusing to build \
             a private batch over a circuit that is not the leaf",
            leaf_common.num_public_inputs,
            PUBLIC_INPUT_LEN
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_proofs =
            add_recursive_verifiers(&mut builder, leaf_common, leaf_verifier_only, num_leaves)?;

        let padding_nullifier_preimages = (0..num_leaves)
            .map(|_| {
                core::array::from_fn(|_| core::array::from_fn(|_| builder.add_virtual_target()))
            })
            .collect();

        let targets = PrivateBatchTargets {
            leaf_proofs,
            padding_nullifier_preimages,
        };
        build_private_batch_constraints(&mut builder, &targets, num_leaves);

        Ok(Self {
            builder,
            targets,
            num_leaves,
        })
    }

    pub fn targets(&self) -> PrivateBatchTargets {
        self.targets.clone()
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Gates before padding, for the size report.
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

/// Read one 4-felt digest out of a leaf proof's public inputs.
fn digest_at(pis: &[Target], start: usize) -> [Target; DIGEST_FELTS] {
    core::array::from_fn(|i| pis[start + i])
}

/// `H(NF_BATCH_PADDING, preimage)`: the nullifier a padding slot publishes.
///
/// The preimage is fresh randomness the prover supplies per slot per proving
/// run, so two padding slots never publish the same value and cloning one
/// padding template into many slots cannot collide. The chain can settle them
/// like any other nullifier, and settling them is inert. It does not hide
/// which slots were padding: the wrapper zeroes a padding slot's commitment
/// pair and a real slot's commitments are Poseidon2 outputs, so the padding
/// positions are public either way (`docs/CIRCUIT.md` section 8.4).
///
/// The domain tag is the point. A padding nullifier is unauthenticated by
/// construction: the prover picks the preimage. Under the real `NF` tag that
/// would be a burn primitive, letting one batch settle a nullifier for a note
/// nobody spent. Under its own tag, reaching a chosen value is a preimage
/// attack on Poseidon2, exactly as for the leaf's own `NF_DUMMY` slots.
fn padding_nullifier(
    builder: &mut CircuitBuilder<F, D>,
    preimage: [Target; DIGEST_FELTS],
) -> [Target; DIGEST_FELTS] {
    let tag = builder.constant(felt_to_plonky2(domain::NF_BATCH_PADDING));
    let mut input = Vec::with_capacity(1 + DIGEST_FELTS);
    input.push(tag);
    input.extend_from_slice(&preimage);
    builder
        .hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(input)
        .elements
}

fn build_private_batch_constraints(
    builder: &mut CircuitBuilder<F, D>,
    targets: &PrivateBatchTargets,
    num_leaves: usize,
) {
    let zero = builder.zero();
    let one = builder.one();

    let leaf_pis: Vec<&[Target]> = targets
        .leaf_proofs
        .iter()
        .map(|proof| proof.public_inputs.as_slice())
        .collect();
    // Guaranteed by the constructor's public-input check; this only guards a
    // future caller that builds the targets by hand.
    debug_assert!(leaf_pis.iter().all(|pis| pis.len() == PUBLIC_INPUT_LEN));

    // --- 2. padding flags, derived from each leaf's published block hash ---
    let sentinel = padding_block_hash_target(builder);
    let mut is_padding: Vec<BoolTarget> = Vec::with_capacity(num_leaves);
    let mut block_hashes: Vec<[Target; DIGEST_FELTS]> = Vec::with_capacity(num_leaves);
    for pis in &leaf_pis {
        let block_hash = digest_at(pis, BLOCK_HASH_START);
        is_padding.push(digests_are_equal(builder, block_hash, sentinel.elements));
        block_hashes.push(block_hash);
    }

    // --- 3. the block reference, from the first non-padding slot ---
    //
    // A prefix scan, so no position is special and the prover can shuffle the
    // slots uniformly. An all-padding batch
    // keeps the sentinel as its reference, which the chain recognises as a
    // batch that settles nothing: the public-batch layer uses exactly that to
    // pad itself.
    let mut found_real = builder._false();
    let mut block_ref = sentinel.elements;
    let mut block_number_ref = builder.constant(F::from_canonical_u32(PADDING_BLOCK_NUMBER));
    for slot in 0..num_leaves {
        let is_real = builder.not(is_padding[slot]);
        let not_found_yet = builder.not(found_real);
        let take = builder.and(is_real, not_found_yet);

        for limb in 0..DIGEST_FELTS {
            block_ref[limb] = builder.select(take, block_hashes[slot][limb], block_ref[limb]);
        }
        block_number_ref =
            builder.select(take, leaf_pis[slot][BLOCK_NUMBER_INDEX], block_number_ref);
        found_real = builder.or(found_real, is_real);
    }

    // --- 4. every non-padding slot agrees with the reference ---
    //
    // The block number check is implied by the hash check, since each leaf
    // binds its number inside the header preimage the hash commits to. It is
    // kept because it costs one gate per slot and because the aggregated
    // header publishes both, so both should be pinned to something.
    for slot in 0..num_leaves {
        let hash_matches = digests_are_equal(builder, block_hashes[slot], block_ref);
        let hash_ok = builder.or(is_padding[slot], hash_matches);
        builder.connect(hash_ok.target, one);

        let number_matches = builder.is_equal(leaf_pis[slot][BLOCK_NUMBER_INDEX], block_number_ref);
        let number_ok = builder.or(is_padding[slot], number_matches);
        builder.connect(number_ok.target, one);
    }

    let mut output: Vec<Target> = Vec::with_capacity(private_batch_pi_len(num_leaves));
    output.extend_from_slice(&block_ref);
    output.push(block_number_ref);

    // --- 5. forward every slot, masked when it is padding ---
    //
    // Six values per slot, in the order `qnero_circuit::batch_layout`
    // documents. Nothing is summed, grouped or deduplicated: the chain needs
    // each leaf's own values, and a wrapper that merged them would have to
    // decide what a collision means.
    //
    // The mask trusts no invariant that crosses a circuit boundary. A padding
    // leaf's fee and output values are already forced to zero by the leaf's
    // own balance equation, and its commitments are hashes of zero-value
    // notes; masking here is what makes a padding slot settle nothing even if
    // a template were substituted or the leaf's rule changed.
    let mut emitted_nullifiers: Vec<[Target; DIGEST_FELTS]> =
        Vec::with_capacity(num_leaves * NUM_INPUTS);
    for slot in 0..num_leaves {
        let pis = leaf_pis[slot];
        let padding = is_padding[slot];

        for input in 0..NUM_INPUTS {
            let published = digest_at(pis, nullifier_index(input));
            let replacement =
                padding_nullifier(builder, targets.padding_nullifier_preimages[slot][input]);
            // What the slot actually publishes, which is what constraint 6
            // below compares. A padding slot carries the padding template's
            // own nullifiers, and that template is one artifact cloned into
            // every empty slot, so the leaf-side values repeat across padding
            // slots and only the emitted ones can be compared.
            let emitted: [Target; DIGEST_FELTS] = core::array::from_fn(|limb| {
                builder.select(padding, replacement[limb], published[limb])
            });
            output.extend_from_slice(&emitted);
            emitted_nullifiers.push(emitted);
        }

        for note in 0..NUM_OUTPUTS {
            let published = digest_at(pis, commitment_index(note));
            for limb in published {
                let masked = builder.select(padding, zero, limb);
                output.push(masked);
            }
        }

        let fee = builder.select(padding, zero, pis[FEE_INDEX]);
        output.push(fee);

        let ct_digest = digest_at(pis, CT_DIGEST_START);
        for limb in ct_digest {
            let masked = builder.select(padding, zero, limb);
            output.push(masked);
        }
    }

    // --- 6. the 2N emitted nullifiers are pairwise distinct ---
    //
    // Every pair, padding slots included, because this is the vector the
    // batch publishes and the chain settles. Exempting padding slots would
    // leave their emitted values unconstrained: the preimages are free
    // witnesses, so one repeated preimage in two padding slots publishes one
    // nullifier twice inside a single settleable segment. An honest batch
    // always satisfies this. Two real slots is the rule that was always
    // here, a real slot against a padding one is separated by the
    // `NF_BATCH_PADDING` tag, and two padding slots are separated by the
    // fresh randomness the prover draws per slot per run.
    for (i, left) in emitted_nullifiers.iter().enumerate() {
        for right in emitted_nullifiers.iter().skip(i + 1) {
            let equal = digests_are_equal(builder, *left, *right);
            builder.connect(equal.target, zero);
        }
    }

    assert_eq!(
        output.len(),
        private_batch_pi_len(num_leaves),
        "the private batch emitted {} public inputs, but the layout says {}",
        output.len(),
        private_batch_pi_len(num_leaves)
    );
    builder.register_public_inputs(&output);
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitData;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use qnero_circuit::config::qnero_private_batch_circuit_config;

    use super::*;
    use crate::private_batch::witness::fill_private_batch_witness;
    // One leaf circuit and one leaf witness shape for the whole lib test
    // binary. A second copy here would build the leaf circuit twice and would
    // keep proving the old witness shape after the shared one changed.
    use crate::test_fixtures::{leaf_circuit, leaf_proof};

    /// Two slots: enough to exercise every cross-slot constraint, and the
    /// cheapest circuit that can.
    const SLOTS: usize = 2;

    fn batch_circuit() -> &'static (PrivateBatchTargets, CircuitData<F, C, D>) {
        static CIRCUIT: OnceLock<(PrivateBatchTargets, CircuitData<F, C, D>)> = OnceLock::new();
        CIRCUIT.get_or_init(|| {
            let (_, leaf) = leaf_circuit();
            let circuit = QneroPrivateBatchCircuit::new(
                qnero_private_batch_circuit_config(),
                &leaf.common,
                &leaf.verifier_only,
                SLOTS,
            )
            .expect("the batch circuit builds");
            let targets = circuit.targets();
            (targets, circuit.build())
        })
    }

    fn preimages() -> Vec<crate::private_batch::witness::SlotPaddingPreimages> {
        (0..SLOTS)
            .map(|slot| {
                core::array::from_fn(|input| {
                    core::array::from_fn(|limb| {
                        F::from_canonical_u64((slot * 17 + input * 7 + limb + 1) as u64)
                    })
                })
            })
            .collect()
    }

    /// A batch the circuit must refuse either at witness generation or at
    /// verification.
    ///
    /// The two slots are filled directly, past the prover's admission checks,
    /// which is the only way to see whether the constraints themselves hold.
    /// Without this, deleting a cross-slot constraint would leave the prover's
    /// preflight as the only thing rejecting these batches, and a caller that
    /// reached the circuit another way would get a proof.
    fn assert_batch_refused(proofs: &[ProofWithPublicInputs<F, C, D>], what: &str) {
        assert_batch_refused_with(proofs, &preimages(), what);
    }

    /// [`assert_batch_refused`] with the padding randomness chosen by the
    /// caller, for the cases where that randomness is the defect.
    fn assert_batch_refused_with(
        proofs: &[ProofWithPublicInputs<F, C, D>],
        padding_preimages: &[crate::private_batch::witness::SlotPaddingPreimages],
        what: &str,
    ) {
        let (targets, data) = batch_circuit();
        let mut pw = PartialWitness::<F>::new();
        fill_private_batch_witness(&mut pw, targets, proofs, padding_preimages)
            .expect("witness filling must succeed, so only the circuit can reject the batch");
        if let Ok(proof) = data.prove(pw) {
            assert!(
                data.verify(proof).is_err(),
                "{what}: the circuit produced a proof that verified"
            );
        }
    }

    /// The padding leaf, proved once for this module.
    fn padding_leaf() -> &'static ProofWithPublicInputs<F, C, D> {
        static PADDING: OnceLock<ProofWithPublicInputs<F, C, D>> = OnceLock::new();
        PADDING.get_or_init(|| {
            let (targets, data) = leaf_circuit();
            crate::padding_proof::generate_padding_leaf_proof(data, targets)
                .expect("the padding leaf proves")
        })
    }

    /// Two leaves anchored at different blocks cannot be aggregated.
    ///
    /// The chain resolves one block hash per settlement, so a batch mixing
    /// blocks would settle notes against a tree root the chain never checked.
    #[test]
    fn the_circuit_refuses_leaves_from_two_blocks() {
        let proofs = [leaf_proof("block-a"), leaf_proof("block-b")];
        assert_batch_refused(&proofs, "two blocks in one batch");
    }

    /// The same leaf proof in both slots cannot be aggregated.
    ///
    /// Both slots would publish the same two nullifiers while carrying two
    /// slots' worth of new commitments, and the chain settles a repeated
    /// nullifier once.
    #[test]
    fn the_circuit_refuses_a_replayed_leaf_proof() {
        let proof = leaf_proof("replayed");
        let proofs = [proof.clone(), proof];
        assert_batch_refused(&proofs, "one leaf proof in both slots");
    }

    /// Two padding slots may not publish the same nullifier.
    ///
    /// The padding preimages are free witness targets and this circuit is
    /// public, so the only thing keeping two padding slots apart on the honest
    /// path is the fresh randomness the prover draws. A caller filling the
    /// witness directly repeats one preimage set across both slots; the
    /// emitted nullifiers then collide, and constraint 6 has to be what
    /// refuses that. It cannot be, if the comparison reads the leaf's own
    /// published values or exempts padding slots: the padding template is one
    /// proof cloned into every empty slot, so every padding slot's published
    /// nullifiers are already identical.
    #[test]
    fn the_circuit_refuses_two_padding_slots_with_one_preimage() {
        let padding = padding_leaf().clone();
        let proofs = [padding.clone(), padding];
        let repeated: Vec<crate::private_batch::witness::SlotPaddingPreimages> =
            vec![preimages()[0]; SLOTS];
        assert_batch_refused_with(&proofs, &repeated, "one padding preimage set in both slots");
    }

    /// The same batch with distinct randomness proves, so the test above fails
    /// on the repeat and not on something the padding path does anyway.
    #[test]
    fn an_all_padding_batch_with_fresh_preimages_proves() {
        let padding = padding_leaf().clone();
        let proofs = [padding.clone(), padding];
        let (targets, data) = batch_circuit();
        let mut pw = PartialWitness::<F>::new();
        fill_private_batch_witness(&mut pw, targets, &proofs, &preimages())
            .expect("the witness fills");
        let proof = data.prove(pw).expect("an all-padding batch proves");
        data.verify(proof).expect("and verifies");
    }

    /// The inner circuit's public-input count is checked at construction, so a
    /// wrapper is never built over a circuit that is not the leaf.
    #[test]
    fn a_circuit_that_is_not_the_leaf_is_refused() {
        let mut builder = CircuitBuilder::<F, D>::new(qnero_private_batch_circuit_config());
        let target = builder.add_virtual_target();
        builder.register_public_input(target);
        let other = builder.build::<C>();

        let error = QneroPrivateBatchCircuit::new(
            qnero_private_batch_circuit_config(),
            &other.common,
            &other.verifier_only,
            SLOTS,
        )
        .expect_err("a non-leaf inner circuit must be refused");
        assert!(error.to_string().contains("public inputs"), "got: {error}");
    }

    #[test]
    fn out_of_range_slot_counts_are_refused() {
        let (_, leaf) = leaf_circuit();
        for slots in [0, crate::config::MAX_PROOF_COUNT + 1] {
            assert!(QneroPrivateBatchCircuit::new(
                qnero_private_batch_circuit_config(),
                &leaf.common,
                &leaf.verifier_only,
                slots,
            )
            .is_err());
        }
    }
}
