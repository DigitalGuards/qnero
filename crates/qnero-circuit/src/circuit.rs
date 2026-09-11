//! The Qnero v0 spend leaf: one shielded transfer, up to two input notes,
//! exactly two output notes.
//!
//! Structure follows `qp-zk-circuits` `wormhole/circuit/src/circuit.rs`: one
//! `Targets` struct that decides the public-input layout, one function that
//! adds every constraint, and a builder wrapper that validates its config
//! before plonky2 sees it.
//!
//! What the leaf proves, in one paragraph. The public `block_hash` is the
//! Poseidon2 hash of a header preimage the prover supplies; that header
//! carries a private `zk_tree_root`. Each input note's commitment is
//! recomputed from a spend key the prover holds, and a Merkle path takes that
//! commitment to `zk_tree_root`. Each input's nullifier is recomputed from the
//! same nullifier key and note randomness and published, under a domain tag
//! that says whether the slot was real. Each output's commitment is
//! recomputed and published. Values balance as a field equation over 62-bit
//! terms. The chain then only has to check that `block_hash` is a block it
//! produced, that neither nullifier has been seen, and that the ciphertexts it
//! was handed hash to `ct_digest`.
//!
//! One leaf is not a real transfer: the batch padding leaf, whose `block_hash`
//! is the fixed sentinel in [`crate::padding`]. It is the only leaf allowed to
//! consume no note, and the balance equation then forces its fee and both
//! output values to zero. Everything it publishes is masked by the batch
//! wrapper one layer up.

use anyhow::Result;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData,
};
use qnero_note_core::VALUE_BITS;

use crate::config::{ensure_zk_supported, qnero_leaf_circuit_config, validate_circuit_config};
use crate::gadgets::{const_less_than_bits, digests_are_equal};
use crate::header::{constrain_header, HeaderTargets};
use crate::layout::{NUM_INPUTS, NUM_OUTPUTS};
use crate::merkle::{
    active_level_flags_from_bits, merkle_root_from_path, MerklePathTargets, DEPTH_BITS, MAX_DEPTH,
};
use crate::note_gadget::{
    derive_pk, note_commitment, note_inner, note_nullifier_tagged, nullifier_domain_tag, output_rho,
};
use crate::padding::is_padding_block_hash;
use crate::{C, D, F};

/// Private targets for one input note.
#[derive(Debug, Clone)]
pub struct InputNoteTargets {
    /// Spend authorizing key. `pk` is derived from it in circuit, so a wrong
    /// `ask` produces a commitment that is not in the tree.
    pub ask: HashOutTarget,
    /// Nullifier key. Feeds both `pk` and the published nullifier, which is
    /// what ties the nullifier to the note being spent.
    pub nk: HashOutTarget,
    pub rho: HashOutTarget,
    pub r: HashOutTarget,
    pub value: Target,
    pub path: MerklePathTargets,
    /// Witnessed. A dummy input carries value 0, skips membership, and
    /// publishes its nullifier under the `NF_DUMMY` domain tag so the value
    /// cannot collide with any real note's nullifier. It is still published,
    /// so it must be unique.
    pub is_dummy: BoolTarget,
}

impl InputNoteTargets {
    fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            ask: builder.add_virtual_hash(),
            nk: builder.add_virtual_hash(),
            rho: builder.add_virtual_hash(),
            r: builder.add_virtual_hash(),
            value: builder.add_virtual_target(),
            path: MerklePathTargets::new(builder),
            is_dummy: builder.add_virtual_bool_target_safe(),
        }
    }
}

/// Private targets for one output note.
///
/// There is no `rho` target. An output's nullifier seed is derived in circuit
/// from both nullifiers the leaf publishes, so a sender cannot choose it;
/// see [`crate::note_gadget::output_rho`].
#[derive(Debug, Clone)]
pub struct OutputNoteTargets {
    pub pk: HashOutTarget,
    pub r: HashOutTarget,
    pub value: Target,
}

impl OutputNoteTargets {
    fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            pk: builder.add_virtual_hash(),
            r: builder.add_virtual_hash(),
            value: builder.add_virtual_target(),
        }
    }
}

/// Every target of the leaf circuit.
///
/// The public-input order is decided here and nowhere else: the registration
/// calls at the top of [`SpendTargets::new`] are the layout documented in
/// [`crate::layout`]. Inserting a registration in the middle shifts every
/// index after it.
#[derive(Debug, Clone)]
pub struct SpendTargets {
    // Public, in layout order.
    pub block_hash: HashOutTarget,
    pub block_number: Target,
    pub nullifiers: [HashOutTarget; NUM_INPUTS],
    pub commitments: [HashOutTarget; NUM_OUTPUTS],
    pub fee: Target,
    pub ct_digest: HashOutTarget,
    // Private.
    pub header: HeaderTargets,
    /// Depth of the commitment tree, shared by both input paths: they are
    /// membership proofs in one tree at one block.
    pub depth: Target,
    pub inputs: [InputNoteTargets; NUM_INPUTS],
    pub outputs: [OutputNoteTargets; NUM_OUTPUTS],
}

impl SpendTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // --- public inputs, in layout order ---
        let block_hash = builder.add_virtual_hash_public_input();
        let block_number = builder.add_virtual_public_input();
        let nullifiers = core::array::from_fn(|_| builder.add_virtual_hash_public_input());
        let commitments = core::array::from_fn(|_| builder.add_virtual_hash_public_input());
        let fee = builder.add_virtual_public_input();
        let ct_digest = builder.add_virtual_hash_public_input();

        // --- private ---
        let header = HeaderTargets::new(builder, block_number);
        let depth = builder.add_virtual_target();
        let inputs = core::array::from_fn(|_| InputNoteTargets::new(builder));
        let outputs = core::array::from_fn(|_| OutputNoteTargets::new(builder));

        Self {
            block_hash,
            block_number,
            nullifiers,
            commitments,
            fee,
            ct_digest,
            header,
            depth,
            inputs,
            outputs,
        }
    }
}

/// Add every constraint of the leaf.
///
/// The numbered comments are the numbered constraints in `docs/CIRCUIT.md`
/// section 5.
pub fn build_constraints(targets: &SpendTargets, builder: &mut CircuitBuilder<F, D>) {
    let zero = builder.zero();

    // 1. block_hash == H(header preimage), and the header carries zk_tree_root.
    constrain_header(builder, targets.block_hash, &targets.header);

    // 2. The tree depth is shared by both paths, and split into bits exactly
    // once. The split is what range-constrains `depth`; the same bits then
    // bound it to MAX_DEPTH and derive the 16 level flags. Splitting a second
    // time for the bound would add a BaseSumGate and a second comparison chain
    // over a value the first split already determines.
    //
    // The MAX_DEPTH bound is defensive: it rejects no witness that the level
    // flags would otherwise accept. `split_le` over DEPTH_BITS already pins
    // `depth` below 32, and the flags only ask
    // `level < depth` for levels 0..MAX_DEPTH, so every depth in
    // `MAX_DEPTH..32` produces the same all-true flags as `MAX_DEPTH` itself.
    // It is kept so that a later change to the flag derivation, or anything
    // that indexes by `depth`, cannot silently inherit an unbounded value.
    let depth_bits = builder.split_le(targets.depth, DEPTH_BITS);
    let depth_over_max = const_less_than_bits(builder, MAX_DEPTH, &depth_bits);
    builder.connect(depth_over_max.target, zero);
    let active_levels = active_level_flags_from_bits(builder, &depth_bits);

    // 3 and 4. Input notes.
    let mut input_values = Vec::with_capacity(NUM_INPUTS);
    for (index, input) in targets.inputs.iter().enumerate() {
        builder.range_check(input.value, VALUE_BITS as usize);

        // A dummy input carries no value. Without this a prover could skip
        // membership and still credit itself the input side of the balance.
        let dummy_value = builder.mul(input.value, input.is_dummy.target);
        builder.connect(dummy_value, zero);

        // pk is derived here in circuit: a wrong ask or nk yields a
        // commitment that is not in the tree.
        let pk = derive_pk(builder, input.ask, input.nk);
        let inner = note_inner(builder, pk, input.rho, input.r);
        let commitment = note_commitment(builder, inner, input.value);

        // The tree leaf is the commitment itself, so the path starts here.
        let root = merkle_root_from_path(builder, commitment, &input.path, &active_levels);
        let is_real = builder.not(input.is_dummy);
        for limb in 0..4 {
            let difference = builder.sub(
                root.elements[limb],
                targets.header.zk_tree_root.elements[limb],
            );
            let gated = builder.mul(difference, is_real.target);
            builder.connect(gated, zero);
        }

        // Published for every input, dummy or not, so a dummy is
        // indistinguishable from a real spend in the public inputs: both are
        // uniform 4-felt Poseidon2 outputs.
        //
        // The domain tag is chosen in circuit by the `is_dummy` bit. A dummy
        // slot proves no membership and carries no `ask`, so whatever it
        // publishes is unauthenticated; under the real tag it would be an
        // arbitrary nullifier of the prover's choosing. A holder of a victim's
        // `nk` and of the victim note's `(rho, r)` could then publish that
        // victim's nullifier from a dummy slot of their own leaf and have the
        // chain settle it, burning the note permanently while proving nothing
        // about it. `NF_DUMMY` puts every dummy slot's value outside the image
        // of the real nullifier function, so no leaf can ever settle a real
        // note's nullifier without the membership proof and the spend key that
        // go with it.
        let nullifier_tag = nullifier_domain_tag(builder, input.is_dummy);
        let nullifier = note_nullifier_tagged(builder, nullifier_tag, input.nk, input.rho, input.r);
        builder.connect_hashes(nullifier, targets.nullifiers[index]);

        input_values.push(input.value);
    }

    // 5. The two nullifiers must differ. Equal nullifiers would mean the same
    // note spent twice inside one leaf, which the chain's used-nullifier set
    // cannot catch if it inserts both in the same transaction. Dummies get a
    // fresh rho, so honest proving is unaffected.
    let nullifiers_equal = digests_are_equal(
        builder,
        targets.nullifiers[0].elements,
        targets.nullifiers[1].elements,
    );
    builder.connect(nullifiers_equal.target, zero);

    // 9. Every leaf that binds a real block must consume a note: at least one
    // input is real, unless this leaf is the batch's padding.
    //
    // Nothing else relates the two `is_dummy` bits. With both set, a leaf
    // proves with no spend key and no note in the tree: every membership check
    // is switched off, both values are forced to zero, so the balance holds at
    // zero out and zero fee, and the header can be any real block, whose
    // preimage is public chain data. That leaf still publishes two nullifiers
    // and two output commitments, which the chain writes into permanent state:
    // two entries in the nullifier set and two slots of a depth-16 tree that is
    // sized for the life of the chain. Settlement extrinsics are fee-free, so
    // the leaf's own `fee` public input is the only cost, and an all-dummy leaf
    // sets it to zero.
    //
    // What this constraint achieves, exactly: every leaf must consume a note
    // that is already in the tree, under a spend credential the prover holds.
    // A prover with no key and no note cannot produce one at all. It is not a
    // bound on how many leaves a prover can produce, because a leaf consumes
    // at most two notes and always mints two: one real input of any value,
    // including zero, plus a dummy yields two spendable notes, so a prover
    // holding a single note never runs out. A minimum fee per non-padding
    // leaf, charged at M4, is what bounds leaf count; see `docs/CIRCUIT.md`
    // section 8.
    //
    // The exemption is the batch padding sentinel (M3). A private batch
    // aggregates a fixed number of leaves, so a wallet with fewer transfers
    // than slots has to fill the rest with leaves that consume nothing, and
    // those leaves must still be proofs of this circuit. `is_padding` is
    // derived here from the public `block_hash` and a constant, never
    // witnessed: a leaf is padding exactly when it binds the one fixed padding
    // header preimage, whose `zk_tree_root` is the empty tree. So the
    // exemption cannot be claimed by a leaf that binds a real block, and
    // constraint 1 stays unconditional for every leaf, padding included.
    // `crate::padding` carries the whole rule and the reasoning.
    let is_padding = is_padding_block_hash(builder, targets.block_hash);
    let is_real_leaf = builder.not(is_padding);
    let mut all_dummy = targets.inputs[0].is_dummy.target;
    for input in &targets.inputs[1..] {
        all_dummy = builder.mul(all_dummy, input.is_dummy.target);
    }
    let all_dummy_in_a_real_leaf = builder.mul(all_dummy, is_real_leaf.target);
    builder.connect(all_dummy_in_a_real_leaf, zero);

    // 6. Output notes. `rho` is derived from both published nullifiers.
    // The reason: `nf = H(NF, nk, rho, r)` is a function of the recipient's
    // key and of values the sender picks for a note it creates, so a sender
    // free to repeat a `(rho, r)` could pay one recipient twice with notes
    // that share a nullifier and strand whichever of the two the recipient
    // does not spend first. The output index separates the two outputs of one
    // leaf.
    //
    // Both nullifiers are in the preimage because either slot may hold the
    // dummy. Constraint 9 guarantees at least one input is real; a real note's
    // nullifier is settled exactly once over the life of the chain, since the
    // chain must refuse a repeat to stop double spends, so the pair can never
    // repeat whichever slot is real. Deriving from slot 0 alone would rest the
    // whole uniqueness argument on a prover-chosen value in every leaf whose
    // slot 0 is a dummy, and would make the chain's settlement of dummy
    // nullifiers load bearing for uniqueness as well as for double-spend
    // safety.
    let mut output_values = Vec::with_capacity(NUM_OUTPUTS + 1);
    for (index, output) in targets.outputs.iter().enumerate() {
        builder.range_check(output.value, VALUE_BITS as usize);
        let rho = output_rho(
            builder,
            targets.nullifiers[0],
            targets.nullifiers[1],
            index as u64,
        );
        let inner = note_inner(builder, output.pk, rho, output.r);
        let commitment = note_commitment(builder, inner, output.value);
        builder.connect_hashes(commitment, targets.commitments[index]);
        output_values.push(output.value);
    }

    // 7. The fee is public but still range checked: it is a term of the
    // balance equation, so an unbounded fee would break the no-wrap argument.
    builder.range_check(targets.fee, VALUE_BITS as usize);
    output_values.push(targets.fee);

    // 8. Balance, as a field equation. Each term is below 2^62, so the left
    // side is below 2^63 and the right side below 3 * 2^62, both below the
    // Goldilocks modulus 2^64 - 2^32 + 1. Their difference is therefore
    // smaller than the modulus, so equality in the field is equality over the
    // integers and no wraparound can fake a balance.
    let total_in = sum(builder, &input_values);
    let total_out = sum(builder, &output_values);
    builder.connect(total_in, total_out);

    // ct_digest is deliberately unconstrained here. The chain recomputes it
    // from the ciphertexts it was handed and compares, which binds them to
    // this proof without hashing kilobytes of ciphertext in circuit.
    let _ = targets.ct_digest;
}

fn sum(builder: &mut CircuitBuilder<F, D>, terms: &[Target]) -> Target {
    let mut total = terms[0];
    for term in &terms[1..] {
        total = builder.add(total, *term);
    }
    total
}

/// The leaf circuit, before it is built.
pub struct QneroSpendCircuit {
    builder: CircuitBuilder<F, D>,
    targets: SpendTargets,
}

impl core::fmt::Debug for QneroSpendCircuit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroSpendCircuit")
            .field("num_gates", &self.builder.num_gates())
            .finish()
    }
}

impl Default for QneroSpendCircuit {
    fn default() -> Self {
        Self::new(qnero_leaf_circuit_config()).expect("the canonical leaf config is valid")
    }
}

impl QneroSpendCircuit {
    /// Build the constraint system.
    ///
    /// The config is validated before it reaches `CircuitBuilder::new`, so a
    /// structurally impossible or resource-pathological config fails here. An
    /// unchecked one panics deep inside plonky2 mid-build or drives
    /// exponential allocation during it.
    pub fn new(config: CircuitConfig) -> Result<Self> {
        validate_circuit_config(&config)?;
        ensure_zk_supported(&config)?;

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = SpendTargets::new(&mut builder);
        build_constraints(&targets, &mut builder);

        Ok(Self { builder, targets })
    }

    pub fn targets(&self) -> SpendTargets {
        self.targets.clone()
    }

    /// Gates before padding. Reported by the gate-count test.
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
