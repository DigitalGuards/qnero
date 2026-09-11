//! Witness values for one spend leaf, and the single place they are written
//! into a `PartialWitness`.
//!
//! Everything public that the circuit recomputes is also computed here
//! through `qnero-notes` and written to the public targets. Plonky2 rejects a
//! partition that is set twice with different values, so a divergence between
//! the wallet-side note code and the in-circuit note gadget fails at proving
//! time with a clear error. The alternative is a proof nobody can use.

use anyhow::{ensure, Result};
use plonky2::field::types::Field as _;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use qnero_notes::keys::{derive_pk, DerivedKeys};
use qnero_notes::note::{commitment_from_inner, note_inner, nullifier};
use qnero_notes::{Digest, Note};

use crate::circuit::{QneroSpendCircuit, SpendTargets};
use crate::convert::{digest_to_felts, digest_to_hashout};
use crate::layout::{NUM_INPUTS, NUM_OUTPUTS, PUBLIC_INPUT_LEN};
use crate::merkle::{empty_digest, MerklePath, ARITY, MAX_DEPTH, SIBLINGS_PER_LEVEL};
use crate::F;

pub use crate::header::HeaderInputs;

/// One input note, with the keys that authorize spending it.
#[derive(Clone)]
pub struct InputNote {
    /// Spend authorizing key.
    pub ask: Digest,
    /// Nullifier key.
    pub nk: Digest,
    pub value: u64,
    pub rho: Digest,
    pub r: Digest,
    /// Path from this note's commitment to the header's `zk_tree_root`.
    pub path: MerklePath,
    /// A dummy input proves nothing about membership and must carry value 0.
    /// Its nullifier is still published, so `rho` must be fresh.
    pub is_dummy: bool,
}

/// Redacting `Debug`: `ask` and `nk` are the spend credential, and the
/// remaining fields identify the note being spent.
impl core::fmt::Debug for InputNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputNote")
            .field("ask", &"[REDACTED]")
            .field("nk", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("rho", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .field("path", &self.path)
            .field("is_dummy", &self.is_dummy)
            .finish()
    }
}

impl InputNote {
    /// A real input. The note's `pk` must be the one these keys derive,
    /// otherwise its commitment is not the one in the tree.
    pub fn real(keys: &DerivedKeys, note: &Note, path: MerklePath) -> Result<Self> {
        let derived = derive_pk(&keys.ask, &keys.nk);
        ensure!(
            derived == note.pk,
            "input note pk does not match the supplied spend keys"
        );
        Ok(Self {
            ask: keys.ask,
            nk: keys.nk,
            value: note.value,
            rho: note.rho,
            r: note.r,
            path,
            is_dummy: false,
        })
    }

    /// A padding input. It carries no value and skips the membership check;
    /// `rho` must be fresh so its published nullifier is unique.
    pub fn dummy(keys: &DerivedKeys, rho: Digest, r: Digest, depth: usize) -> Self {
        Self {
            ask: keys.ask,
            nk: keys.nk,
            value: 0,
            rho,
            r,
            path: MerklePath::dummy(depth),
            is_dummy: true,
        }
    }

    /// The note receiving key these spend keys own.
    pub fn pk(&self) -> Digest {
        derive_pk(&self.ask, &self.nk)
    }

    /// `nf = H(NF, nk, rho)`.
    pub fn nullifier(&self) -> Digest {
        nullifier(&self.nk, &self.rho)
    }

    /// The commitment this input claims membership for.
    ///
    /// Computed from the hash rules directly, bypassing [`Note`]'s value
    /// check, so an out-of-range value reaches the circuit's range check.
    pub fn commitment(&self) -> Digest {
        commitment_from_inner(&note_inner(&self.pk(), &self.rho, &self.r), self.value)
    }
}

/// One output note. The circuit knows nothing about the recipient beyond
/// `pk`.
#[derive(Clone)]
pub struct OutputNote {
    pub pk: Digest,
    pub value: u64,
    pub rho: Digest,
    pub r: Digest,
}

/// Redacting `Debug`: an output note is the plaintext the recipient's
/// ciphertext hides.
impl core::fmt::Debug for OutputNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutputNote")
            .field("pk", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("rho", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .finish()
    }
}

impl OutputNote {
    pub fn new(note: &Note) -> Self {
        Self {
            pk: note.pk,
            value: note.value,
            rho: note.rho,
            r: note.r,
        }
    }

    /// See [`InputNote::commitment`] for why this does not go through
    /// [`Note`].
    pub fn commitment(&self) -> Digest {
        commitment_from_inner(&note_inner(&self.pk, &self.rho, &self.r), self.value)
    }
}

/// Everything one leaf proof is built from.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    pub header: HeaderInputs,
    /// Depth of the commitment tree the header's root belongs to.
    pub depth: usize,
    pub inputs: [InputNote; NUM_INPUTS],
    pub outputs: [OutputNote; NUM_OUTPUTS],
    pub fee: u64,
    /// Digest of the output ciphertexts. The circuit passes it through; the
    /// chain recomputes it from the ciphertexts it was handed.
    pub ct_digest: Digest,
}

impl SpendWitness {
    /// Structural validation, cheap checks first.
    ///
    /// Everything here is O(1) or bounded by `MAX_DEPTH` and runs before any
    /// witness writing, so malformed input cannot force work proportional to
    /// an arbitrarily long path vector.
    ///
    /// Value ranges and the dummy contract are deliberately NOT checked here.
    /// The circuit's 62-bit range checks and its `value * is_dummy == 0`
    /// constraint are the authority on those, and a witness that violates one
    /// must reach them. A front door here that turned them away would hide
    /// whether the circuit constrains them at all.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_DEPTH).contains(&self.depth),
            "tree depth {} must be in 1..={}",
            self.depth,
            MAX_DEPTH
        );
        for (index, input) in self.inputs.iter().enumerate() {
            ensure!(
                input.path.siblings.len() == input.path.positions.len(),
                "input {} path has {} sibling levels and {} positions",
                index,
                input.path.siblings.len(),
                input.path.positions.len()
            );
            ensure!(
                input.path.depth() == self.depth,
                "input {} path has depth {}, tree depth is {}",
                index,
                input.path.depth(),
                self.depth
            );
            for (level, position) in input.path.positions.iter().enumerate() {
                ensure!(
                    (*position as usize) < ARITY,
                    "input {} position {} at level {} is not in 0..{}",
                    index,
                    position,
                    level,
                    ARITY
                );
            }
        }

        Ok(())
    }

    /// The public inputs this witness produces, in layout order.
    pub fn public_inputs(&self) -> Vec<F> {
        let mut public = Vec::with_capacity(PUBLIC_INPUT_LEN);
        public.extend_from_slice(&digest_to_felts(&self.header.block_hash()));
        public.push(F::from_canonical_u32(self.header.block_number));
        for input in &self.inputs {
            public.extend_from_slice(&digest_to_felts(&input.nullifier()));
        }
        for output in &self.outputs {
            public.extend_from_slice(&digest_to_felts(&output.commitment()));
        }
        public.push(F::from_noncanonical_u64(self.fee));
        public.extend_from_slice(&digest_to_felts(&self.ct_digest));
        debug_assert_eq!(public.len(), PUBLIC_INPUT_LEN);
        public
    }
}

/// Write a witness into the circuit's targets.
///
/// This is the single source of truth for witness filling. Anything that
/// builds a leaf proof, including the batch layer's padding, goes through it.
pub fn fill_witness(
    pw: &mut PartialWitness<F>,
    witness: &SpendWitness,
    targets: &SpendTargets,
) -> Result<()> {
    witness.validate()?;

    // Public.
    pw.set_hash_target(
        targets.block_hash,
        digest_to_hashout(&witness.header.block_hash()),
    )?;
    pw.set_target(
        targets.block_number,
        F::from_canonical_u32(witness.header.block_number),
    )?;
    for (index, input) in witness.inputs.iter().enumerate() {
        pw.set_hash_target(
            targets.nullifiers[index],
            digest_to_hashout(&input.nullifier()),
        )?;
    }
    for (index, output) in witness.outputs.iter().enumerate() {
        pw.set_hash_target(
            targets.commitments[index],
            digest_to_hashout(&output.commitment()),
        )?;
    }
    pw.set_target(targets.fee, F::from_noncanonical_u64(witness.fee))?;
    pw.set_hash_target(targets.ct_digest, digest_to_hashout(&witness.ct_digest))?;

    // Header, private part.
    pw.set_hash_target(
        targets.header.parent_hash,
        digest_to_hashout(&witness.header.parent_hash),
    )?;
    pw.set_hash_target(
        targets.header.state_root,
        digest_to_hashout(&witness.header.state_root),
    )?;
    pw.set_hash_target(
        targets.header.extrinsics_root,
        digest_to_hashout(&witness.header.extrinsics_root),
    )?;
    pw.set_hash_target(
        targets.header.zk_tree_root,
        digest_to_hashout(&witness.header.zk_tree_root),
    )?;
    pw.set_target_arr(&targets.header.digest, &witness.header.digest)?;

    pw.set_target(targets.depth, F::from_canonical_usize(witness.depth))?;

    // Input notes.
    for (index, input) in witness.inputs.iter().enumerate() {
        let input_targets = &targets.inputs[index];
        pw.set_hash_target(input_targets.ask, digest_to_hashout(&input.ask))?;
        pw.set_hash_target(input_targets.nk, digest_to_hashout(&input.nk))?;
        pw.set_hash_target(input_targets.rho, digest_to_hashout(&input.rho))?;
        pw.set_hash_target(input_targets.r, digest_to_hashout(&input.r))?;
        pw.set_target(input_targets.value, F::from_noncanonical_u64(input.value))?;
        pw.set_bool_target(input_targets.is_dummy, input.is_dummy)?;

        // Levels past the tree's depth are inert: their flag is false, so the
        // running hash is kept and the parent computed from them is dropped.
        for level in 0..MAX_DEPTH {
            for sibling in 0..SIBLINGS_PER_LEVEL {
                let value = input
                    .path
                    .siblings
                    .get(level)
                    .map(|level_siblings| level_siblings[sibling])
                    .unwrap_or_else(empty_digest);
                pw.set_hash_target(
                    input_targets.path.siblings[level][sibling],
                    digest_to_hashout(&value),
                )?;
            }
            let position = input.path.positions.get(level).copied().unwrap_or(0);
            pw.set_target(
                input_targets.path.positions[level],
                F::from_canonical_u8(position),
            )?;
        }
    }

    // Output notes.
    for (index, output) in witness.outputs.iter().enumerate() {
        let output_targets = &targets.outputs[index];
        pw.set_hash_target(output_targets.pk, digest_to_hashout(&output.pk))?;
        pw.set_hash_target(output_targets.rho, digest_to_hashout(&output.rho))?;
        pw.set_hash_target(output_targets.r, digest_to_hashout(&output.r))?;
        pw.set_target(output_targets.value, F::from_noncanonical_u64(output.value))?;
    }

    Ok(())
}

/// Build the leaf circuit and fill it in one call. Used by tests and by
/// anything that needs the built circuit and the witness together.
pub fn build_and_fill(
    config: CircuitConfig,
    witness: &SpendWitness,
) -> Result<(QneroSpendCircuit, PartialWitness<F>)> {
    let circuit = QneroSpendCircuit::new(config)?;
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, witness, &circuit.targets())?;
    Ok((circuit, pw))
}
