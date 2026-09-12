//! Witness values for one spend leaf, and the single place they are written
//! into a `PartialWitness`.
//!
//! Everything public that the circuit recomputes is also computed here
//! through `qnero-notes` and written to the public targets. Plonky2 rejects a
//! partition that is set twice with different values, so a divergence between
//! the wallet-side note code and the in-circuit note gadget fails at proving
//! time with a clear error. The alternative is a proof nobody can use.

use anyhow::{ensure, Result};
use core::fmt::Arguments;
use plonky2::field::types::{Field as _, Field64 as _};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use qnero_note_core::keys::{derive_pk, DerivedKeys};
use qnero_note_core::note::{
    commitment_from_inner, dummy_nullifier, note_inner, nullifier, output_rho,
};
use qnero_note_core::{Digest, Note};
use rand_core::{CryptoRng, RngCore};

use crate::circuit::{QneroSpendCircuit, SpendTargets};
use crate::convert::{digest_to_felts, digest_to_hashout};
use crate::layout::{NUM_INPUTS, NUM_OUTPUTS, PUBLIC_INPUT_LEN};
use crate::merkle::{empty_digest, MerklePath, ARITY, MAX_DEPTH, SIBLINGS_PER_LEVEL};
use crate::sensitive::Secret;
use crate::F;

pub use crate::header::HeaderInputs;

/// One input note, with the keys that authorize spending it.
///
/// Not `Clone`: `ask` and `nk` live in a move-only, zeroize-on-drop
/// [`Secret`], so duplicating the spend credential takes an explicitly named
/// `expose_digest` call that review can grep for.
pub struct InputNote {
    /// Spend authorizing key.
    pub ask: Secret,
    /// Nullifier key.
    pub nk: Secret,
    pub value: u64,
    pub rho: Digest,
    pub r: Digest,
    /// Path from this note's commitment to the header's `zk_tree_root`.
    pub path: MerklePath,
    /// A dummy input proves nothing about membership and must carry value 0.
    /// Its nullifier is still published, under the `NF_DUMMY` domain tag, so
    /// `(rho, r)` must be fresh.
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
            ask: Secret::from(keys.ask),
            nk: Secret::from(keys.nk),
            value: note.value,
            rho: note.rho,
            r: note.r,
            path,
            is_dummy: false,
        })
    }

    /// A padding input with caller-supplied randomness. It carries no value
    /// and skips the membership check.
    ///
    /// The caller owns freshness of `(rho, r)`. A dummy publishes a nullifier
    /// like any other input, so repeating a pair publishes a nullifier the
    /// chain has already settled and the settlement extrinsic is rejected,
    /// naming a value the wallet cannot map to any note it holds. Prefer
    /// [`InputNote::dummy_random`], which draws both from a CSPRNG.
    pub fn dummy(keys: &DerivedKeys, rho: Digest, r: Digest, depth: usize) -> Self {
        Self {
            ask: Secret::from(keys.ask),
            nk: Secret::from(keys.nk),
            value: 0,
            rho,
            r,
            path: MerklePath::dummy(depth),
            is_dummy: true,
        }
    }

    /// A padding input with fresh randomness, the constructor a wallet should
    /// use.
    ///
    /// `rho` and `r` are drawn the way [`qnero_note_core::Note::random`] draws
    /// them: bytes from the RNG, hashed so the results are canonical digests.
    pub fn dummy_random<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        keys: &DerivedKeys,
        depth: usize,
    ) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let rho = Digest::hash_bytes(&[b"qnero/dummy-rho", &seed]);
        let r = Digest::hash_bytes(&[b"qnero/dummy-r", &seed]);
        Self::dummy(keys, rho, r, depth)
    }

    /// The note receiving key these spend keys own.
    pub fn pk(&self) -> Digest {
        derive_pk(&self.ask.expose_digest(), &self.nk.expose_digest())
    }

    /// The nullifier this slot publishes.
    ///
    /// `H(NF, nk, rho, r)` for a real input, `H(NF_DUMMY, nk, rho, r)` for a
    /// dummy. The circuit selects the same tag from the same bit, so the two
    /// must branch together; the published value is a uniform Poseidon2 output
    /// either way, which is what keeps a dummy slot invisible in the public
    /// inputs.
    pub fn nullifier(&self) -> Digest {
        let nk = self.nk.expose_digest();
        if self.is_dummy {
            dummy_nullifier(&nk, &self.rho, &self.r)
        } else {
            nullifier(&nk, &self.rho, &self.r)
        }
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
///
/// There is no `rho` field. An output's nullifier seed is a function of both
/// nullifiers its leaf publishes, [`SpendWitness::output_rho`], so it cannot
/// be supplied here and cannot be repeated across two notes.
#[derive(Clone)]
pub struct OutputNote {
    pub pk: Digest,
    pub value: u64,
    pub r: Digest,
}

/// Redacting `Debug`: an output note is the plaintext the recipient's
/// ciphertext hides.
impl core::fmt::Debug for OutputNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutputNote")
            .field("pk", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .finish()
    }
}

impl OutputNote {
    pub fn new(pk: Digest, value: u64, r: Digest) -> Self {
        Self { pk, value, r }
    }

    /// The commitment this output carries, given the `rho` its leaf derives.
    ///
    /// See [`InputNote::commitment`] for why this does not go through
    /// [`Note`].
    pub fn commitment_with_rho(&self, rho: &Digest) -> Digest {
        commitment_from_inner(&note_inner(&self.pk, rho, &self.r), self.value)
    }
}

/// Everything one leaf proof is built from.
///
/// Not `Clone`, because [`InputNote`] is not: the spend credential is held in
/// a move-only zeroize-on-drop container.
#[derive(Debug)]
pub struct SpendWitness {
    pub header: HeaderInputs,
    /// Depth of the commitment tree the header's root belongs to.
    pub depth: usize,
    pub inputs: [InputNote; NUM_INPUTS],
    pub outputs: [OutputNote; NUM_OUTPUTS],
    pub fee: u64,
    /// Digest of the output ciphertexts, from
    /// [`chain::ct_digest`](crate::chain::ct_digest), which compiles without
    /// the `circuit` feature so the chain and the wallet call one function.
    /// The circuit passes the digest through; the chain recomputes it with
    /// that same function from the ciphertexts it was handed and compares.
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
    ///
    /// The circuit is that authority only for canonical values. A `u64` at or
    /// above the Goldilocks modulus is the one range the circuit provably
    /// cannot see: the witness carries it as a field element, which is its
    /// reduction `v - p`, always below `2^32` and therefore always inside the
    /// 62-bit check. It is also the range a wallet reaches by accident, since
    /// a wrapping `total_in - payment - fee` underflows to `2^64 - k` and any
    /// `k` below `2^32` lands in it. So the bound is enforced here, where a
    /// non-canonical value can still be distinguished from its reduction, and
    /// the whole window `[2^62, p)` is left to the circuit.
    pub fn validate(&self) -> Result<()> {
        for (index, input) in self.inputs.iter().enumerate() {
            ensure_canonical(input.value, format_args!("input {index} value"))?;
        }
        for (index, output) in self.outputs.iter().enumerate() {
            ensure_canonical(output.value, format_args!("output {index} value"))?;
        }
        ensure_canonical(self.fee, format_args!("fee"))?;

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

    /// `rho` of output note `index`, as the circuit derives it.
    ///
    /// `rho = H(RHO, nf_1, nf_2, index)` over both nullifiers the leaf
    /// publishes. A wallet needs this to build the ciphertext the recipient
    /// decrypts, since `rho` is part of the note plaintext.
    pub fn output_rho(&self, index: usize) -> Digest {
        output_rho(
            &self.inputs[0].nullifier(),
            &self.inputs[1].nullifier(),
            index as u64,
        )
    }

    /// The commitment output note `index` publishes.
    pub fn output_commitment(&self, index: usize) -> Digest {
        self.outputs[index].commitment_with_rho(&self.output_rho(index))
    }

    /// Output note `index` as a whole [`Note`], for a wallet that has to
    /// encrypt it to its recipient.
    ///
    /// Errors when the value is out of range, which is the one case the
    /// checked [`Note`] constructor exists to catch.
    pub fn output_note(&self, index: usize) -> Result<Note> {
        let output = &self.outputs[index];
        Ok(Note::new(
            output.pk,
            output.value,
            self.output_rho(index),
            output.r,
        )?)
    }

    /// The public inputs this witness produces, in layout order.
    pub fn public_inputs(&self) -> Vec<F> {
        let mut public = Vec::with_capacity(PUBLIC_INPUT_LEN);
        public.extend_from_slice(&digest_to_felts(&self.header.block_hash()));
        public.push(F::from_canonical_u32(self.header.block_number));
        for input in &self.inputs {
            public.extend_from_slice(&digest_to_felts(&input.nullifier()));
        }
        for index in 0..NUM_OUTPUTS {
            public.extend_from_slice(&digest_to_felts(&self.output_commitment(index)));
        }
        public.push(F::from_noncanonical_u64(self.fee));
        public.extend_from_slice(&digest_to_felts(&self.ct_digest));
        debug_assert_eq!(public.len(), PUBLIC_INPUT_LEN);
        public
    }
}

/// Reject a `u64` the field cannot hold, before it is silently reduced.
///
/// `F::from_noncanonical_u64` does not reduce, and every comparison on the
/// resulting element does, so a value in `[p, 2^64)` is proved as `v - p`.
fn ensure_canonical(value: u64, what: Arguments<'_>) -> Result<()> {
    ensure!(
        value < F::ORDER,
        "{} is {}, at or above the Goldilocks modulus {}; the circuit would \
         range-check its reduction instead",
        what,
        value,
        F::ORDER
    );
    Ok(())
}

/// The public values a witness implies, as written to the public targets.
struct PublicValues {
    block_hash: Digest,
    nullifiers: [Digest; NUM_INPUTS],
    commitments: [Digest; NUM_OUTPUTS],
}

impl PublicValues {
    fn from_witness(witness: &SpendWitness) -> Self {
        Self {
            block_hash: witness.header.block_hash(),
            nullifiers: core::array::from_fn(|i| witness.inputs[i].nullifier()),
            commitments: core::array::from_fn(|j| witness.output_commitment(j)),
        }
    }
}

/// Public values the circuit recomputes, written in place of the ones the
/// witness implies.
///
/// A negative-testing seam, and nothing else: it exists so a test can write a
/// public target that disagrees with the private witness beside it and check
/// that the circuit refuses to prove. Every constraint that binds a published
/// value to its in-circuit recomputation is otherwise untestable, because
/// [`fill_witness`] writes both sides from the same `qnero-notes` call, so a
/// test comparing them is comparing a value to itself.
///
/// This is not a capability the seam grants. Every field of [`SpendTargets`]
/// is public and a `PartialWitness` can always be built by hand, so any
/// caller could already write a disagreeing pair. What they cannot do is
/// produce a proof from one.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Default)]
pub struct PublicOverrides {
    pub block_hash: Option<Digest>,
    pub nullifiers: [Option<Digest>; NUM_INPUTS],
    pub commitments: [Option<Digest>; NUM_OUTPUTS],
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
    fill_public(pw, targets, witness, &PublicValues::from_witness(witness))?;
    fill_private(pw, witness, targets)
}

/// [`fill_witness`], with some public values replaced. See
/// [`PublicOverrides`].
#[cfg(feature = "test-support")]
pub fn fill_witness_with_public_overrides(
    pw: &mut PartialWitness<F>,
    witness: &SpendWitness,
    targets: &SpendTargets,
    overrides: &PublicOverrides,
) -> Result<()> {
    witness.validate()?;
    let mut public = PublicValues::from_witness(witness);
    if let Some(block_hash) = overrides.block_hash {
        public.block_hash = block_hash;
    }
    for (index, nullifier) in overrides.nullifiers.iter().enumerate() {
        if let Some(nullifier) = nullifier {
            public.nullifiers[index] = *nullifier;
        }
    }
    for (index, commitment) in overrides.commitments.iter().enumerate() {
        if let Some(commitment) = commitment {
            public.commitments[index] = *commitment;
        }
    }
    fill_public(pw, targets, witness, &public)?;
    fill_private(pw, witness, targets)
}

fn fill_public(
    pw: &mut PartialWitness<F>,
    targets: &SpendTargets,
    witness: &SpendWitness,
    public: &PublicValues,
) -> Result<()> {
    pw.set_hash_target(targets.block_hash, digest_to_hashout(&public.block_hash))?;
    pw.set_target(
        targets.block_number,
        F::from_canonical_u32(witness.header.block_number),
    )?;
    for (index, nullifier) in public.nullifiers.iter().enumerate() {
        pw.set_hash_target(targets.nullifiers[index], digest_to_hashout(nullifier))?;
    }
    for (index, commitment) in public.commitments.iter().enumerate() {
        pw.set_hash_target(targets.commitments[index], digest_to_hashout(commitment))?;
    }
    pw.set_target(targets.fee, F::from_noncanonical_u64(witness.fee))?;
    pw.set_hash_target(targets.ct_digest, digest_to_hashout(&witness.ct_digest))?;
    Ok(())
}

fn fill_private(
    pw: &mut PartialWitness<F>,
    witness: &SpendWitness,
    targets: &SpendTargets,
) -> Result<()> {
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
        // The two `expose_digest` calls are the deliberate duplication out of
        // the zeroize-on-drop container: the field elements they return are
        // transient here and are consumed by the witness writer, whose own
        // copies are plonky2's to scrub.
        pw.set_hash_target(
            input_targets.ask,
            digest_to_hashout(&input.ask.expose_digest()),
        )?;
        pw.set_hash_target(
            input_targets.nk,
            digest_to_hashout(&input.nk.expose_digest()),
        )?;
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

    // Output notes. `rho` has no target: the circuit derives it.
    for (index, output) in witness.outputs.iter().enumerate() {
        let output_targets = &targets.outputs[index];
        pw.set_hash_target(output_targets.pk, digest_to_hashout(&output.pk))?;
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
