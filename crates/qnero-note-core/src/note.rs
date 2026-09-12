//! Notes and their commitments.

use rand_core::{CryptoRng, RngCore};

use crate::digest::{domain, Digest, Felt};
use crate::error::NoteError;

/// Values are range-checked to 62 bits inside the circuit so that a sum of
/// four of them can never wrap the 64-bit Goldilocks field.
pub const VALUE_BITS: u32 = 62;
pub const MAX_VALUE: u64 = (1u64 << VALUE_BITS) - 1;

#[derive(Clone, PartialEq, Eq)]
pub struct Note {
    /// Recipient's note receiving key.
    pub pk: Digest,
    /// Amount in the smallest unit.
    pub value: u64,
    /// Nullifier seed, unique per note.
    pub rho: Digest,
    /// Commitment randomness.
    pub r: Digest,
}

/// Redacting `Debug`: every field of a note is linkable material. The leaf
/// publishes `nf = H(NF, nk, rho, r)` on chain, so anyone holding a log line
/// with `rho` and `r` beside a settled nullifier learns the amount and the
/// recipient key that nullifier belongs to. `InputNote`, `OutputNote` and the
/// prover types redact the same values; this is where they come from.
impl core::fmt::Debug for Note {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Note")
            .field("pk", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("rho", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .finish()
    }
}

impl Note {
    pub fn new(pk: Digest, value: u64, rho: Digest, r: Digest) -> Result<Self, NoteError> {
        if value > MAX_VALUE {
            return Err(NoteError::ValueTooLarge(value));
        }
        Ok(Self { pk, value, rho, r })
    }

    /// Fresh `rho` and `r` from the RNG, hashed so they are canonical digests.
    pub fn random<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        pk: Digest,
        value: u64,
    ) -> Result<Self, NoteError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let rho = Digest::hash_bytes(&[b"qnero/rho", &seed]);
        let r = Digest::hash_bytes(&[b"qnero/r", &seed]);
        Self::new(pk, value, rho, r)
    }

    /// `inner = H(NOTE, pk, rho, r)`. Hides everything except the value.
    pub fn inner(&self) -> Digest {
        note_inner(&self.pk, &self.rho, &self.r)
    }

    /// `cm = H(CM, inner, value)`. The leaf stored in the commitment tree.
    pub fn commitment(&self) -> Digest {
        commitment_from_inner(&self.inner(), self.value)
    }

    /// `nf = H(NF, nk, rho, r)`. Published when the note is spent.
    pub fn nullifier(&self, nk: &Digest) -> Digest {
        nullifier(nk, &self.rho, &self.r)
    }
}

/// `inner = H(NOTE, pk, rho, r)`, on loose fields.
///
/// The free functions exist because the spend circuit's witness carries note
/// fields that have not been through [`Note::new`], including deliberately
/// out-of-range values a negative test feeds to the circuit's range checks.
/// [`Note`] is the checked constructor; these are the hash rules themselves.
pub fn note_inner(pk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NOTE, &[pk.felts(), rho.felts(), r.felts()])
}

/// `nf = H(NF, nk, rho, r)`, on loose fields.
///
/// `r` is in the preimage so that `nk` alone is not a spend-linkability key
/// for the whole pool. An output's `rho` is a public function of the leaf that
/// created it (see [`output_rho`]), so the candidate `rho` set for the entire
/// chain is public data; were the nullifier a function of `(nk, rho)` only, a
/// holder of `nk` could hash every published pair against every leaf and
/// recover exactly which notes that wallet spent, with no viewing key and no
/// decryption. `r` is known only to the note's sender and holder, which is the
/// same role Orchard gives `psi`. It also means a leaked `nk` cannot be used
/// to compute a victim's nullifier from public data alone.
pub fn nullifier(nk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NF, &[nk.felts(), rho.felts(), r.felts()])
}

/// `nf = H(NF_DUMMY, nk, rho, r)`: the nullifier a padding input slot
/// publishes.
///
/// Same shape as [`nullifier`] under a different domain tag. A dummy slot
/// proves no membership and carries no `ask`, so whatever it publishes is
/// unauthenticated; the separate tag is what keeps that value out of the image
/// of the real nullifier function. Without it, a holder of a victim's `nk`
/// could put the victim's nullifier in a dummy slot of their own leaf and have
/// the chain settle it, which burns the victim's note permanently while
/// proving nothing about it.
pub fn dummy_nullifier(nk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NF_DUMMY, &[nk.felts(), rho.felts(), r.felts()])
}

/// Recompute a commitment from its public opening. Used by the chain for
/// coinbase notes, where `inner` and `value` are published and `pk` stays
/// hidden inside `inner`.
pub fn commitment_from_inner(inner: &Digest, value: u64) -> Digest {
    Digest::hash_felts(domain::CM, &[inner.felts(), &[Felt::new(value)]])
}

/// `rho = H(RHO, nf_1, nf_2, index)`: the nullifier seed of output note
/// `index` of a spend that published `nf_1` and `nf_2`.
///
/// A sender does not choose an output's `rho`. The spend circuit derives it
/// from both nullifiers the leaf publishes, so that every note the pool ever
/// creates has a distinct `rho`, and `index` separates the two outputs of one
/// spend.
///
/// Both nullifiers are in the preimage because a leaf may carry its real
/// input in either slot. At least one input is real,
/// a real note's nullifier is settled exactly once over the life of the chain,
/// and the chain refuses a nullifier it has already seen, so the pair
/// `(nf_1, nf_2)` can never repeat no matter which slot holds the dummy.
/// Deriving from slot 0 alone would rest the whole uniqueness argument on a
/// prover-chosen value whenever slot 0 is the dummy.
///
/// A freely chosen `rho` is a griefing vector. `nf` depends on the recipient's
/// key, `rho` and `r`, and a sender picks all three for a note it creates, so
/// a sender who pays the same recipient twice with one `(rho, r)` creates two
/// notes that share a nullifier, of which the recipient can spend exactly one;
/// the other is stranded for good, at the cost of the smaller note.
pub fn output_rho(nf_1: &Digest, nf_2: &Digest, index: u64) -> Digest {
    Digest::hash_felts(
        domain::RHO,
        &[nf_1.felts(), nf_2.felts(), &[Felt::new(index)]],
    )
}

/// `rho` of a note created outside a spend proof: a shield at M4, a coinbase
/// at M6.
///
/// ```text
/// rho = H(RHO_ENTRY, block_number, entry_index_hi, entry_index_lo)
/// ```
///
/// [`output_rho`] derives a spend output's `rho` from the nullifiers the leaf
/// publishes, which removes the sender's choice. An entry has no spent
/// nullifier to derive from, so it derives from a unique on-chain identifier
/// instead: `entry_index` is a chain-wide monotone counter over pool entries,
/// so the pair `(block_number, entry_index)` never repeats and neither does
/// `rho`.
///
/// **The chain cannot check this.** `inner = H(NOTE, pk, rho, r)` is opaque by
/// construction, which is what keeps a shielded entry's recipient private
/// while its value is public, so what the chain owes is the identifier:
/// `pallet-shielded` publishes `block_number` and `entry_index` with every
/// shield, and the recipient recomputes `rho` from them; reading it out of the
/// ciphertext would trust the sender to have followed the rule. A shielder that ignores the rule can only strand its
/// own note, since computing anyone else's nullifier needs their `nk`. A
/// wallet should refuse a received note whose nullifier duplicates one it
/// already holds or one already settled.
pub fn entry_rho(block_number: u32, entry_index: u64) -> Digest {
    // Two 32-bit limbs, high then low: the same split the chain's own
    // `u64_to_felts` makes, so a `u64` never reaches the field as one element
    // that could exceed the modulus.
    let index = [
        Felt::new(entry_index >> 32),
        Felt::new(entry_index & 0xFFFF_FFFF),
    ];
    Digest::hash_felts(
        domain::RHO_ENTRY,
        &[&[Felt::new(block_number as u64)], &index],
    )
}

/// `rho` of the coinbase note a block mints to its author.
///
/// ```text
/// rho = H(RHO_COINBASE, block_number)
/// ```
///
/// The same argument as [`entry_rho`], over a shorter identifier. A block
/// mints exactly one coinbase note, so the block number alone names it, and no
/// two coinbase notes can share a nullifier seed. The domain tag is what keeps
/// a coinbase of block `n` off the preimage of a shield in block `n` at entry
/// index `0`.
///
/// The node computes this before it proposes, which is the reason the rule is
/// the block number and not the pool's entry counter: `inner = H(NOTE, pk,
/// rho, r)` is built while the block is being proposed, and how many shields
/// that block will carry is not known then.
///
/// There is no randomness in this, and none in [`coinbase_r`] either. Two
/// proposals at one height on one chain, which is what a re-proposed block or
/// an orphan looks like, carry the same `inner`; only the canonical one is
/// ever in a tree, and the header's author label is already the same in both,
/// so the note adds no linkage the block did not already carry. What the
/// derivation does keep apart is two chains: [`coinbase_r`] hashes the
/// genesis, so one miner key used on a testnet and on mainnet mints unrelated
/// notes at equal heights. Two chains built from one genesis, which is what a
/// repeated `--dev --tmp` is, are one chain by this rule and do repeat.
///
/// **The chain cannot check this**, for the reason [`entry_rho`] gives:
/// `inner` is opaque. What the chain owes is the identifier, and it owes
/// nothing extra here because the block number is already the key the record
/// is stored under.
pub fn coinbase_rho(block_number: u32) -> Digest {
    Digest::hash_felts(domain::RHO_COINBASE, &[&[Felt::new(block_number as u64)]])
}

/// `r` of the coinbase note a block mints to its author.
///
/// ```text
/// r = H(R_COINBASE, cvk, H_bytes("qnero/coinbase-chain", genesis_hash), block_number)
/// ```
///
/// Every other note reaches its recipient as an ML-KEM ciphertext carrying
/// `(rho, r)`. A coinbase note cannot: the block author's node is what builds
/// it, one per block, and that node cannot link an ML-KEM implementation. The
/// chain's own post-quantum Noise transport pins a different, semver
/// incompatible `ml-kem`, and the two cannot be in one binary (the split this
/// crate exists for, `crate` docs). So the randomness is derived instead, from
/// a coinbase viewing key the operator configures its node with and its wallet
/// keeps.
///
/// What that buys and what it costs:
///
/// - The note stays private. `inner = H(NOTE, pk, rho, r)` is what the chain publishes, and
///   recovering `pk` from it needs `r`, which needs `cvk`. Holding the miner's address is not
///   enough, which is the property an encrypted payload would have given.
/// - `cvk` is a viewing-tier secret for coinbase notes and nothing else. Whoever holds it, together
///   with the address, can pick the miner's coinbase notes out of the tree. It confers no ability
///   to spend: that needs `ask`. It says nothing about any other note the wallet holds.
/// - It is only for a note the author pays to itself. Paying a coinbase to an address whose `cvk`
///   the node does not hold needs the encrypted payload, which the pallet still accepts and the
///   wallet still reads.
///
/// The chain's genesis is in the preimage because the derivation has no
/// randomness in it. Without that binding, one miner key configured on a
/// testnet and on mainnet, or on any two chains with different genesis blocks,
/// mints byte-identical `inner` values at equal heights on both, and anyone
/// who can point at that operator's coinbase notes on the chain that matters
/// less points at them on the other by comparing 32 bytes. Both the node and
/// the wallet already hold the genesis hash, so the binding costs a scan
/// nothing.
pub fn coinbase_r(cvk: &Digest, genesis_hash: &[u8], block_number: u32) -> Digest {
    // The genesis is arbitrary bytes from outside the field, so it is hashed
    // to canonical limbs before it joins a felt preimage.
    let chain = Digest::hash_bytes(&[b"qnero/coinbase-chain".as_slice(), genesis_hash]);
    Digest::hash_felts(
        domain::R_COINBASE,
        &[
            cvk.felts(),
            chain.felts(),
            &[Felt::new(block_number as u64)],
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two rules for a note created outside a spend proof hash different
    /// identifier tuples, and the whole point of the separate domain tag is
    /// that a coinbase of block `n` and the first entry of block `n` cannot
    /// land on one `rho`. A shared tag would have made those two preimages
    /// `(n, 0, 0)` and `(n)`, which the sponge pads differently today and
    /// which nothing would keep apart if the padding ever changed.
    #[test]
    fn a_coinbase_rho_is_never_an_entry_rho() {
        for block in [0u32, 1, 2, 7, 4096, u32::MAX] {
            assert_ne!(coinbase_rho(block), entry_rho(block, 0));
            assert_ne!(coinbase_rho(block), entry_rho(block, 1));
        }
    }

    /// The two halves of a coinbase note's randomness hash the same block
    /// number, and the domain tags are the whole of what keeps them apart.
    #[test]
    fn a_coinbase_rho_and_its_r_are_never_one_value() {
        let cvk = Digest::hash_bytes(&[b"cvk"]);
        for block in [0u32, 1, 4096, u32::MAX] {
            assert_ne!(coinbase_rho(block), coinbase_r(&cvk, &[7u8; 32], block));
        }
    }

    /// One miner key on two chains mints unrelated notes at equal heights.
    ///
    /// The derivation has no randomness in it, so without the genesis in the
    /// preimage the same key would publish byte-identical `inner` values at
    /// equal heights on a testnet and on mainnet, and matching 32 bytes would
    /// carry an identification from the chain that matters less to the one
    /// that matters. This is the regression test for that.
    #[test]
    fn one_miner_key_on_two_chains_mints_unrelated_notes() {
        let cvk = Digest::hash_bytes(&[b"one operator"]);
        let pk = Digest::hash_bytes(&[b"pk"]);
        let mainnet = [1u8; 32];
        let testnet = [2u8; 32];
        for block in [0u32, 1, 4096, u32::MAX] {
            assert_ne!(
                coinbase_r(&cvk, &mainnet, block),
                coinbase_r(&cvk, &testnet, block),
                "block {block}: two chains must not share a coinbase `r`"
            );
            assert_ne!(
                note_inner(
                    &pk,
                    &coinbase_rho(block),
                    &coinbase_r(&cvk, &mainnet, block)
                ),
                note_inner(
                    &pk,
                    &coinbase_rho(block),
                    &coinbase_r(&cvk, &testnet, block)
                ),
                "block {block}: two chains must not share a coinbase `inner`"
            );
        }
        assert_eq!(
            coinbase_r(&cvk, &mainnet, 9),
            coinbase_r(&cvk, &mainnet, 9),
            "one chain, one height, one note: the wallet finds it by recomputing it"
        );
    }

    /// `r` is what an observer holding the miner's address still does not
    /// have, so it has to move with the key and with the block.
    #[test]
    fn a_coinbase_r_follows_the_key_and_the_block() {
        let mine = Digest::hash_bytes(&[b"mine"]);
        let theirs = Digest::hash_bytes(&[b"theirs"]);
        let chain = [3u8; 32];
        assert_ne!(coinbase_r(&mine, &chain, 7), coinbase_r(&theirs, &chain, 7));
        assert_ne!(coinbase_r(&mine, &chain, 7), coinbase_r(&mine, &chain, 8));
        assert_eq!(coinbase_r(&mine, &chain, 7), coinbase_r(&mine, &chain, 7));
    }

    /// One coinbase per block, so the block number alone has to separate them.
    #[test]
    fn a_coinbase_rho_is_unique_per_block() {
        let a = coinbase_rho(10);
        let b = coinbase_rho(11);
        assert_ne!(a, b);
        assert_eq!(a, coinbase_rho(10));
    }
}
