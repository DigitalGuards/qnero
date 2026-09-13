//! Randomness, and the startup probe that proves it works.
//!
//! Two independent entropy paths reach this module, both ending at
//! `crypto.getRandomValues`:
//!
//! - rand 0.9 through getrandom 0.3, which is what this crate draws with and
//!   what `qnero-aggregator` draws its padding nullifier preimages and slot
//!   shuffle with.
//! - rand 0.10 through getrandom 0.4, which is what qp-plonky2 draws every
//!   zero-knowledge blinding value with, inside `RandomValueGenerator` during
//!   witness generation.
//!
//! The second one is the reason [`entropy_self_check`] exists. Blinding values
//! are drawn at PROVING time, so a page served from a non-secure context (a
//! plain `http://` LAN address, where `crypto.getRandomValues` is undefined)
//! does not fail at load, and does not fail at circuit build. It fails tens of
//! seconds into the first private batch, inside plonky2, with an error nobody
//! can attribute. Drawing from both paths at startup turns that into an error
//! at the call a user is still watching.

use anyhow::{ensure, Result};
use qnero_notes::Digest;

/// The CSPRNG this crate draws from. Seeded from the browser's, per the
/// `wasm_js` backend.
pub fn rng() -> rand::rngs::ThreadRng {
    rand::rng()
}

/// 32 raw bytes, for an ML-KEM encapsulation seed.
pub fn random_seed() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes)
        .map_err(|_| anyhow::anyhow!("the browser CSPRNG refused to fill 32 bytes"))?;
    Ok(bytes)
}

/// A canonical digest from fresh randomness, drawn the way
/// [`qnero_note_core::Note::random`] draws one: bytes from the CSPRNG, hashed
/// under a domain so the result is four canonical limbs.
pub fn random_digest(domain: &[u8]) -> Result<Digest> {
    Ok(Digest::hash_bytes(&[domain, &random_seed()?]))
}

/// Draw from both entropy paths and refuse to go on if either is dead.
///
/// Call it once, at worker startup, before any proving is offered. It costs
/// microseconds and it is the difference between an error at load and an error
/// 30 seconds into a proof.
///
/// The checks are deliberately weak: 32 bytes that are not all equal, and four
/// field elements that are not all equal. A broken backend in this environment
/// returns zeros or throws, and either is caught. Nothing here is a statistical
/// test of the browser's CSPRNG, which is not something a wasm module can
/// audit.
pub fn entropy_self_check() -> Result<()> {
    let bytes = random_seed()?;
    ensure!(
        bytes.iter().any(|byte| *byte != bytes[0]),
        "the browser CSPRNG returned 32 identical bytes: this page is probably not a secure \
         context, so crypto.getRandomValues is undefined. Serve it over https:// or \
         http://localhost."
    );

    // qp-plonky2's own path, which is where zero-knowledge blinding values come
    // from. `Sample::rand` calls `rand::rng()` against rand 0.10 and getrandom
    // 0.4, a different crate version from the one above with its own feature
    // and its own backend selection.
    use plonky2::field::types::Sample;
    let felts: [qnero_circuit::F; 4] = core::array::from_fn(|_| qnero_circuit::F::rand());
    ensure!(
        felts.iter().any(|felt| *felt != felts[0]),
        "plonky2's randomness returned four identical field elements: zero-knowledge blinding \
         would be deterministic, which is a privacy failure that still produces a valid proof"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_entropy_paths_answer() {
        entropy_self_check().expect("a native build has both backends");
    }

    #[test]
    fn a_random_digest_is_canonical_and_fresh() {
        let first = random_digest(b"test").unwrap();
        let second = random_digest(b"test").unwrap();
        assert_ne!(first, second);
        assert_eq!(
            Digest::from_bytes(&first.to_bytes()).unwrap(),
            first,
            "a digest from hashed randomness round-trips through its bytes"
        );
    }
}
