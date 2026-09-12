//! The coinbase inherent: what a block author hands the runtime so the block's
//! reward can be minted as a shielded note instead of a transparent credit.
//!
//! Three things live here because the node and the runtime both need them and
//! neither can depend on the other: the inherent identifier, the payload an
//! author supplies, and the sink trait `pallet-mining-rewards` pays the block
//! reward into.
//!
//! The payload is the author's alone. `inner = H(NOTE, pk, rho, r)` hides the
//! recipient key of the note, and the ciphertext is that note's `(rho, r)`
//! encrypted to the author's own view key. The chain checks neither: it
//! computes `cm = H(CM, inner, value)` over the value it decided itself and
//! appends that, so an author that supplies a malformed payload can only
//! strand its own reward. What the chain does enforce is that every block
//! carries exactly one of these, which is what makes the coinbase the only way
//! new value enters circulation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use sp_inherents::{InherentIdentifier, IsFatalError};

/// The inherent identifier. Eight bytes, like every other one.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"qnerocbs";

/// What the block author's node puts in the inherent data.
///
/// `inner` is four canonical Goldilocks limbs, little endian per limb: the
/// same encoding a note commitment takes. `ciphertext` is a
/// `qnero_pqcrypto::note_encryption::NoteCiphertext` serialized whole, and the
/// chain never parses it.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct CoinbaseInherentData {
	pub inner: [u8; 32],
	pub ciphertext: Vec<u8>,
}

/// What a runtime can report about a block's coinbase inherent.
///
/// Only one of these is reachable. The runtime never checks an author's
/// payload against anything, so the single failure it can report is the
/// absence of the inherent, and that one is fatal: a block with no coinbase
/// mints its reward nowhere and is refused rather than imported with the
/// reward silently rolled into the next block.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub enum InherentError {
	/// The block carries no coinbase inherent.
	Missing,
}

impl IsFatalError for InherentError {
	fn is_fatal_error(&self) -> bool {
		true
	}
}

impl InherentError {
	/// Decode an error this pallet reported, for a node's `try_handle_error`.
	pub fn try_from(identifier: &InherentIdentifier, mut error: &[u8]) -> Option<Self> {
		if identifier != &INHERENT_IDENTIFIER {
			return None;
		}
		<InherentError as Decode>::decode(&mut error).ok()
	}
}

/// Where a block reward goes.
///
/// `pallet-mining-rewards` computes the emission and hands it over; the
/// shielded pool turns it into the block's coinbase note. The sink owns the
/// issuance side of that credit: the reward is newly emitted value, so
/// whatever takes it is what has to account for it.
///
/// Returns the part it could not take, which the caller keeps for the next
/// block. A block with no coinbase inherent is the one case that reaches it,
/// and rolling the credit forward is what keeps an author from losing a reward
/// to a payload its own node failed to build.
pub trait CoinbaseSink<Balance> {
	fn deposit_coinbase(amount: Balance) -> Result<(), Balance>;
}

/// For a runtime that mints no coinbase: the whole credit comes back.
impl<Balance> CoinbaseSink<Balance> for () {
	fn deposit_coinbase(amount: Balance) -> Result<(), Balance> {
		Err(amount)
	}
}
