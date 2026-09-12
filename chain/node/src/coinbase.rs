//! The coinbase inherent, node side.
//!
//! Under v1 mandatory privacy a block's reward is a shielded note, and a note
//! needs a recipient key the chain cannot see. The runtime therefore cannot
//! build the coinbase for itself: it computes the value, and nothing else. The
//! author's node supplies `inner = H(NOTE, pk, rho, r)`, and `pallet-shielded`
//! hashes `cm = H(CM, inner, value)` over the value it decided.
//!
//! **Why the note is derived and not encrypted.** Every other note reaches its
//! recipient as an ML-KEM ciphertext. This node cannot build one: the chain's
//! own post-quantum Noise transport (`litep2p` through `clatter`) pins
//! `ml-kem` 0.2, the wallet's note encryption uses `ml-kem` 0.3, and the two
//! share a `kem` dependency that resolves to one version, so a binary cannot
//! hold both. `qnero-note-core` exists for exactly this split and the
//! constraint is in its module documentation. So the block author's node is
//! configured with a miner key (`pk` and a coinbase viewing key `cvk`) and
//! derives the note instead:
//!
//! ```text
//! rho   = H(RHO_COINBASE, block_number)
//! chain = H_bytes("qnero/coinbase-chain", genesis_hash)
//! r     = H(R_COINBASE, cvk, chain, block_number)
//! inner = H(NOTE, pk, rho, r)
//! ```
//!
//! What it costs and what it keeps is in `qnero_note_core::coinbase_r`. The
//! short version: the note stays private against anyone holding only the
//! miner's address, `cvk` is a viewing-tier secret for coinbase notes alone,
//! and a coinbase paid to somebody else's address still needs the encrypted
//! payload, which the pallet accepts and the wallet reads.
//!
//! `rho` is the block number rather than a random value because a block mints
//! exactly one coinbase note, so the height names it and no two coinbase notes
//! can share a nullifier seed. The node knows the height it is proposing at,
//! which the pool's entry counter would not give it: that depends on how many
//! shields the block ends up carrying.
//!
//! The chain's genesis is in `r` because the rest of the derivation is
//! deterministic. One miner key configured on a testnet and on mainnet would
//! otherwise publish the same `inner` at equal heights on both, and matching
//! 32 bytes would carry an identification from one chain to the other.

use std::sync::Arc;

use qnero_note_core::{note_inner, MinerKey};
use qp_coinbase::CoinbaseInherentData;
use sp_blockchain::HeaderBackend;
use sp_inherents::{InherentData, InherentIdentifier};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

/// Supplies the coinbase payload for the block being proposed, and answers for
/// the identifier when the runtime reports one missing.
///
/// The import path builds one with no payload: a node that is not authoring
/// has no miner key and builds nobody's note. It is still in the provider
/// tuple, because `PowBlockImport::check_inherents` turns an inherent error
/// whose identifier no provider claims into `CheckInherentsUnknownError`, and
/// a block missing its coinbase deserves the refusal that says so.
#[derive(Clone)]
pub struct CoinbaseInherentDataProvider {
	payload: Option<CoinbaseInherentData>,
}

impl CoinbaseInherentDataProvider {
	/// The import-side provider: no payload, error handling only.
	pub fn checking() -> Self {
		Self { payload: None }
	}

	/// The authoring-side provider for the child of `parent`.
	///
	/// Without a miner key there is no payload, the node builds a block with no
	/// coinbase inherent, and its own import refuses that block. An authority
	/// is held to supplying the key at startup for exactly that reason.
	pub fn for_child_of<Block, Client>(
		client: &Arc<Client>,
		parent: Block::Hash,
		miner_key: Option<&MinerKey>,
	) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
	where
		Block: BlockT,
		Client: HeaderBackend<Block>,
		<Block::Header as HeaderT>::Number: TryInto<u32>,
	{
		let Some(miner_key) = miner_key else {
			return Ok(Self::checking());
		};
		let parent_number = client
			.number(parent)?
			.ok_or_else(|| format!("no header for the proposal's parent {parent:?}"))?;
		let parent_number: u32 = parent_number
			.try_into()
			.map_err(|_| "block number does not fit the coinbase rho rule".to_string())?;
		let block_number = parent_number.saturating_add(1);
		// The genesis of the chain this node serves, which the wallet reads
		// from the same node and binds its store to.
		let genesis = client.info().genesis_hash;
		Ok(Self { payload: Some(build_payload(miner_key, genesis.as_ref(), block_number)) })
	}
}

/// Build one block's coinbase payload for `miner_key`.
///
/// The value is absent on purpose. A coinbase note's value is public, on chain,
/// in `Shielded::CoinbaseValues`, because the chain hashes it into the
/// commitment; `inner` commits to everything else. The ciphertext field is
/// empty, which is what a derived coinbase is: there is nothing to send when
/// the recipient can recompute the note from its own key and the block number.
pub fn build_payload(
	miner_key: &MinerKey,
	genesis_hash: &[u8],
	block_number: u32,
) -> CoinbaseInherentData {
	let rho = qnero_note_core::coinbase_rho(block_number);
	let r = qnero_note_core::coinbase_r(&miner_key.cvk, genesis_hash, block_number);
	CoinbaseInherentData {
		inner: note_inner(&miner_key.pk, &rho, &r).to_bytes(),
		ciphertext: Vec::new(),
	}
}

#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for CoinbaseInherentDataProvider {
	async fn provide_inherent_data(
		&self,
		inherent_data: &mut InherentData,
	) -> Result<(), sp_inherents::Error> {
		match &self.payload {
			Some(payload) => inherent_data.put_data(qp_coinbase::INHERENT_IDENTIFIER, payload),
			None => Ok(()),
		}
	}

	async fn try_handle_error(
		&self,
		identifier: &InherentIdentifier,
		error: &[u8],
	) -> Option<Result<(), sp_inherents::Error>> {
		let reported = qp_coinbase::InherentError::try_from(identifier, error)?;
		Some(Err(sp_inherents::Error::Application(Box::from(match reported {
			qp_coinbase::InherentError::Missing =>
				"the block carries no coinbase inherent, so its reward is minted nowhere",
		}))))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use qnero_note_core::Digest;

	/// Any 32 bytes: the derivation hashes the genesis, so nothing here needs
	/// a real one.
	const GENESIS: [u8; 32] = [4u8; 32];

	fn miner_key(seed: &str) -> MinerKey {
		MinerKey::new(
			Digest::hash_bytes(&[b"pk", seed.as_bytes()]),
			Digest::hash_bytes(&[b"cvk", seed.as_bytes()]),
		)
	}

	/// The whole agreement between the node and the wallet: the payload the
	/// node publishes opens the commitment the chain appends, at the value the
	/// chain decided and at no other.
	#[test]
	fn a_coinbase_payload_opens_the_commitment_the_chain_computes() {
		let key = miner_key("mine");
		let payload = build_payload(&key, &GENESIS, 42);

		let note = key.coinbase_note(&GENESIS, 42, 11).expect("a note");
		assert_eq!(note.inner().to_bytes(), payload.inner);
		assert_eq!(
			note.commitment().to_bytes(),
			qnero_circuit::chain::commitment(&payload.inner, 11).expect("canonical inner"),
			"the wallet's commitment must be the one the chain appends"
		);
		assert!(payload.ciphertext.is_empty(), "a derived coinbase carries no ciphertext");
	}

	/// Two blocks are two notes, and one block on one chain is always the same
	/// note: the derivation has no randomness in it, which is what lets a
	/// wallet find the note without being told anything.
	#[test]
	fn every_block_gets_its_own_note() {
		let key = miner_key("mine");
		assert_ne!(build_payload(&key, &GENESIS, 1).inner, build_payload(&key, &GENESIS, 2).inner);
		assert_eq!(build_payload(&key, &GENESIS, 1).inner, build_payload(&key, &GENESIS, 1).inner);
	}

	/// The determinism stops at the chain boundary. An operator that runs one
	/// miner key on a testnet and on mainnet publishes unrelated notes at
	/// equal heights, so nobody carries an identification across by comparing
	/// 32 bytes.
	#[test]
	fn two_chains_never_share_a_note() {
		let key = miner_key("mine");
		let other_chain = [9u8; 32];
		assert_ne!(
			build_payload(&key, &GENESIS, 7).inner,
			build_payload(&key, &other_chain, 7).inner
		);
	}

	/// Holding the address is not holding the coinbase view. Two miners with
	/// the same `pk` and different `cvk` publish different notes, so `cvk` is
	/// what an observer is missing.
	#[test]
	fn the_coinbase_view_needs_more_than_the_address() {
		let mine = miner_key("mine");
		let same_pk_other_cvk =
			MinerKey::new(mine.pk, qnero_note_core::Digest::hash_bytes(&[b"someone else"]));
		assert_ne!(
			build_payload(&mine, &GENESIS, 5).inner,
			build_payload(&same_pk_other_cvk, &GENESIS, 5).inner
		);
	}
}
