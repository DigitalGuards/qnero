//! The transparent entry's extrinsic type, and the consensus rule that keeps it
//! to one signature scheme.
//!
//! # Consensus rule: the transparent entry admits ML-DSA-87 only
//!
//! `qp-dilithium-crypto` carries a two-variant [`DilithiumSignatureScheme`]:
//! `Dilithium87` is ML-DSA-87 (FIPS 204, level 5) and `Dilithium65` is
//! ML-DSA-65 (level 3). The enum is upstream's and stays exactly as it is, for
//! two reasons. The next subtree merge into `chain/` would otherwise conflict
//! on a type every upstream primitive touches, and the metadata a client reads
//! keeps describing both variant encodings, which is what lets a decoder size a
//! signature blob by its variant index without guessing.
//!
//! The refusal of the `Dilithium65` variant is a rule of the chain:
//!
//! > A signed extrinsic whose signature is the `Dilithium65` variant is invalid.
//! > It is refused with [`InvalidTransaction::BadSigner`], before its signature
//! > is verified, before any transaction extension runs, and before its call is
//! > dispatched.
//!
//! The refusal sits in [`Checkable::check`] for [`QneroUncheckedExtrinsic`],
//! which is the single seam under both `Executive::validate_transaction` and
//! `Executive::apply_extrinsic`. Every signed call therefore inherits it with no
//! per-call enumeration: transfers, governance, multisig, `Utility::batch_all`,
//! `Vesting::claim` and `Shielded::shield` alike. The `try-runtime` blind-check
//! path carries the same refusal, so a replay, which skips signature
//! verification entirely, cannot admit what the live path refuses.
//!
//! ## Why it is not a transaction extension
//!
//! A [`TransactionExtension`](sp_runtime::traits::TransactionExtension) cannot
//! see the variant. By the time one runs, `check` has already verified and
//! dropped the signature and handed the extension an `AccountId32`, and both
//! variants hash to an `AccountId32` of the same shape
//! (`IdentifyAccount for DilithiumSigner`), so a Dilithium65 account is
//! byte-indistinguishable from a Dilithium87 one in state, in an address and in
//! `origin`. Adding an extension would also change the signed extrinsic
//! encoding, which moves `transaction_version` and every hand-written copy of
//! the extension tuple. This wrapper moves neither: the derived SCALE codec of a
//! single-field struct is the inner encoding byte for byte, and [`TypeInfo`] is
//! forwarded to the inner type, so the extrinsic's metadata entry is unchanged
//! as well.
//!
//! ## Where a Dilithium65 key can still be minted
//!
//! The vendored `sc-cli` fork still offers `key generate --scheme dilithium65`,
//! and the keystore will still hold what it mints. That is upstream CLI surface
//! and it is left alone on purpose: this rule is what makes the material inert,
//! because nothing signed with it can enter a block or the transaction pool.
//!
//! ## Upgrade caveat
//!
//! This is a consensus break, and it is one on purpose. Before it, an ML-DSA-65
//! extrinsic was admitted and included (refused only later, at dispatch, by the
//! v1 call filter). A block already carrying one fails to re-execute under this
//! rule. Qnero is devnet-only, so no such block exists outside a local chain,
//! and a devnet carrying one has to be reset.

extern crate alloc;

use crate::{Address, RuntimeCall, Signature, TxExtension};
use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_support::{
	dispatch::{DispatchInfo, GetDispatchInfo},
	traits::{InherentBuilder, SignedTransactionBuilder},
};
use qp_dilithium_crypto::DilithiumSignatureScheme;
use scale_info::TypeInfo;
use sp_runtime::{
	generic::{Preamble, UncheckedExtrinsic},
	serde,
	traits::{Checkable, ExtrinsicCall, ExtrinsicLike, ExtrinsicMetadata, LazyExtrinsic},
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	OpaqueExtrinsic,
};

/// The upstream generic extrinsic this runtime's own extrinsic wraps.
///
/// Kept as a named alias so the wrapper below stays a one-line change if the
/// address, call, signature or extension types move.
pub type UpstreamUncheckedExtrinsic =
	UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

/// Qnero's unchecked extrinsic: the upstream generic one, plus the consensus
/// rule at the top of this module.
///
/// SCALE-transparent by construction. The derived codec of a single-field tuple
/// struct is the field's own encoding, and [`TypeInfo`] is forwarded, so the
/// wire format, `transaction_version` and the extrinsic's metadata entry are all
/// the same as the type it wraps.
#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, DecodeWithMemTracking)]
pub struct QneroUncheckedExtrinsic(pub UpstreamUncheckedExtrinsic);

impl QneroUncheckedExtrinsic {
	/// New instance of a bare (inherent or unsigned) extrinsic.
	pub fn new_bare(function: RuntimeCall) -> Self {
		Self(UpstreamUncheckedExtrinsic::new_bare(function))
	}

	/// New instance of an old-school signed transaction.
	pub fn new_signed(
		function: RuntimeCall,
		signed: Address,
		signature: Signature,
		tx_ext: TxExtension,
	) -> Self {
		Self(UpstreamUncheckedExtrinsic::new_signed(function, signed, signature, tx_ext))
	}

	/// The consensus rule of this module, as one function.
	///
	/// `Ok(())` for a bare extrinsic, a general transaction, and a signed
	/// transaction carrying an ML-DSA-87 signature. `InvalidTransaction::BadSigner`
	/// for a signed transaction carrying the ML-DSA-65 variant.
	///
	/// Both callers of this are consensus paths: `check` on the live path and
	/// `unchecked_into_checked_i_know_what_i_am_doing` on the `try-runtime`
	/// replay path. Keep them in step.
	fn ensure_supported_signature_scheme(&self) -> Result<(), TransactionValidityError> {
		match &self.0.preamble {
			Preamble::Signed(_, DilithiumSignatureScheme::Dilithium65(_), _) =>
				Err(InvalidTransaction::BadSigner.into()),
			_ => Ok(()),
		}
	}
}

/// Forwarded so the extrinsic's metadata entry is the upstream one, byte for
/// byte: same type id, same type definition, same registry slot. A derived
/// `TypeInfo` would describe a composite wrapping it, which moves the metadata
/// and breaks every client that sizes a signature blob off the signature
/// variant's index.
impl TypeInfo for QneroUncheckedExtrinsic {
	type Identity = <UpstreamUncheckedExtrinsic as TypeInfo>::Identity;

	fn type_info() -> scale_info::Type {
		<UpstreamUncheckedExtrinsic as TypeInfo>::type_info()
	}
}

impl<C> Checkable<C> for QneroUncheckedExtrinsic
where
	UpstreamUncheckedExtrinsic: Checkable<C>,
{
	type Checked = <UpstreamUncheckedExtrinsic as Checkable<C>>::Checked;

	fn check(self, lookup: &C) -> Result<Self::Checked, TransactionValidityError> {
		self.ensure_supported_signature_scheme()?;
		self.0.check(lookup)
	}

	#[cfg(feature = "try-runtime")]
	fn unchecked_into_checked_i_know_what_i_am_doing(
		self,
		lookup: &C,
	) -> Result<Self::Checked, TransactionValidityError> {
		self.ensure_supported_signature_scheme()?;
		self.0.unchecked_into_checked_i_know_what_i_am_doing(lookup)
	}
}

impl ExtrinsicLike for QneroUncheckedExtrinsic {
	// Deprecated upstream in favour of `!is_bare()`, and forwarded anyway so
	// that a caller reading it off this type gets the same answer it got from
	// the type this wraps.
	#[allow(deprecated)]
	fn is_signed(&self) -> Option<bool> {
		<UpstreamUncheckedExtrinsic as ExtrinsicLike>::is_signed(&self.0)
	}

	fn is_bare(&self) -> bool {
		<UpstreamUncheckedExtrinsic as ExtrinsicLike>::is_bare(&self.0)
	}
}

impl ExtrinsicCall for QneroUncheckedExtrinsic {
	type Call = RuntimeCall;

	fn call(&self) -> &RuntimeCall {
		self.0.call()
	}

	fn into_call(self) -> RuntimeCall {
		self.0.into_call()
	}
}

impl ExtrinsicMetadata for QneroUncheckedExtrinsic {
	const VERSIONS: &'static [u8] = <UpstreamUncheckedExtrinsic as ExtrinsicMetadata>::VERSIONS;
	type TransactionExtensions = TxExtension;
}

impl InherentBuilder for QneroUncheckedExtrinsic {
	fn new_inherent(call: RuntimeCall) -> Self {
		Self::new_bare(call)
	}
}

impl SignedTransactionBuilder for QneroUncheckedExtrinsic {
	type Address = Address;
	type Signature = Signature;
	type Extension = TxExtension;

	fn new_signed_transaction(
		call: RuntimeCall,
		signed: Address,
		signature: Signature,
		tx_ext: TxExtension,
	) -> Self {
		Self::new_signed(call, signed, signature, tx_ext)
	}
}

impl LazyExtrinsic for QneroUncheckedExtrinsic {
	fn decode_unprefixed(data: &[u8]) -> Result<Self, codec::Error> {
		UpstreamUncheckedExtrinsic::decode_unprefixed(data).map(Self)
	}
}

impl GetDispatchInfo for QneroUncheckedExtrinsic {
	fn get_dispatch_info(&self) -> DispatchInfo {
		self.0.get_dispatch_info()
	}
}

impl From<QneroUncheckedExtrinsic> for OpaqueExtrinsic {
	fn from(extrinsic: QneroUncheckedExtrinsic) -> Self {
		extrinsic.0.into()
	}
}

impl serde::Serialize for QneroUncheckedExtrinsic {
	fn serialize<S: serde::Serializer>(&self, seq: S) -> Result<S::Ok, S::Error> {
		<UpstreamUncheckedExtrinsic as serde::Serialize>::serialize(&self.0, seq)
	}
}

impl<'a> serde::Deserialize<'a> for QneroUncheckedExtrinsic {
	fn deserialize<D: serde::Deserializer<'a>>(de: D) -> Result<Self, D::Error> {
		let bytes: Vec<u8> = sp_core::bytes::deserialize(de)?;
		Self::decode(&mut &bytes[..])
			.map_err(|e| serde::de::Error::custom(alloc::format!("Decode error: {}", e)))
	}
}
