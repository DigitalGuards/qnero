//! The Qnero v0 wallet.

pub mod chain;
pub mod dev_account;
pub mod extrinsic;
pub mod fee;
pub mod keys;
pub mod memo;
pub mod metadata;
pub mod rpc;
pub mod scale;
pub mod select;
pub mod store;
pub mod wallet;

/// Planck per pool quantum.
///
/// The pool counts values in quanta and the chain's balance is `u128` planck
/// at twelve decimals, so one quantum is 0.01 QTC. It is
/// `pallet_shielded::POOL_QUANTUM`, a constant of the pallet crate with no
/// `#[pallet::constant]` declaration, so it has no metadata surface for a
/// wallet to read and this copy is the one value here that could drift from
/// the chain. A mismatch surfaces: the runtime refuses a value that is not a
/// whole multiple with `ValueNotQuantized`, and `shield` confirms a leaf was
/// actually appended before it reports success, so a refused dispatch comes
/// back as an error. See `docs/WALLET.md`.
pub const POOL_QUANTUM: u128 = 10_000_000_000;
