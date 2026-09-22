//! The fields of `VERSION` that nothing else pins.
//!
//! `call_filter.rs::the_runtime_identity_is_pinned` covers `spec_name`,
//! `impl_name` and the `(spec_version, transaction_version)` pair. This file
//! covers `system_version`, which has no tripwire anywhere and which decides
//! how a block's `extrinsicsRoot` is built.

use qnero_runtime::VERSION;

/// `system_version` must stay 1.
///
/// `sp-version` switches the extrinsics-root construction at 2, silently:
/// version 0 and 1 build the root as `LayoutV0` over the encoded extrinsics,
/// and 2 moves to `LayoutV1`. The shielded pool's block bodies are
/// authenticated against `extrinsicsRoot`, and both the wallet and the explorer
/// recompute it as `LayoutV0`. A bump here would change every block hash on the
/// chain and break that recomputation with nothing in the build to say so, so
/// the number is pinned rather than inherited.
///
/// `extrinsics_root.rs` pins the construction itself, against `sp_trie`'s
/// `LayoutV0` named directly and against a known-answer vector both wallets
/// check. This assertion stays because it belongs with the other identity
/// fields and costs nothing.
#[test]
fn the_extrinsics_root_construction_is_pinned() {
	assert_eq!(
		VERSION.system_version, 1,
		"system_version moved; sp-version switches extrinsicsRoot from LayoutV0 to \
		 LayoutV1 at 2, which changes every block hash and breaks the client-side \
		 recomputation the shielded pool's block bodies are authenticated by"
	);
}
