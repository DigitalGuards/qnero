//! Everything the wallet reads out of the runtime's own metadata.
//!
//! Nothing here is a compiled-in copy of a chain value. The runtime moved
//! `CiphertextBytesPerFeeQuantum` and added and removed a payload-ratio bound
//! inside one `spec_version` during M4 (`docs/OPS-DEV.md`), and this chain
//! still answers `spec_version` 152 whatever it carries, so a pinned copy of a
//! constant or a call index is a wallet that builds a proof against the wrong
//! rule and finds out after paying for it. The pallet index, the three call
//! indices and the fee constants all come from `state_getMetadata`.
//!
//! The one number that has no metadata surface is `POOL_QUANTUM`; see
//! [`crate::POOL_QUANTUM`].

use anyhow::{anyhow, bail, Context, Result};
use codec::Decode;
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use scale_info::{PortableRegistry, TypeDef};
use serde_json::json;

use crate::rpc::{decode_hex, RpcClient};

/// Names the wallet looks up. They are the `construct_runtime` names, which
/// are also the storage prefixes.
pub const SHIELDED_PALLET: &str = "Shielded";
pub const ZK_TREE_PALLET: &str = "ZkTree";

/// The transaction extensions this wallet knows how to encode, in the order
/// the runtime declares them. A signed `shield` is built against this list and
/// refuses to sign when the runtime's list differs, because every extension
/// contributes bytes to the payload the signature covers and an unknown one
/// silently shifts everything after it.
pub const KNOWN_SIGNED_EXTENSIONS: &[&str] = &[
    "CheckNonZeroSender",
    "CheckSpecVersion",
    "CheckTxVersion",
    "CheckGenesis",
    "CheckMortality",
    "CheckNonce",
    "CheckWeight",
    "ReversibleTransactionExtension",
    "WormholeProofRecorderExtension",
    "ChargeTransactionPayment",
    "CheckMetadataHash",
    "WeightReclaim",
];

/// What the wallet needs from the runtime, resolved once per command.
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub shielded_pallet_index: u8,
    pub submit_private_batch: u8,
    pub submit_public_batch: u8,
    pub shield: u8,
    /// Anchor window, in blocks.
    pub block_hash_window: u32,
    /// Flat fee floor per real leaf slot, in pool quanta.
    pub min_leaf_fee: u64,
    /// Bytes of note ciphertext one quantum of fee buys.
    pub ciphertext_bytes_per_fee_quantum: u32,
    /// Size cap on one ciphertext. Exceeding it fails the extrinsic's SCALE
    /// decode, after the proof that committed to those bytes exists.
    pub max_ciphertext_bytes: u32,
    pub signed_extensions: Vec<String>,
}

impl ChainMetadata {
    /// Fetch and parse `state_getMetadata`.
    pub fn fetch(rpc: &RpcClient) -> Result<Self> {
        let blob: String = rpc.call_as("state_getMetadata", json!([]))?;
        Self::parse(&decode_hex(&blob)?)
    }

    pub fn parse(blob: &[u8]) -> Result<Self> {
        let prefixed = RuntimeMetadataPrefixed::decode(&mut &blob[..])
            .context("the node returned metadata this wallet cannot decode")?;
        let (pallets, extrinsic, types) = match prefixed.1 {
            RuntimeMetadata::V14(md) => (
                md.pallets
                    .into_iter()
                    .map(|p| PalletView {
                        name: p.name,
                        index: p.index,
                        call_type: p.calls.map(|c| c.ty.id),
                        constants: p.constants.into_iter().map(|c| (c.name, c.value)).collect(),
                    })
                    .collect::<Vec<_>>(),
                md.extrinsic
                    .signed_extensions
                    .iter()
                    .map(|e| e.identifier.clone())
                    .collect::<Vec<_>>(),
                md.types,
            ),
            RuntimeMetadata::V15(md) => (
                md.pallets
                    .into_iter()
                    .map(|p| PalletView {
                        name: p.name,
                        index: p.index,
                        call_type: p.calls.map(|c| c.ty.id),
                        constants: p.constants.into_iter().map(|c| (c.name, c.value)).collect(),
                    })
                    .collect::<Vec<_>>(),
                md.extrinsic
                    .signed_extensions
                    .iter()
                    .map(|e| e.identifier.clone())
                    .collect::<Vec<_>>(),
                md.types,
            ),
            _ => bail!("this wallet reads metadata v14 and v15; the node answered another version"),
        };

        let shielded = pallets
            .iter()
            .find(|p| p.name == SHIELDED_PALLET)
            .ok_or_else(|| anyhow!("the runtime has no `{SHIELDED_PALLET}` pallet"))?;
        let call_type = shielded
            .call_type
            .ok_or_else(|| anyhow!("`{SHIELDED_PALLET}` declares no calls"))?;

        Ok(Self {
            shielded_pallet_index: shielded.index,
            submit_private_batch: call_index(&types, call_type, "submit_private_batch")?,
            submit_public_batch: call_index(&types, call_type, "submit_public_batch")?,
            shield: call_index(&types, call_type, "shield")?,
            block_hash_window: shielded.decode_u32("BlockHashWindow")?,
            min_leaf_fee: shielded.decode_u64("MinLeafFee")?,
            ciphertext_bytes_per_fee_quantum: shielded
                .decode_u32("CiphertextBytesPerFeeQuantum")?,
            max_ciphertext_bytes: shielded.decode_u32("MaxCiphertextBytes")?,
            signed_extensions: extrinsic,
        })
    }

    /// The signed `shield` path refuses to sign a payload it cannot lay out.
    ///
    /// Every extension contributes explicit bytes to the extrinsic and
    /// implicit bytes to the signed payload. An extension this wallet does not
    /// know shifts both, and the failure a node reports is `Transaction has a
    /// bad signature`, which says nothing about why.
    pub fn ensure_known_signed_extensions(&self) -> Result<()> {
        let found: Vec<&str> = self.signed_extensions.iter().map(String::as_str).collect();
        if found != KNOWN_SIGNED_EXTENSIONS {
            bail!(
                "this runtime declares transaction extensions this wallet cannot lay out.\n  \
                 runtime: {:?}\n  wallet:  {:?}\n\
                 Signing would produce a payload the node reads as a bad signature. \
                 Update `KNOWN_SIGNED_EXTENSIONS` and the explicit encoding beside it.",
                found,
                KNOWN_SIGNED_EXTENSIONS
            );
        }
        Ok(())
    }
}

struct PalletView {
    name: String,
    index: u8,
    call_type: Option<u32>,
    constants: Vec<(String, Vec<u8>)>,
}

impl PalletView {
    fn constant(&self, name: &str) -> Result<&[u8]> {
        self.constants
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, value)| value.as_slice())
            .ok_or_else(|| anyhow!("`{}` declares no `{name}` constant", self.name))
    }

    fn decode_u32(&self, name: &str) -> Result<u32> {
        let value = self.constant(name)?;
        let bytes: [u8; 4] = value
            .try_into()
            .map_err(|_| anyhow!("`{name}` is {} bytes, expected 4", value.len()))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn decode_u64(&self, name: &str) -> Result<u64> {
        let value = self.constant(name)?;
        let bytes: [u8; 8] = value
            .try_into()
            .map_err(|_| anyhow!("`{name}` is {} bytes, expected 8", value.len()))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

/// The dispatch index of one call, read from the runtime's own call enum.
fn call_index(types: &PortableRegistry, call_type: u32, call: &str) -> Result<u8> {
    let ty = types
        .resolve(call_type)
        .ok_or_else(|| anyhow!("the metadata type registry has no type {call_type}"))?;
    let TypeDef::Variant(variants) = &ty.type_def else {
        bail!("the call type of `{SHIELDED_PALLET}` is not a variant");
    };
    variants
        .variants
        .iter()
        .find(|variant| variant.name == call)
        .map(|variant| variant.index)
        .ok_or_else(|| anyhow!("`{SHIELDED_PALLET}` has no `{call}` call"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A metadata blob captured from the M4 dev node, so the parse is covered
    /// without a running chain. Regenerate with
    /// `curl -s -H 'Content-Type: application/json' -d
    /// '{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":[]}'
    /// http://127.0.0.1:9944 | jq -r .result > tests/fixtures/metadata.hex`.
    fn fixture() -> Vec<u8> {
        let hex_blob = include_str!("../tests/fixtures/metadata.hex");
        decode_hex(hex_blob.trim()).expect("the fixture is hex")
    }

    #[test]
    fn the_dev_runtime_metadata_carries_the_shielded_pallet() {
        let md = ChainMetadata::parse(&fixture()).expect("the fixture parses");
        assert_eq!(md.shielded_pallet_index, 24);
        assert_eq!(md.submit_private_batch, 0);
        assert_eq!(md.submit_public_batch, 1);
        assert_eq!(md.shield, 2);
    }

    /// The four fee and anchor constants, as the M4 runtime sets them. This
    /// test is not the authority on their values: it pins that the wallet
    /// reads them out of the right place and decodes them at the right width,
    /// which is what silently produces an unprovable fee when it drifts.
    #[test]
    fn the_fee_constants_come_out_of_the_metadata() {
        let md = ChainMetadata::parse(&fixture()).expect("the fixture parses");
        assert_eq!(md.block_hash_window, 256);
        assert_eq!(md.min_leaf_fee, 1);
        assert_eq!(md.ciphertext_bytes_per_fee_quantum, 512);
        assert_eq!(md.max_ciphertext_bytes, 2048);
    }

    #[test]
    fn the_runtime_declares_the_transaction_extensions_this_wallet_encodes() {
        let md = ChainMetadata::parse(&fixture()).expect("the fixture parses");
        md.ensure_known_signed_extensions()
            .expect("the M4 runtime's extension list is the one the wallet lays out");
    }
}
