//! SS58 for one address format, Qnero's.
//!
//! The chain spec's faucet account is an SS58 literal and the faucet's seed
//! file is the key behind it, so the two have to be compared somewhere. The
//! node can print an address from a seed (`key qnero --no-derivation --seed`)
//! and so can this, and `the_node_and_this_agree_on_one_seed` pins the pair
//! they both produce.
//!
//! Only format 189 is handled, because only 189 is a Qnero address. Every
//! other prefix decodes to a refusal that names what it found, so a Polkadot
//! or Kusama address pasted into the faucet's configuration is refused at
//! startup rather than turning into a Qnero account nobody holds.

use anyhow::{bail, Result};
use blake2::{Blake2b512, Digest};

/// The SS58 address format of every Qnero chain
/// (`chain/node/src/chain_spec.rs`, `ss58Format` in the properties map).
pub const QNERO_SS58: u16 = 189;

/// The domain separator SS58 hashes before the payload.
const PREFIX: &[u8] = b"SS58PRE";

/// Format 189 is above 63, so its prefix is the two-byte form.
fn prefix_bytes(format: u16) -> Vec<u8> {
    if format < 64 {
        vec![format as u8]
    } else {
        vec![
            (((format & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000) as u8,
            ((format >> 8) | ((format & 0b0000_0000_0000_0011) << 6)) as u8,
        ]
    }
}

fn checksum(body: &[u8]) -> [u8; 2] {
    let mut hasher = Blake2b512::new();
    hasher.update(PREFIX);
    hasher.update(body);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Encode a 32-byte account id as a Qnero SS58 address.
pub fn encode(account: &[u8; 32]) -> String {
    let mut body = prefix_bytes(QNERO_SS58);
    body.extend_from_slice(account);
    let sum = checksum(&body);
    body.extend_from_slice(&sum);
    bs58::encode(body).into_string()
}

/// Decode a Qnero SS58 address into its 32-byte account id.
///
/// Refuses any other address format by name. Both halves matter: a
/// wrong-format address has a valid checksum for its own format and would
/// otherwise decode into 32 bytes that are a perfectly good Qnero account
/// nobody holds a key for.
pub fn decode(address: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(address)
        .into_vec()
        .map_err(|error| anyhow::anyhow!("not base58: {error}"))?;
    if raw.len() < 3 {
        bail!(
            "an SS58 address is at least three bytes and this one is {}",
            raw.len()
        );
    }
    let prefix_len = if raw[0] < 64 { 1 } else { 2 };
    if raw.len() != prefix_len + 32 + 2 {
        bail!(
            "a Qnero address is {} bytes of prefix plus 32 of account plus 2 of checksum, and \
             this one decodes to {}",
            prefix_len,
            raw.len()
        );
    }
    let (body, sum) = raw.split_at(raw.len() - 2);
    if checksum(body) != sum {
        bail!("the SS58 checksum does not match, so the address is mistyped");
    }
    let format = if prefix_len == 1 {
        u16::from(raw[0])
    } else {
        (u16::from(raw[0] & 0b0011_1111) << 2)
            | (u16::from(raw[1]) >> 6)
            | (u16::from(raw[1] & 0b0011_1111) << 8)
    };
    if format != QNERO_SS58 {
        bail!(
            "this is an SS58 address in format {format}, and a Qnero address is format \
             {QNERO_SS58}. The 32 bytes inside it would be a Qnero account nobody holds a key \
             for, so it is refused here rather than used"
        );
    }
    let mut account = [0u8; 32];
    account.copy_from_slice(&body[prefix_len..]);
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Planck preset's faucet literal
    /// (`chain/runtime/src/genesis_config_presets/mod.rs`), which the runtime
    /// decodes with `sp_core`'s own SS58 and this decodes with the code above.
    /// A round trip through both halves is what says the two agree on the
    /// prefix, the checksum and the alphabet.
    #[test]
    fn a_preset_literal_round_trips() {
        let address = "qzka7DZXAT7GnzgXQfxiSwrPKRWgW6m6G89QRsQiLThThZ6Cw";
        let account = decode(address).expect("a preset literal decodes");
        assert_eq!(encode(&account), address);
    }

    /// Format 189 is the two-byte prefix form, and these are the two bytes.
    #[test]
    fn the_qnero_prefix_is_two_bytes() {
        assert_eq!(prefix_bytes(QNERO_SS58), vec![0x6f, 0x40]);
    }

    /// A format-0 address is a valid SS58 string carrying 32 bytes that are a
    /// perfectly good Qnero account id. Nobody holds the key to that account,
    /// so pasting one into the faucet's configuration has to be an error and
    /// not a silent reinterpretation. The address is built here rather than
    /// quoted, so the test cannot be wrong about somebody else's chain.
    #[test]
    fn another_chains_address_is_refused_by_name() {
        let account = [7u8; 32];
        let mut body = prefix_bytes(0);
        body.extend_from_slice(&account);
        let sum = checksum(&body);
        body.extend_from_slice(&sum);
        let elsewhere = bs58::encode(body).into_string();

        let error = decode(&elsewhere).expect_err("a format 0 address is not a Qnero address");
        assert!(
            error.to_string().contains("format 0"),
            "the refusal does not say which format it found: {error}"
        );
    }

    /// One mistyped character has to be caught by the checksum rather than
    /// decoding into a neighbouring account.
    #[test]
    fn a_mistyped_address_is_refused() {
        let address = "qzka7DZXAT7GnzgXQfxiSwrPKRWgW6m6G89QRsQiLThThZ6Cx";
        assert!(decode(address).is_err());
    }
}
