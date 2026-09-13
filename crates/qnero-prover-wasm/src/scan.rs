//! The two things a browser wallet does that are not proving: derive its
//! identity, and read a ciphertext off the chain.
//!
//! Both are here rather than in the `wasm-bindgen` layer so they are reachable
//! from a native test. The layer above is a one-line adapter per function, and
//! a `JsError` cannot be constructed on a native target at all.

use anyhow::Result;
use qnero_notes::{decrypt_note, try_receive, NoteCiphertext};
use serde_json::json;

use crate::request::{digest_from_hex, spending_key_from_hex};

/// The public half of a key tree, as JSON.
///
/// `ask` and `nk` are not in it and never cross the boundary: they are the
/// spend credential, and the witness that needs them is built from the seed
/// inside this module.
pub fn derive_account_json(seed_hex: &str) -> Result<String> {
    let key = spending_key_from_hex(seed_hex)?;
    Ok(json!({
        "address": key.address().encode(),
        "pk": key.pk().to_hex(),
        "ak": key.ak().to_hex(),
        "cvk": key.cvk().to_hex(),
    })
    .to_string())
}

/// One scan step.
///
/// `expected_commitment_hex` is the commitment the chain published beside the
/// ciphertext. With it, a plaintext that opens a different commitment is
/// rejected, which is what makes a malformed output visible; with an empty
/// string the ciphertext is decrypted and not checked, which is what a wallet
/// does for a ciphertext it has not yet located in the tree.
pub fn decrypt_note_json(
    seed_hex: &str,
    ciphertext: &[u8],
    expected_commitment_hex: &str,
) -> Result<String> {
    let key = spending_key_from_hex(seed_hex)?;
    let ivk = key.incoming_viewing_key();
    let ct = NoteCiphertext::from_bytes(ciphertext)
        .map_err(|_| anyhow::anyhow!("the ciphertext does not parse"))?;

    let expected = expected_commitment_hex.trim();
    let received = if expected.is_empty() {
        decrypt_note(&ivk, &ct)
    } else {
        try_receive(
            &ivk,
            &ct,
            &digest_from_hex("expected_commitment", expected)?,
        )
    }
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    Ok(json!({
        "value": received.note.value,
        "rho": received.note.rho.to_hex(),
        "r": received.note.r.to_hex(),
        "commitment": received.commitment.to_hex(),
        "memo": String::from_utf8_lossy(qnero_notes::unpad_memo(&received.memo)),
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_publishes_no_spend_credential() {
        let json = derive_account_json(&"07".repeat(32)).unwrap();
        let account: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(account["address"].as_str().unwrap().starts_with("qn1"));
        assert!(account.get("ask").is_none());
        assert!(account.get("nk").is_none());
        assert!(!json.contains(&"07".repeat(32)));
    }

    /// A ciphertext for somebody else is refused, and the refusal says nothing
    /// about what was inside it.
    #[test]
    fn a_ciphertext_for_another_key_does_not_decrypt() {
        let json =
            crate::fixture::synthetic_transfer_request(&"08".repeat(32), &"09".repeat(32), 2)
                .unwrap();
        let request: crate::request::TransferRequest = serde_json::from_str(&json).unwrap();
        let prepared = request.prepare().unwrap();
        let outputs = prepared.encrypt_outputs().unwrap();

        let mine = decrypt_note_json(&"09".repeat(32), &outputs[0].ciphertext, "").unwrap();
        assert!(mine.contains("\"value\":900"));

        let theirs = decrypt_note_json(&"0a".repeat(32), &outputs[0].ciphertext, "");
        assert!(theirs.is_err());
    }
}
