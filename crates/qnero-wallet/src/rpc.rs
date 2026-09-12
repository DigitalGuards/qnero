//! The JSON-RPC client.
//!
//! Blocking HTTP, one request per call. The node serves JSON-RPC over both
//! HTTP and WebSocket on the same port, and nothing this wallet does needs a
//! subscription: inclusion is polled, because an unsigned settlement drops out
//! of the pool after five blocks and has to be resubmitted, and waiting on it
//! achieves nothing (`docs/CIRCUIT.md` section 9.10).

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// Default endpoint of a `--dev` node.
pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:9944";

pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
    next_id: std::cell::Cell<u64>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient").field("url", &self.url).finish()
    }
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build();
        Self {
            url: url.to_string(),
            agent,
            next_id: std::cell::Cell::new(1),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// One JSON-RPC call. A node-side error comes back as an error.
    /// `zkTree_getMerkleProof` answers `null` for a leaf that is not folded
    /// into the tree yet, and that has to stay distinguishable from a node
    /// that is unwell, so the two reach the caller as different shapes.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let response = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| anyhow!("{method} failed against {}: {e}", self.url))?
            .into_string()
            .with_context(|| format!("{method} returned a body that is not UTF-8"))?;
        let parsed: Value = serde_json::from_str(&response)
            .with_context(|| format!("{method} returned a body that is not JSON"))?;
        if let Some(error) = parsed.get("error") {
            bail!("{method} returned an RPC error: {error}");
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method} returned no result field"))
    }

    pub fn call_as<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let result = self.call(method, params)?;
        serde_json::from_value(result)
            .with_context(|| format!("{method} returned a result this wallet cannot read"))
    }

    /// `state_getStorage`, decoded from `0x`-hex. `None` is an absent key.
    pub fn storage(&self, key: &[u8], at: Option<&str>) -> Result<Option<Vec<u8>>> {
        let params = match at {
            Some(hash) => json!([hex_0x(key), hash]),
            None => json!([hex_0x(key)]),
        };
        let value = self.call("state_getStorage", params)?;
        match value {
            Value::Null => Ok(None),
            Value::String(s) => Ok(Some(decode_hex(&s)?)),
            other => bail!("state_getStorage returned {other}"),
        }
    }

    /// `state_queryStorageAt` over many keys at one block. Returns the values
    /// in the order the keys were given, `None` for an absent key.
    ///
    /// Batched because a scan reads two keys per leaf and a chain that has run
    /// for a day has tens of thousands of them.
    pub fn storage_batch(&self, keys: &[Vec<u8>], at: &str) -> Result<Vec<Option<Vec<u8>>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let hex_keys: Vec<String> = keys.iter().map(|key| hex_0x(key)).collect();
        let result = self.call("state_queryStorageAt", json!([hex_keys, at]))?;
        let blocks = result
            .as_array()
            .ok_or_else(|| anyhow!("state_queryStorageAt returned a non-array"))?;
        let mut values: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        for block in blocks {
            let changes = block
                .get("changes")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("state_queryStorageAt returned a block with no changes"))?;
            for change in changes {
                let pair = change
                    .as_array()
                    .ok_or_else(|| anyhow!("a storage change is not a [key, value] pair"))?;
                let (Some(Value::String(key)), Some(value)) = (pair.first(), pair.get(1)) else {
                    bail!("a storage change is not a [key, value] pair");
                };
                if let Value::String(encoded) = value {
                    values.insert(key.clone(), decode_hex(encoded)?);
                }
            }
        }
        Ok(hex_keys
            .iter()
            .map(|key| values.get(key).cloned())
            .collect())
    }
}

pub fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).with_context(|| format!("{value} is not hex"))
}

/// A `0x`-prefixed 32-byte hash from JSON.
pub fn decode_hash(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{value} is not 32 bytes"))
}

/// Substrate encodes block numbers as `0x`-prefixed hex strings in JSON.
pub fn decode_u32_hex(value: &str) -> Result<u32> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    u32::from_str_radix(trimmed, 16).with_context(|| format!("{value} is not a hex number"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(decode_hex("0x0102").unwrap(), vec![1, 2]);
        assert_eq!(decode_hex("0102").unwrap(), vec![1, 2]);
        assert_eq!(hex_0x(&[0xab, 0xcd]), "0xabcd");
    }

    #[test]
    fn block_numbers_decode_from_hex_strings() {
        assert_eq!(decode_u32_hex("0x12").unwrap(), 18);
        assert_eq!(decode_u32_hex("0x0").unwrap(), 0);
    }
}
