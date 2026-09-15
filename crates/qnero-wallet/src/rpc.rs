//! The JSON-RPC client.
//!
//! Blocking HTTP. The node serves JSON-RPC over both HTTP and WebSocket on the
//! same port, and nothing this wallet does needs a subscription: inclusion is
//! polled, because an unsigned settlement drops out of the pool after five
//! blocks and has to be resubmitted, and waiting on it achieves nothing
//! (`docs/CIRCUIT.md` section 9.10).
//!
//! One request per call, except where a caller has a list of calls and no use
//! for the answers one at a time. [`RpcClient::call_many`] sends those as a
//! JSON-RPC batch array, which this chain's node accepts: a header walk is
//! latency bound, and 64 headers in one request is one round trip where 64
//! requests is 64. A node that does not take batch arrays is an ordinary
//! answer and not a refusal to be reported, so the first batch a process sends
//! is also the probe, and a node that does not take it gets one request per
//! call from then on.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// Default endpoint of a `--dev` node.
pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:9944";

/// Whether this node takes JSON-RPC batch arrays, as far as this process knows.
///
/// Asked once, by sending one. `Unknown` until the first batch goes out,
/// `Refused` after one comes back as anything but an array of answers, and
/// there is no way back to `Taken` inside a process: a node does not grow the
/// feature mid-command, and re-probing would pay the failed round trip again
/// on every page of a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchSupport {
    Unknown,
    Taken,
    Refused,
}

pub struct RpcClient {
    url: String,
    agent: ureq::Agent,
    next_id: std::cell::Cell<u64>,
    batches: std::cell::Cell<BatchSupport>,
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
            batches: std::cell::Cell::new(BatchSupport::Unknown),
        }
    }

    /// What this process has learned about batch arrays on this node.
    pub fn batch_support(&self) -> BatchSupport {
        self.batches.get()
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
        let parsed: Value = serde_json::from_str(&response).with_context(|| {
            // The body, not just "that is not JSON". A rate limiter, a proxy
            // error page and a captive portal all answer 200 with HTML, and a
            // wallet that only said the body was unreadable sent an operator
            // looking for a decoding bug in the wallet.
            format!(
                "{method} returned a body that is not JSON: {}",
                first_line_of(&response)
            )
        })?;
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

    /// Many calls in one JSON-RPC batch array, answered in the order given.
    ///
    /// The whole point is the round trip: a header walk over a thousand blocks
    /// is a thousand requests one after another otherwise, and against a node
    /// behind a CDN the wide-area round trip is the entire cost. Sixty-four
    /// calls in one array is one of them.
    ///
    /// A node that will not take an array is answered around rather than
    /// refused: this falls back to one request per call and records that, so
    /// the rest of the command does not pay a failed batch per page. What is
    /// **not** a refusal to batch is an error inside a batch that came back as
    /// an array: that is the node answering one of the calls, and it is
    /// returned as an error the way a single call's would be.
    ///
    /// The answers are matched to the calls by JSON-RPC id, because a batch
    /// answer may arrive in any order and this chain's node does reorder them.
    pub fn call_many(&self, calls: &[(&str, Value)]) -> Result<Vec<Value>> {
        if calls.is_empty() {
            return Ok(Vec::new());
        }
        if calls.len() == 1 {
            let (method, params) = &calls[0];
            return Ok(vec![self.call(method, params.clone())?]);
        }
        if self.batches.get() != BatchSupport::Refused {
            match self.try_batch(calls) {
                Ok(Some(values)) => {
                    self.batches.set(BatchSupport::Taken);
                    return Ok(values);
                }
                Ok(None) => self.batches.set(BatchSupport::Refused),
                Err(error) => return Err(error),
            }
        }
        calls
            .iter()
            .map(|(method, params)| self.call(method, params.clone()))
            .collect()
    }

    /// One batch attempt. `Ok(None)` is a node that does not take batches.
    fn try_batch(&self, calls: &[(&str, Value)]) -> Result<Option<Vec<Value>>> {
        let first = self.next_id.get();
        self.next_id.set(first + calls.len() as u64);
        let body = Value::Array(
            calls
                .iter()
                .enumerate()
                .map(|(offset, (method, params))| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": first + offset as u64,
                        "method": method,
                        "params": params,
                    })
                })
                .collect(),
        );
        let response = match self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(response) => response,
            // A status this client will not read, which is what a front end
            // that rejects an array body answers with. The caller is about to
            // make the same calls one at a time, so an endpoint that is simply
            // unreachable fails there with its own message.
            Err(_) => return Ok(None),
        };
        let text = match response.into_string() {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };
        let parsed: Value = match serde_json::from_str(&text) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(None),
        };
        let Some(answers) = parsed.as_array() else {
            return Ok(None);
        };
        if answers.len() != calls.len() {
            return Ok(None);
        }
        let mut by_id: std::collections::HashMap<u64, &Value> = std::collections::HashMap::new();
        for answer in answers {
            let Some(id) = answer.get("id").and_then(Value::as_u64) else {
                return Ok(None);
            };
            by_id.insert(id, answer);
        }
        let mut out = Vec::with_capacity(calls.len());
        for (offset, (method, _)) in calls.iter().enumerate() {
            let Some(answer) = by_id.get(&(first + offset as u64)) else {
                return Ok(None);
            };
            if let Some(error) = answer.get("error") {
                bail!("{method} returned an RPC error: {error}");
            }
            out.push(
                answer
                    .get("result")
                    .cloned()
                    .ok_or_else(|| anyhow!("{method} returned no result field"))?,
            );
        }
        Ok(Some(out))
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

/// The start of a body, on one line, for an error message.
///
/// Bounded and flattened on purpose: this goes into an error somebody reads.
/// An HTML error page's first line is `<html>`, which says nothing, and its
/// title two lines later says everything, so the whole head of the body is
/// taken with its line breaks turned into spaces.
fn first_line_of(body: &str) -> String {
    let flattened = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return "an empty body".to_string();
    }
    let mut short: String = flattened.chars().take(160).collect();
    if flattened.chars().count() > 160 {
        short.push('…');
    }
    short
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
