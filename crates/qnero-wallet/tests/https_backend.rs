//! This crate, built on its own, can speak https://.
//!
//! The documented build is `cargo build -p qnero-wallet`, and the public
//! testnet is reached over TLS: `https://rpc.<domain>` for the CLI, with
//! `wss://` left to the two browser apps (`docs/TESTNET.md`). A crate built on
//! its own resolves its own manifest, so the HTTP client's `tls` feature has
//! to be asked for in `Cargo.toml` here. Without it every command against the
//! deployed chain dies before a byte is written, with "cannot make HTTPS
//! request because no TLS backend is configured", and a whole-workspace build
//! hides it: the faucet asks for the same dependency with `tls` and Cargo
//! unifies the features across one build.
//!
//! What this asserts is the shape of the failure. Nothing here serves TLS, so
//! the call fails either way; the question is whether it failed on the wire or
//! was refused by a client that cannot dial an https:// URL at all.
//!
//! The listener is what makes that decidable. ureq opens the TCP connection
//! first and reaches for its TLS backend after, so a closed port fails at
//! connect in both builds and says nothing. A socket that accepts and hangs up
//! gets a build with TLS as far as a handshake, and a build without one no
//! further than the missing backend.

use std::net::TcpListener;

use qnero_wallet::rpc::RpcClient;
use serde_json::json;

/// The string ureq answers an https:// URL with when it was built with no TLS
/// backend.
const NO_BACKEND: &str = "no tls backend";

#[test]
fn an_https_node_is_dialled_and_not_refused_by_the_client() {
    // Accept one connection and close it. The handshake then ends in an
    // ordinary transport error in about the time the socket takes, so the
    // agent's 60 s read timeout is never reached.
    let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    let endpoint = listener.local_addr().expect("the bound address");
    // Left running. A build with no TLS backend never connects, so joining
    // this thread would wait on an accept that cannot happen.
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    let client = RpcClient::new(&format!("https://{endpoint}"));
    let error = client
        .call("system_health", json!([]))
        .expect_err("nothing on that socket serves TLS");
    let text = format!("{error:#}").to_lowercase();

    assert!(
        !text.contains(NO_BACKEND),
        "this crate was built without a TLS backend, so every https:// node is \
         unreachable from it: {text}"
    );
    assert!(
        !text.contains("scheme"),
        "the client refused the URL before dialling it: {text}"
    );
    assert!(
        text.contains(&format!("https://{endpoint}")),
        "the error names the endpoint it failed against: {text}"
    );
}

/// The other half of the shape: a port with nothing on it fails at the
/// connection, with no mention of a missing backend.
#[test]
fn an_unreachable_https_node_fails_at_the_connection() {
    let client = RpcClient::new("https://127.0.0.1:1");
    let error = client
        .call("system_health", json!([]))
        .expect_err("nothing listens on port 1");
    let text = format!("{error:#}").to_lowercase();

    assert!(!text.contains(NO_BACKEND), "{text}");
    assert!(
        text.contains("connect") || text.contains("refused") || text.contains("connection"),
        "a dead port reads as a connection failure: {text}"
    );
}
