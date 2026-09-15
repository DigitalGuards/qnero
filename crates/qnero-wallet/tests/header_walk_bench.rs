//! The header walk, before and after, over the same node.
//!
//! Ignored, because one half of it is deliberately slow and the other half
//! wants a node:
//!
//! ```text
//! nice -n 19 cargo test -j 2 --release -p qnero-wallet \
//!   --test header_walk_bench -- --ignored --nocapture
//! ```
//!
//! With no `QNERO_BENCH_NODE` it builds the three-chunk fixture on loopback,
//! which is `3 * HEADER_WALK_LIMIT` blocks, and measures both walks against
//! it. Loopback is the fast case and it is the one that isolates the request
//! count from the round trip. With `QNERO_BENCH_NODE` pointed at a real
//! endpoint it measures the same two walks against that, which is where the
//! round trip is the whole cost.
//!
//! The sequential walk below is the old implementation, kept here verbatim so
//! the two are measured against one node in one process rather than compared
//! across two builds. Both are asserted to produce the same chain, which is
//! the claim the pipelining rests on.

mod support;

use std::time::{Duration, Instant};

use anyhow::Result;
use qnero_wallet::chain::{Chain, ChainHead};
use qnero_wallet::rpc::RpcClient;

use support::{FakeNode, NodeState};

/// The walk as it was: one `chain_getHeader` at a time, downward by
/// `parentHash`, each header fetched by the hash its child named.
fn sequential_walk(chain: &Chain, head: &ChainHead, anchor: u32, walked: &mut usize) -> Result<()> {
    let mut hash = head.hash;
    let mut number = head.number;
    loop {
        let raw = chain.header_at(&hash)?;
        let claimed = raw.block_number()?;
        assert_eq!(
            claimed, number,
            "the node answered a header for another height"
        );
        let header = raw.to_header_inputs()?;
        assert_eq!(
            header.block_hash().to_bytes(),
            hash,
            "a header did not hash to its own name"
        );
        *walked += 1;
        if number == anchor {
            break;
        }
        hash = qnero_wallet::rpc::decode_hash(&raw.parent_hash)?;
        number -= 1;
    }
    Ok(())
}

fn rate(blocks: u32, elapsed: Duration) -> f64 {
    f64::from(blocks + 1) / elapsed.as_secs_f64().max(f64::MIN_POSITIVE)
}

#[test]
#[ignore = "a measurement, not an assertion: run with --ignored --nocapture"]
fn the_header_walk_before_and_after() {
    let external = std::env::var("QNERO_BENCH_NODE").ok();
    let held;
    let url = match external.as_deref() {
        Some(url) => url.to_string(),
        None => {
            let head = qnero_wallet::wallet::HEADER_WALK_LIMIT * 3;
            held = FakeNode::start(NodeState {
                head_number: head,
                ..Default::default()
            });
            held.url.clone()
        }
    };
    let rpc = RpcClient::new(&url);
    let chain = Chain::new(&rpc);
    let head = chain.head().expect("a head");
    println!("node {url} at block {}", head.number);

    // The walk is bounded at one chunk per call, so a longer range is climbed
    // the way `Wallet::sync_with` climbs it.
    let chunks: Vec<(u32, u32)> = {
        let mut out = Vec::new();
        let mut bottom = 0u32;
        while bottom < head.number {
            let top = (bottom + qnero_wallet::wallet::HEADER_WALK_LIMIT).min(head.number);
            out.push((bottom, top));
            bottom = top;
        }
        if out.is_empty() {
            out.push((0, head.number));
        }
        out
    };

    // `QNERO_BENCH_ONLY` runs one of the two walks and skips the other, which
    // is what a rate-limited endpoint needs: both walks want one answer per
    // block, the endpoint allows about a hundred requests a window, and a run
    // that did both would measure the second one against a window the first
    // had already spent.
    let only = std::env::var("QNERO_BENCH_ONLY").unwrap_or_default();
    let run_pipelined = only != "sequential";
    let run_sequential = only != "pipelined";

    let mut pipelined = Vec::new();
    let started = Instant::now();
    for (bottom, top) in chunks.iter().filter(|_| run_pipelined) {
        let chunk_head = ChainHead {
            number: *top,
            hash: chain.block_hash(*top).expect("a hash at the chunk top"),
        };
        let chunk = chain
            .header_chain(&chunk_head, *bottom)
            .expect("the pipelined walk");
        // Each chunk re-fetches the block it stands on, which is the block
        // that proves it, so the boundary is dropped when the chunks are
        // joined back into one chain.
        let skip = usize::from(!pipelined.is_empty());
        pipelined.extend(chunk.into_iter().skip(skip));
    }
    let after = started.elapsed();
    if run_pipelined {
        println!(
            "pipelined  {} headers in {:.2} s, {:.0} headers/s",
            head.number + 1,
            after.as_secs_f64(),
            rate(head.number, after)
        );
    }

    let started = Instant::now();
    let mut sequential_failed = None;
    let mut walked = 0usize;
    for (bottom, top) in chunks.iter().filter(|_| run_sequential) {
        let chunk_head = ChainHead {
            number: *top,
            hash: chain.block_hash(*top).expect("a hash at the chunk top"),
        };
        if let Err(error) = sequential_walk(&chain, &chunk_head, *bottom, &mut walked) {
            sequential_failed = Some(format!("{error:#}"));
            break;
        }
    }
    let before = started.elapsed();
    match sequential_failed.filter(|_| run_sequential) {
        Some(error) => println!(
            "sequential gave up after {walked} headers in {:.2} s, {:.0} headers/s: {error}",
            before.as_secs_f64(),
            walked as f64 / before.as_secs_f64().max(f64::MIN_POSITIVE)
        ),
        None if run_sequential => println!(
            "sequential {} headers in {:.2} s, {:.0} headers/s",
            walked,
            before.as_secs_f64(),
            walked as f64 / before.as_secs_f64().max(f64::MIN_POSITIVE)
        ),
        None => {}
    }

    // The two walks build the same chain, which is the whole claim.
    if run_pipelined {
        for pair in pipelined.windows(2) {
            assert_eq!(pair[1].parent_hash, pair[0].hash);
        }
        assert_eq!(pipelined.last().expect("a top").hash, head.hash);
    }
}
