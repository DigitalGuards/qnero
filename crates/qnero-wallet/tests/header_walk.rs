//! The header walk, pipelined, and what it still refuses.
//!
//! The walk used to descend by `parentHash`, one `chain_getHeader` at a time,
//! each header fetched by the hash its child named. That is one round trip per
//! block with nothing else in flight, and against a node behind a CDN the
//! round trip is the whole cost: at the public chain's 120 s target a year of
//! history is 262 000 of them in series.
//!
//! It is two pipelined halves now. The heights become hashes through one
//! `chain_getBlockHash` per page of numbers, and the headers are fetched by
//! hash in JSON-RPC batch arrays. Neither half is trusted on its own, and the
//! tests here are about that: a header answered for a height that is not its
//! own is refused, a hash answered for a number the header chain does not
//! carry is refused, and a node that takes neither a batch array nor a list of
//! numbers is answered around rather than refused, because that is an older
//! implementation and not a lie. A request that did not complete is neither of
//! those and is reported: a rate limit read as "this node takes no batches"
//! puts the rest of the sync on sixty-four times the requests.
//!
//! `docs/WALLET.md` carries the bound the walk delivers and the one it does
//! not: no proof of work is verified here and none was before.

mod support;

use qnero_wallet::chain::{Chain, ChainHead, ListSupport};
use qnero_wallet::rpc::{BatchSupport, RpcClient};

use support::{FakeNode, NodeState};

/// A node with a head and nothing else: the walk reads headers alone.
fn chain_of(head: u32) -> NodeState {
    NodeState {
        head_number: head,
        ..Default::default()
    }
}

fn head_of(chain: &Chain, number: u32) -> ChainHead {
    ChainHead {
        number,
        hash: chain.block_hash(number).expect("a hash at the head"),
    }
}

#[test]
fn a_walk_builds_one_ascending_chain_out_of_answers_that_arrive_in_another_order() {
    // The fake node answers a batch array in reverse, because a real one may
    // answer in any order and the wallet matches answers to calls by JSON-RPC
    // id rather than by position.
    let node = FakeNode::start(chain_of(300));
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 300);
    // The head's own hash was read to build it, so the walk's own requests are
    // counted from here.
    let (hash_calls, trips) = {
        let state = node.state();
        (state.calls("chain_getBlockHash"), state.round_trips())
    };

    let blocks = chain.header_chain(&head, 0).expect("an honest chain walks");

    assert_eq!(blocks.len(), 301);
    for (offset, block) in blocks.iter().enumerate() {
        assert_eq!(block.number, offset as u32);
    }
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].parent_hash, pair[0].hash);
    }
    assert_eq!(blocks[300].hash, head.hash);
    assert_eq!(rpc.batch_support(), BatchSupport::Taken);

    let state = node.state();
    // 300 heights below the top, paged at 256, and the top's own hash is the
    // caller's: two calls rather than three hundred. The headers are 301
    // calls in five batch arrays, so the walk is seven round trips where the
    // descending walk was 301.
    assert_eq!(state.calls("chain_getBlockHash") - hash_calls, 2);
    assert_eq!(state.calls("chain_getHeader"), 301);
    assert!(
        state.round_trips() - trips <= 8,
        "a 301-block walk took {} requests",
        state.round_trips() - trips
    );
}

#[test]
fn a_node_that_refuses_batch_arrays_gets_one_request_per_call() {
    let mut state = chain_of(120);
    state.refuse_batches = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 120);

    let blocks = chain
        .header_chain(&head, 0)
        .expect("a node without batches still serves a walk");

    assert_eq!(blocks.len(), 121);
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].parent_hash, pair[0].hash);
    }
    assert_eq!(rpc.batch_support(), BatchSupport::Refused);
    let state = node.state();
    // One request per header, plus the one refused batch array that found the
    // node out, which the request log counts as well. What this is not is a
    // refusal: the answers are the same answers and the chain is the same
    // chain.
    assert!(
        state.round_trips() >= 121,
        "the fallback made {} requests",
        state.round_trips()
    );
    assert!(
        state.round_trips() <= 130,
        "the fallback probed for batches more than once: {} requests",
        state.round_trips()
    );
}

#[test]
fn a_node_that_answers_one_hash_for_a_list_is_asked_one_height_at_a_time() {
    let mut state = chain_of(40);
    state.refuse_hash_lists = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 40);

    let blocks = chain
        .header_chain(&head, 0)
        .expect("a node without list answers still serves a walk");

    assert_eq!(blocks.len(), 41);
    let state = node.state();
    // The list attempt, then one call per height it could not read as a list.
    // The head's own hash was read before the walk, by `head_of`.
    assert!(
        state.calls("chain_getBlockHash") >= 41,
        "the fallback made {} hash calls",
        state.calls("chain_getBlockHash")
    );
}

#[test]
fn a_node_that_answers_a_list_with_an_rpc_error_is_asked_one_height_at_a_time() {
    // The likelier shape of the same older node: an implementation whose
    // `chain_getBlockHash` parameter is one number rather than Substrate's
    // list-or-value fails to deserialize an array and answers `Invalid
    // params`. A wallet that read that as a refusal would refuse every walk
    // against such a node instead of asking the way it can answer.
    let mut state = chain_of(40);
    state.error_hash_lists = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 40);

    let blocks = chain
        .header_chain(&head, 0)
        .expect("a node that will not take a list still serves a walk");

    assert_eq!(blocks.len(), 41);
    for pair in blocks.windows(2) {
        assert_eq!(pair[1].parent_hash, pair[0].hash);
    }
    assert_eq!(chain.list_support(), ListSupport::Refused);
}

#[test]
fn a_node_that_will_not_answer_a_list_is_probed_once_and_not_once_per_page() {
    // The heights are paged at `HASH_PAGE`, so a walk over three pages asked
    // three times and threw two of the answers away. The answer is remembered
    // for the command, the way `RpcClient` remembers a node that will not take
    // batch arrays.
    let mut state = chain_of(600);
    state.refuse_hash_lists = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 600);

    let blocks = chain.header_chain(&head, 0).expect("a walk");
    assert_eq!(blocks.len(), 601);

    let state = node.state();
    let lists = state
        .requests
        .iter()
        .filter(|body| {
            body.contains("\"method\":\"chain_getBlockHash\"") && body.contains("\"params\":[[")
        })
        .count();
    assert_eq!(lists, 1, "the walk probed the list form {lists} times");
}

#[test]
fn a_rate_limited_batch_is_an_error_and_leaves_batching_alone() {
    // A 429 is the endpoint refusing for now and says nothing about batch
    // arrays. Latching "no batches" on it would send the next 1024-block
    // chunk as 1025 single requests into the limiter that had just refused
    // one, which is the request pattern that endpoint refuses.
    let mut state = chain_of(200);
    state.rate_limited_batches = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 200);

    let refused = chain
        .header_chain(&head, 0)
        .expect_err("a rate-limited walk is reported rather than worked around");
    let message = format!("{refused:#}");
    assert!(message.contains("HTTP 429"), "{message}");
    // The body, so the operator reads the node's own words rather than a
    // decoding complaint from the wallet.
    assert!(message.contains("429 Too Many Requests"), "{message}");
    assert_eq!(rpc.batch_support(), BatchSupport::Unknown);

    // And the next attempt still sends a batch array, because nothing was
    // learned about batching.
    node.state().rate_limited_batches = false;
    let blocks = chain
        .header_chain(&head, 0)
        .expect("the walk goes through once the limiter lets it");
    assert_eq!(blocks.len(), 201);
    assert_eq!(rpc.batch_support(), BatchSupport::Taken);
}

#[test]
fn a_header_answered_for_a_height_that_is_not_its_own_refuses_the_walk() {
    let mut state = chain_of(20);
    // A real header, hashing to its own name, carrying a number that is not
    // the height it was answered for.
    state.renumbered_headers.insert(7, 9);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 20);

    let refused = chain
        .header_chain(&head, 0)
        .expect_err("a header numbered for another height is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("numbered 9"), "{message}");
    assert!(message.contains("block 7"), "{message}");
}

#[test]
fn a_hash_the_header_chain_does_not_carry_refuses_the_walk() {
    let mut state = chain_of(20);
    // Block 11 is built naming a parent that is not block 10. It hashes to
    // its own name and carries its own number, so every check but the parent
    // link passes: it is a block out of a second chain spliced into this one,
    // which is the lie a walk that fetches by height has to catch for itself.
    state.spliced_parents.insert(11);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 20);

    let refused = chain
        .header_chain(&head, 0)
        .expect_err("a spliced parent link is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("as its parent"), "{message}");
    assert!(message.contains("block 11"), "{message}");
}

#[test]
fn a_walk_longer_than_one_chunk_is_refused_before_anything_is_asked_for() {
    let node = FakeNode::start(chain_of(2000));
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let head = head_of(&chain, 2000);
    let before = node.state().round_trips();

    let refused = chain
        .header_chain(&head, 0)
        .expect_err("a span over the chunk is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("at most 1024"), "{message}");
    assert_eq!(
        node.state().round_trips(),
        before,
        "the refusal asked the node for nothing"
    );
}
