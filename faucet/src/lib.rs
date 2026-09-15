//! The Qnero testnet faucet.
//!
//! One shielded drip per address, behind two rate limits and an optional
//! Turnstile challenge, paid from the account the `qnero-testnet` preset
//! endows at genesis.
//!
//! The shape follows from one fact about the chain: under v1's mandatory
//! privacy there is no transparent transfer between accounts a user chooses,
//! so a faucet cannot send transparent QNR. The only payout it can make is a
//! shielded note, which is a private-batch proof: about 9.8 seconds and
//! roughly a gigabyte of working memory per drip, then up to one 120 s block
//! to settle (`docs/BENCH.md`). Every design decision here is downstream of
//! that: one prover built at startup, one worker thread that owns the wallet,
//! a bounded queue in front of it, and a claim that is answered `queued` and
//! polled rather than held open.

pub mod config;
pub mod http;
pub mod keys;
pub mod limits;
pub mod page;
pub mod ss58;
pub mod store;
pub mod turnstile;
pub mod worker;
