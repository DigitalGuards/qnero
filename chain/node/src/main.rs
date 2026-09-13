//! Substrate Node Template CLI library.
#![warn(missing_docs)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod chain_spec;
mod cli;
mod coinbase;
mod command;
mod prometheus;
mod rpc;
mod service;
mod stratum;
#[cfg(test)]
mod tests;
mod txwatch;
mod zktree_rpc;

#[allow(clippy::result_large_err)]
fn main() -> sc_cli::Result<()> {
	command::run()
}
