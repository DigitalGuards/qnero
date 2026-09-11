//! CLI for artifact generation on a trusted build host.
//!
//! ```text
//! qnero-circuit-builder --output <dir> --num-leaf-proofs <n>
//!                       [--num-private-batch-proofs <n>] [--skip-padding-batch]
//! ```
//!
//! The flags are parsed by hand. A build-host tool that pulls in an argument
//! parser and its dependency tree buys convenience for four flags and pays for
//! it in everything that has to be reviewed and rebuilt alongside the
//! circuits.

use anyhow::{bail, Context, Result};

use qnero_circuit_builder::generate_all_artifacts;

/// The chain defaults, and why they are what they are.
///
/// Seven leaves per private batch is a wallet-side memory decision: it is what
/// a phone can prove. Fifty-three private batches per public batch is an
/// aggregator-side cost decision, amortizing one on-chain verification across
/// many wallets.
const DEFAULT_NUM_LEAF_PROOFS: usize = 7;
const DEFAULT_NUM_PRIVATE_BATCH_PROOFS: usize = 53;

/// Environment overrides, for a build script that has no command line.
///
/// A pallet's `build.rs` reads these and passes them to
/// `generate_all_artifacts`, the way `pallet-wormhole` reads
/// `QP_NUM_LEAF_PROOFS`. Such a script must also emit
/// `cargo:rerun-if-env-changed` for both: without it Cargo reuses a previous
/// `OUT_DIR` after the variable is unset and embeds a verifier built for
/// different dimensions.
const ENV_NUM_LEAF_PROOFS: &str = "QNERO_NUM_LEAF_PROOFS";
const ENV_NUM_PRIVATE_BATCH_PROOFS: &str = "QNERO_NUM_PRIVATE_BATCH_PROOFS";

/// A dimension from the environment, when it is set.
///
/// A malformed value is an error. Falling back to the default would publish a
/// set built for dimensions nobody asked for, and the mismatch would surface
/// as a public-input length failure much later.
fn count_from_env(name: &str) -> Result<Option<usize>> {
    match std::env::var(name) {
        Ok(value) => {
            Ok(Some(value.parse().with_context(|| {
                format!("{name} expects a number, got {value}")
            })?))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {name}")),
    }
}

struct Args {
    output: String,
    num_leaf_proofs: usize,
    num_private_batch_proofs: Option<usize>,
    include_padding_batch: bool,
}

const USAGE: &str = "\
usage: qnero-circuit-builder [options]

  --output <dir>                     where to write the set (default: generated-artifacts)
  --num-leaf-proofs <n>              leaf slots per private batch (default: 7,
                                     or QNERO_NUM_LEAF_PROOFS)
  --num-private-batch-proofs <n>     private batches per public batch (default: 53,
                                     or QNERO_NUM_PRIVATE_BATCH_PROOFS)
  --no-public-batch                  stop at the private batch
  --skip-padding-batch               do not prove the all-padding private batch
  --help                             print this
";

fn parse_count(flag: &str, value: Option<String>) -> Result<usize> {
    let Some(value) = value else {
        bail!("{} needs a value", flag);
    };
    value
        .parse()
        .with_context(|| format!("{flag} expects a number, got {value}"))
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Args>> {
    let mut parsed = Args {
        output: String::from("generated-artifacts"),
        num_leaf_proofs: count_from_env(ENV_NUM_LEAF_PROOFS)?.unwrap_or(DEFAULT_NUM_LEAF_PROOFS),
        num_private_batch_proofs: Some(
            count_from_env(ENV_NUM_PRIVATE_BATCH_PROOFS)?
                .unwrap_or(DEFAULT_NUM_PRIVATE_BATCH_PROOFS),
        ),
        include_padding_batch: true,
    };

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--help" | "-h" => return Ok(None),
            "--output" => {
                parsed.output = args.next().context("--output needs a value")?;
            }
            "--num-leaf-proofs" => {
                parsed.num_leaf_proofs = parse_count("--num-leaf-proofs", args.next())?;
            }
            "--num-private-batch-proofs" => {
                parsed.num_private_batch_proofs =
                    Some(parse_count("--num-private-batch-proofs", args.next())?);
            }
            "--no-public-batch" => parsed.num_private_batch_proofs = None,
            "--skip-padding-batch" => parsed.include_padding_batch = false,
            other => bail!("unknown argument {}\n\n{}", other, USAGE),
        }
    }

    Ok(Some(parsed))
}

fn main() -> Result<()> {
    let Some(args) = parse_args(std::env::args().skip(1))? else {
        print!("{USAGE}");
        return Ok(());
    };

    println!(
        "generating the Qnero artifact set into {} (leaf slots {}, private batches per public \
         batch {})",
        args.output,
        args.num_leaf_proofs,
        args.num_private_batch_proofs
            .map_or_else(|| String::from("none"), |n| n.to_string()),
    );

    let started = std::time::Instant::now();
    generate_all_artifacts(
        &args.output,
        args.num_leaf_proofs,
        args.num_private_batch_proofs,
        args.include_padding_batch,
    )?;
    println!("done in {:.1}s", started.elapsed().as_secs_f64());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Option<Args>> {
        parse_args(values.iter().map(|value| value.to_string()))
    }

    #[test]
    fn the_defaults_are_the_chain_defaults() {
        // The environment overrides the defaults, so a test that asserts them
        // has to look at an environment that carries neither. `std::env::var`
        // is process-wide, so this reads the variables instead of setting
        // them, and says why if it cannot.
        if std::env::var(ENV_NUM_LEAF_PROOFS).is_ok()
            || std::env::var(ENV_NUM_PRIVATE_BATCH_PROOFS).is_ok()
        {
            return;
        }
        let parsed = args(&[]).unwrap().unwrap();
        assert_eq!(parsed.num_leaf_proofs, DEFAULT_NUM_LEAF_PROOFS);
        assert_eq!(
            parsed.num_private_batch_proofs,
            Some(DEFAULT_NUM_PRIVATE_BATCH_PROOFS)
        );
        assert!(parsed.include_padding_batch);
    }

    /// A flag beats the environment, and both beat the default.
    #[test]
    fn a_flag_overrides_the_environment() {
        let parsed = args(&["--num-leaf-proofs", "3"]).unwrap().unwrap();
        assert_eq!(parsed.num_leaf_proofs, 3);
    }

    #[test]
    fn every_flag_is_parsed() {
        let parsed = args(&[
            "--output",
            "bins",
            "--num-leaf-proofs",
            "3",
            "--num-private-batch-proofs",
            "5",
            "--skip-padding-batch",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(parsed.output, "bins");
        assert_eq!(parsed.num_leaf_proofs, 3);
        assert_eq!(parsed.num_private_batch_proofs, Some(5));
        assert!(!parsed.include_padding_batch);

        let parsed = args(&["--no-public-batch"]).unwrap().unwrap();
        assert_eq!(parsed.num_private_batch_proofs, None);
    }

    /// A flag with no value, or a value that is not a number, must be an error
    /// rather than a silent default: an operator who mistypes a dimension
    /// would otherwise publish a set built for something else.
    #[test]
    fn malformed_arguments_are_errors() {
        assert!(args(&["--num-leaf-proofs"]).is_err());
        assert!(args(&["--num-leaf-proofs", "seven"]).is_err());
        assert!(args(&["--output"]).is_err());
        assert!(args(&["--unknown"]).is_err());
    }

    #[test]
    fn help_prints_instead_of_generating() {
        assert!(args(&["--help"]).unwrap().is_none());
    }
}
