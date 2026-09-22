//! CLI for artifact generation on a trusted build host.
//!
//! ```text
//! qnero-circuit-builder --output <dir> --num-leaf-proofs <n>
//!                       [--num-private-batch-proofs <n>] [--no-public-batch]
//!                       [--skip-padding-batch] [--report-pins]
//! ```
//!
//! The flags are parsed by hand. A build-host tool that pulls in an argument
//! parser and its dependency tree buys convenience for four flags and pays for
//! it in everything that has to be reviewed and rebuilt alongside the
//! circuits.

use anyhow::{bail, Context, Result};

use qnero_circuit_builder::{
    generate_all_artifacts_with, PinPolicy, DEFAULT_NUM_LEAF_PROOFS,
    DEFAULT_NUM_PRIVATE_BATCH_PROOFS,
};

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

/// How a dimension is looked up in the environment.
///
/// A parameter, taken so the code under test never reads the process
/// environment directly, which is global: a test that asserted the defaults against the real
/// environment would have to skip itself whenever an override was exported,
/// and a skip that reports as a pass is worse than no test. `main` passes the
/// real lookup; the tests pass an empty one.
type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The real environment.
fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// A dimension from the environment, when it is set.
///
/// A malformed value is an error. Falling back to the default would publish a
/// set built for dimensions nobody asked for, and the mismatch would surface
/// as a public-input length failure much later.
fn count_from_env(env: EnvLookup<'_>, name: &str) -> Result<Option<usize>> {
    match env(name) {
        Some(value) => {
            Ok(Some(value.parse().with_context(|| {
                format!("{name} expects a number, got {value}")
            })?))
        }
        None => Ok(None),
    }
}

struct Args {
    output: String,
    num_leaf_proofs: usize,
    num_private_batch_proofs: Option<usize>,
    include_padding_batch: bool,
    pins: PinPolicy,
}

/// The numbers are not spelled out here: they live in
/// [`DEFAULT_NUM_LEAF_PROOFS`] and [`DEFAULT_NUM_PRIVATE_BATCH_PROOFS`], and a
/// copy in this string would drift the moment one of them moves.
const USAGE: &str = "\
usage: qnero-circuit-builder [options]

  --output <dir>                     where to write the set (default: generated-artifacts)
  --num-leaf-proofs <n>              leaf slots per private batch (default: the chain
                                     default, or QNERO_NUM_LEAF_PROOFS)
  --num-private-batch-proofs <n>     private batches per public batch (default: the chain
                                     default, or QNERO_NUM_PRIVATE_BATCH_PROOFS)
  --no-public-batch                  stop at the private batch
  --skip-padding-batch               do not prove the all-padding private batch
  --report-pins                      print the three artifact digests and publish the set
                                     whatever they are, instead of holding it to the
                                     release pin. For the release that moves the circuit
                                     on purpose and needs the new digests.
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

fn parse_args(mut args: impl Iterator<Item = String>, env: EnvLookup<'_>) -> Result<Option<Args>> {
    let mut parsed = Args {
        output: String::from("generated-artifacts"),
        num_leaf_proofs: count_from_env(env, ENV_NUM_LEAF_PROOFS)?
            .unwrap_or(DEFAULT_NUM_LEAF_PROOFS),
        num_private_batch_proofs: Some(
            count_from_env(env, ENV_NUM_PRIVATE_BATCH_PROOFS)?
                .unwrap_or(DEFAULT_NUM_PRIVATE_BATCH_PROOFS),
        ),
        include_padding_batch: true,
        pins: PinPolicy::Enforce,
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
            "--report-pins" => parsed.pins = PinPolicy::Report,
            other => bail!("unknown argument {}\n\n{}", other, USAGE),
        }
    }

    Ok(Some(parsed))
}

fn main() -> Result<()> {
    let Some(args) = parse_args(std::env::args().skip(1), &process_env)? else {
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

    if args.pins == PinPolicy::Report {
        println!(
            "--report-pins: the release pin is measured and printed, not enforced. Paste the \
             digests into crates/qnero-circuit/src/profile.rs and rebuild without this flag."
        );
    }

    let started = std::time::Instant::now();
    generate_all_artifacts_with(
        &args.output,
        args.num_leaf_proofs,
        args.num_private_batch_proofs,
        args.include_padding_batch,
        args.pins,
    )?;
    println!("done in {:.1}s", started.elapsed().as_secs_f64());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment that carries no override, whatever the real one holds.
    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn args(values: &[&str]) -> Result<Option<Args>> {
        parse_args(values.iter().map(|value| value.to_string()), &no_env)
    }

    fn args_with_env(values: &[&str], env: EnvLookup<'_>) -> Result<Option<Args>> {
        parse_args(values.iter().map(|value| value.to_string()), env)
    }

    /// The defaults are asserted against an empty environment: a shell that
    /// exports an override must not turn this into a silent pass.
    #[test]
    fn the_defaults_are_the_chain_defaults() {
        let parsed = args(&[]).unwrap().unwrap();
        assert_eq!(parsed.num_leaf_proofs, DEFAULT_NUM_LEAF_PROOFS);
        assert_eq!(
            parsed.num_private_batch_proofs,
            Some(DEFAULT_NUM_PRIVATE_BATCH_PROOFS)
        );
        assert!(parsed.include_padding_batch);
    }

    /// The environment beats the default.
    #[test]
    fn the_environment_overrides_the_defaults() {
        let env = |name: &str| match name {
            ENV_NUM_LEAF_PROOFS => Some(String::from("6")),
            ENV_NUM_PRIVATE_BATCH_PROOFS => Some(String::from("11")),
            _ => None,
        };
        let parsed = args_with_env(&[], &env).unwrap().unwrap();
        assert_eq!(parsed.num_leaf_proofs, 6);
        assert_eq!(parsed.num_private_batch_proofs, Some(11));
    }

    /// A malformed override is an error. A silent fall back to the default
    /// would publish a set built for dimensions nobody asked
    /// for.
    #[test]
    fn a_malformed_environment_override_is_an_error() {
        let env = |name: &str| (name == ENV_NUM_LEAF_PROOFS).then(|| String::from("seven"));
        assert!(args_with_env(&[], &env).is_err());
    }

    /// A flag beats the environment, and both beat the default.
    #[test]
    fn a_flag_overrides_the_environment() {
        let env = |name: &str| (name == ENV_NUM_LEAF_PROOFS).then(|| String::from("6"));
        let parsed = args_with_env(&["--num-leaf-proofs", "3"], &env)
            .unwrap()
            .unwrap();
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
            "--report-pins",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(parsed.output, "bins");
        assert_eq!(parsed.num_leaf_proofs, 3);
        assert_eq!(parsed.num_private_batch_proofs, Some(5));
        assert!(!parsed.include_padding_batch);
        assert_eq!(parsed.pins, PinPolicy::Report);

        let parsed = args(&["--no-public-batch"]).unwrap().unwrap();
        assert_eq!(parsed.num_private_batch_proofs, None);
    }

    /// The pin is enforced unless an operator asks for it not to be. A
    /// default that reported would let a circuit change reach a runtime with
    /// nothing refusing it.
    #[test]
    fn the_release_pin_is_enforced_unless_the_flag_asks_otherwise() {
        assert_eq!(args(&[]).unwrap().unwrap().pins, PinPolicy::Enforce);
        assert_eq!(
            args(&["--report-pins"]).unwrap().unwrap().pins,
            PinPolicy::Report
        );
    }

    /// A flag with no value, or a value that is not a number, must be an
    /// error: an operator who mistypes a dimension would otherwise publish a
    /// set built for something else.
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
