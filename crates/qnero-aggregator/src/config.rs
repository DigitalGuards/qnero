//! Batch dimensions, and the file that records them next to the artifacts.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub use qnero_circuit::batch_layout::MAX_PROOF_COUNT;

/// Reject a per-layer proof count outside `1..=MAX_PROOF_COUNT`.
///
/// Every entry point that takes a count from outside calls this before
/// allocating, building a circuit or computing a layout offset. Zero would
/// build a wrapper with no inner-proof constraints at all, and the layout
/// helpers in `qnero_circuit::batch_layout` use unchecked arithmetic that
/// wraps in release builds.
pub fn validate_proof_count(count: usize, label: &str) -> Result<()> {
    if count == 0 {
        bail!("{} must be greater than 0", label);
    }
    if count > MAX_PROOF_COUNT {
        bail!(
            "{} ({}) exceeds the maximum supported proof count ({})",
            label,
            count,
            MAX_PROOF_COUNT
        );
    }
    Ok(())
}

/// The dimensions an artifact set was built for, stored beside it as
/// `config.json`.
///
/// A verifier artifact's public-input length is a function of these numbers,
/// so a consumer that loaded the artifacts without them would have nothing to
/// check that length against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBinsConfig {
    /// Leaf proofs per private batch.
    pub num_leaf_proofs: usize,
    /// Private-batch proofs per public batch. `None` when the set stops at the
    /// private batch.
    pub num_private_batch_proofs: Option<usize>,
}

impl CircuitBinsConfig {
    pub fn new(num_leaf_proofs: usize, num_private_batch_proofs: Option<usize>) -> Result<Self> {
        let config = Self {
            num_leaf_proofs,
            num_private_batch_proofs,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        validate_proof_count(self.num_leaf_proofs, "num_leaf_proofs")?;
        if let Some(count) = self.num_private_batch_proofs {
            validate_proof_count(count, "num_private_batch_proofs")?;
        }
        Ok(())
    }

    /// Read `config.json` from an artifact directory.
    pub fn load<P: AsRef<Path>>(bins_dir: P) -> Result<Self> {
        let path = bins_dir.as_ref().join("config.json");
        let bytes = crate::artifacts::read_artifact_file(&path)?;
        let text = String::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("{} is not valid UTF-8: {}", path.display(), e))?;
        let config: Self = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {}", path.display(), e))?;
        config.validate()?;
        Ok(config)
    }

    /// Write `config.json` into an artifact directory.
    pub fn save<P: AsRef<Path>>(&self, bins_dir: P) -> Result<()> {
        self.validate()?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize the artifact config: {}", e))?;
        crate::artifacts::commit_artifact_set(
            bins_dir.as_ref(),
            &[("config.json", text.into_bytes())],
            &[],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qnero-config-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn proof_counts_are_bounded_on_both_sides() {
        assert!(validate_proof_count(0, "n").is_err());
        assert!(validate_proof_count(1, "n").is_ok());
        assert!(validate_proof_count(MAX_PROOF_COUNT, "n").is_ok());
        assert!(validate_proof_count(MAX_PROOF_COUNT + 1, "n").is_err());
    }

    #[test]
    fn the_config_round_trips_through_a_directory() {
        let dir = temp_dir("round-trip");
        let config = CircuitBinsConfig::new(7, Some(53)).unwrap();
        config.save(&dir).unwrap();
        assert_eq!(CircuitBinsConfig::load(&dir).unwrap(), config);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A config file is data, and a stored zero would otherwise reach the
    /// circuit builder as a dimension.
    #[test]
    fn a_stored_config_is_validated_on_load() {
        let dir = temp_dir("invalid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.json"),
            br#"{"num_leaf_proofs": 0, "num_private_batch_proofs": 4}"#,
        )
        .unwrap();
        let error = CircuitBinsConfig::load(&dir).unwrap_err();
        assert!(error.to_string().contains("num_leaf_proofs"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_private_batch_only_set_has_no_public_batch_count() {
        let dir = temp_dir("private-only");
        let config = CircuitBinsConfig::new(2, None).unwrap();
        config.save(&dir).unwrap();
        assert_eq!(
            CircuitBinsConfig::load(&dir)
                .unwrap()
                .num_private_batch_proofs,
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
