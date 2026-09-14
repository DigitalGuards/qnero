//! Repository guard: Qnero has one signature scheme at the transparent entry.
//!
//! The consensus rule lives in `chain/runtime/src/extrinsic.rs`: a signed
//! extrinsic carrying the ML-DSA-65 variant of `DilithiumSignatureScheme` is
//! refused with `InvalidTransaction::BadSigner`. Its runtime guard is
//! `chain/runtime/tests/transactions/signature_scheme.rs`.
//!
//! This test guards the documentation and the code around that rule: no
//! Qnero-owned path may present the level-3 scheme as something this chain
//! carries. It walks the paths Qnero owns and fails on every spelling of it,
//! with three narrow exceptions, each of which has to earn its place:
//!
//! 1. The files whose job is the rule itself, [`RULE_FILES`].
//! 2. A line that states the refusal. A sentence naming the scheme beside the
//!    word "refuse" is the rule being written down, which every doc that
//!    documents it has to be able to do.
//! 3. A named line that describes somebody else's chain,
//!    [`FOREIGN_CLAIM_ANCHORS`]. The comparison table in `README.md` sets five
//!    projects against each other, and what Quantus admits is Quantus's
//!    business.
//!
//! Upstream files under `chain/` are out of scope on purpose. The two-variant
//! enum stays exactly as upstream wrote it so the next subtree merge is clean,
//! and so a client can still size a signature blob by its variant index out of
//! the runtime's own metadata. The vendored `sc-cli` fork can still mint a
//! level-3 key; the consensus rule is what makes that key inert.

use std::fs;
use std::path::{Path, PathBuf};

/// Every spelling of the level-3 scheme that appears in this tree, searched
/// case-insensitively. `ML-DSA-65`, `ml-dsa-65` and `ml_dsa_65` reduce to the
/// first two; `Dilithium65` and `MlDsa65` to the last two.
const FORBIDDEN: [&str; 4] = ["ml-dsa-65", "ml_dsa_65", "dilithium65", "mldsa65"];

/// Paths Qnero owns, relative to the repository root. A file or a directory.
const SCANNED: [&str; 8] = [
    "README.md",
    "docs",
    "crates",
    "chain/runtime/src",
    "chain/node/src",
    "chain/pallets/shielded",
    "chain/README.md",
    "chain/MINING.md",
];

/// The rule, its runtime guard, the change entry that records the removal, and
/// this file. Each one exists to name the scheme the chain refuses.
const RULE_FILES: [&str; 4] = [
    "chain/runtime/src/extrinsic.rs",
    "chain/runtime/tests/transactions/signature_scheme.rs",
    "crates/qnero-pqcrypto/CHANGES.md",
    "crates/qnero-wallet/tests/one_signature_scheme.rs",
];

/// `(file, anchor)`: a line carrying the anchor may name the scheme, because it
/// is a statement about another project.
const FOREIGN_CLAIM_ANCHORS: [(&str, &str); 1] = [("README.md", "| Spend authorization |")];

/// Build output and dependency trees. Source lives elsewhere.
const SKIPPED_DIRS: [&str; 4] = ["target", "node_modules", "pkg", ".git"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves from the wallet crate")
}

fn is_text(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "md" | "toml" | "json" | "ts" | "tsx" | "js" | "html" | "sh" | "yml" | "yaml")
    )
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        if is_text(path) {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let name = child
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if child.is_dir() && SKIPPED_DIRS.contains(&name) {
            continue;
        }
        collect(&child, out);
    }
}

/// A hit is allowed when the block it sits in says the chain refuses the
/// scheme. That is the rule being written down, and `docs/DESIGN.md`,
/// `docs/OPS-DEV.md` and the runtime's own comments all have to be able to
/// write it down.
///
/// The unit is the block, a run of lines between blank ones: a markdown
/// paragraph, a list item, a comment block. Prose wraps, so the sentence that
/// states the rule is rarely on the line that names the scheme; asking for it
/// in the same paragraph is what keeps this from being a keyword next to a
/// keyword.
fn states_the_refusal(lines: &[&str], at: usize) -> bool {
    let start = lines[..at]
        .iter()
        .rposition(|line| line.trim().is_empty())
        .map_or(0, |i| i + 1);
    let end = lines[at..]
        .iter()
        .position(|line| line.trim().is_empty())
        .map_or(lines.len(), |i| at + i);
    lines[start..end]
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("refus"))
}

fn is_foreign_claim(relative: &str, line: &str) -> bool {
    FOREIGN_CLAIM_ANCHORS
        .iter()
        .any(|(file, anchor)| *file == relative && line.contains(anchor))
}

#[test]
fn no_qnero_owned_path_offers_ml_dsa_65() {
    let root = repo_root();

    let mut files = Vec::new();
    for entry in SCANNED {
        let path = root.join(entry);
        assert!(
            path.exists(),
            "scanned path {entry} is gone; fix this guard's list"
        );
        collect(&path, &mut files);
    }
    assert!(
        files.len() > 50,
        "the guard walked only {} files; its list is wrong",
        files.len()
    );

    let mut hits = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if RULE_FILES.contains(&relative.as_str()) {
            continue;
        }
        let Ok(contents) = fs::read_to_string(file) else {
            continue;
        };
        let lines: Vec<&str> = contents.lines().collect();
        for (number, line) in lines.iter().enumerate() {
            let lowered = line.to_ascii_lowercase();
            if !FORBIDDEN.iter().any(|needle| lowered.contains(needle)) {
                continue;
            }
            if states_the_refusal(&lines, number) || is_foreign_claim(&relative, line) {
                continue;
            }
            hits.push(format!("{relative}:{}: {}", number + 1, line.trim()));
        }
    }

    assert!(
        hits.is_empty(),
        "Qnero has one signature scheme at the transparent entry, ML-DSA-87. These lines \
		 present the level-3 scheme as something Qnero carries:\n{}\n\nThe refusal rule is \
		 chain/runtime/src/extrinsic.rs. A line that documents the refusal may name the \
		 scheme; a line that offers it may not.",
        hits.join("\n")
    );
}

/// The comparison table's own Qnero column, checked apart from the line it sits
/// on. The row is exempt above because the Quantus cell beside it names the
/// scheme, and that exemption must not become a hole in Qnero's own cell.
#[test]
fn the_comparison_table_claims_one_scheme_for_qnero() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let row = readme
        .lines()
        .find(|line| line.starts_with("| Spend authorization |"))
        .expect("the comparison table still has a spend-authorization row");

    let cells: Vec<&str> = row.split('|').map(str::trim).collect();
    let qnero = cells.get(2).expect("the Qnero column");
    let lowered = qnero.to_ascii_lowercase();
    assert!(
        !FORBIDDEN.iter().any(|needle| lowered.contains(needle)),
        "the Qnero cell of the comparison table still offers the level-3 scheme: {qnero}"
    );
    assert!(
        lowered.contains("ml-dsa-87"),
        "the Qnero cell must name the one scheme the chain admits: {qnero}"
    );
}

/// The rule must stay where this guard says it is, and must still be the
/// refusal. A guard whose exemption list points at a file that refuses nothing
/// is worse than no guard.
#[test]
fn the_refusal_rule_is_where_the_guard_says() {
    let rule = repo_root().join("chain/runtime/src/extrinsic.rs");
    let contents = fs::read_to_string(&rule).expect("the consensus rule file exists");
    assert!(
        contents.contains("DilithiumSignatureScheme::Dilithium65(_)"),
        "the refusal no longer matches on the level-3 variant"
    );
    assert!(
        contents.contains("InvalidTransaction::BadSigner"),
        "the refusal no longer answers BadSigner"
    );
}
