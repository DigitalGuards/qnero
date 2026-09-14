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
//! 2. A line that states the refusal, within one line either side, and on the
//!    line itself when it is a markdown table row. A sentence naming the scheme
//!    next to the word "refuse" is the rule being written down, which every doc
//!    that documents it has to be able to do.
//! 3. A named line that describes somebody else's chain,
//!    [`FOREIGN_CLAIM_ANCHORS`]. The comparison table in `README.md` sets five
//!    projects against each other, and what Quantus admits is Quantus's
//!    business.
//!
//! Exception 2 is deliberately tight, and [`EXPECTED_EXEMPT_HITS`] pins how far
//! it reaches. It used to be evaluated over the whole blank-line-delimited
//! block a hit sat in, which is a unit with no ceiling: a markdown table has no
//! blank line between its rows, so one row saying "refuses" exempted every other
//! row, and a long Rust block with one "refused" in a doc comment exempted every
//! line of code under it. Prose still wraps, so one line either side is the
//! width a sentence actually needs; a table row gets no neighbours at all,
//! because the row beside it is a different claim.
//!
//! Upstream files under `chain/` are out of scope on purpose. The two-variant
//! enum stays exactly as upstream wrote it so the next subtree merge is clean,
//! and so a client can still size a signature blob by its variant index out of
//! the runtime's own metadata. The vendored `sc-cli` fork can still mint a
//! level-3 key; `chain/node/src/command.rs` refuses the flag before `sc-cli`
//! sees it, and the consensus rule is what makes any key minted elsewhere inert.

use std::fs;
use std::path::{Path, PathBuf};

/// Every spelling of the level-3 scheme that appears in this tree, searched
/// case-insensitively. `ML-DSA-65`, `ml-dsa-65` and `ml_dsa_65` reduce to the
/// first two; `Dilithium65` and `MlDsa65` to the last two.
const FORBIDDEN: [&str; 4] = ["ml-dsa-65", "ml_dsa_65", "dilithium65", "mldsa65"];

/// Paths Qnero owns, relative to the repository root. A file or a directory.
const SCANNED: [&str; 12] = [
    "README.md",
    "docs",
    "crates",
    "chain/runtime/src",
    "chain/runtime/tests",
    "chain/node/src",
    "chain/pallets/shielded",
    "chain/README.md",
    "chain/MINING.md",
    "chain/docs",
    "wallet-web",
    "explorer",
];

/// The rule, its runtime guard, the change entry that records the removal, the
/// runtime tests that pin the primitive underneath the rule, and this file.
/// Each one exists to name the scheme the chain refuses.
const RULE_FILES: [&str; 5] = [
    "chain/runtime/src/extrinsic.rs",
    "chain/runtime/tests/transactions/signature_scheme.rs",
    "chain/runtime/tests/transactions/integration.rs",
    "crates/qnero-pqcrypto/CHANGES.md",
    "crates/qnero-wallet/tests/one_signature_scheme.rs",
];

/// `(file, anchor)`: a line carrying the anchor may name the scheme, because it
/// is a statement about another project.
const FOREIGN_CLAIM_ANCHORS: [(&str, &str); 1] = [("README.md", "| Spend authorization |")];

/// Build output, dependency trees, test artifacts and local devnet state.
/// Source lives elsewhere.
const SKIPPED_DIRS: [&str; 10] = [
    "target",
    "node_modules",
    "pkg",
    ".git",
    "dist",
    "build",
    ".next",
    "coverage",
    "test-results",
    ".devnet",
];

/// How many hits the refusal exemption and the foreign-claim anchor carry
/// between them, as of the commit that narrowed the exemption.
///
/// This is pinned, and a doc edit that adds or drops a mention of the scheme is
/// expected to move it. That is the point: the count is the exemption's reach,
/// and a reach that grows without anyone noticing is how the old block-wide
/// version went from "the sentence that states the rule" to 16% of every line
/// the guard walked. Move the number when you have read the new hits the
/// failure message lists.
const EXPECTED_EXEMPT_HITS: usize = 25;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves from the wallet crate")
}

fn is_text(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(
            "rs" | "md"
                | "toml"
                | "json"
                | "ts"
                | "tsx"
                | "js"
                | "mjs"
                | "svelte"
                | "html"
                | "sh"
                | "yml"
                | "yaml"
        )
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

/// A hit is allowed when the line it sits on, or one line either side of it,
/// says the chain refuses the scheme. That is the rule being written down, and
/// `docs/DESIGN.md`, `docs/OPS-DEV.md` and the runtime's own comments all have
/// to be able to write it down.
///
/// One line either side, and no more. Prose wraps, so the sentence that states
/// the rule is often not on the line that names the scheme; every wider unit
/// (the paragraph, the blank-line-delimited block) exempts an amount of
/// unrelated text that nobody can see from the code.
///
/// A markdown table row is narrower still: it has to state the refusal itself.
/// A table has no blank line anywhere in it and every row is a claim of its
/// own, so a row that offers the scheme must not be able to borrow the word
/// from the row above it. Every table row exempted today already carries it.
fn states_the_refusal(lines: &[&str], at: usize) -> bool {
    let says_it = |line: &&str| line.to_ascii_lowercase().contains("refus");
    if lines[at].trim_start().starts_with('|') {
        return says_it(&lines[at]);
    }
    let start = at.saturating_sub(1);
    let end = (at + 2).min(lines.len());
    lines[start..end].iter().any(says_it)
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
        files.len() > 300,
        "the guard walked only {} files; its list is wrong",
        files.len()
    );

    let mut hits = Vec::new();
    let mut exempt = Vec::new();
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
            let found = format!("{relative}:{}: {}", number + 1, line.trim());
            if states_the_refusal(&lines, number) || is_foreign_claim(&relative, line) {
                exempt.push(found);
                continue;
            }
            hits.push(found);
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

    assert_eq!(
        exempt.len(),
        EXPECTED_EXEMPT_HITS,
        "the exemptions now cover {} lines; EXPECTED_EXEMPT_HITS says \
		 {EXPECTED_EXEMPT_HITS}. Read them, then move it if every one of them is the rule \
		 being written down:\n{}",
        exempt.len(),
        exempt.join("\n")
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

/// The narrowed exemption, checked on its own terms.
///
/// A line that names the scheme with no refusal close enough to it is a hit,
/// whichever unit it sits in. The old block-wide version answered `true` for
/// every row of the table below, because a table is one blank-line-delimited
/// block and one of its rows says "refuses"; that is the case that showed the
/// exemption had no ceiling.
#[test]
fn the_exemption_does_not_reach_past_the_line_that_states_it() {
    let table = [
        "| Layer | Scheme | Where |",
        "| --- | --- | --- |",
        "| Transparent entry | ML-DSA-87; the entry refuses level 3 | extrinsic.rs |",
        "| Legacy wallets | ML-DSA-65 accepted | nowhere |",
    ];
    assert!(
        states_the_refusal(&table, 2),
        "the row that states the rule"
    );
    assert!(
        !states_the_refusal(&table, 3),
        "a table row states the refusal itself or it is a hit"
    );

    // Prose wraps, so a sentence is given one line either side and no more.
    let prose = [
        "The transparent entry refuses the level-3 variant, so an",
        "ML-DSA-65 signature is invalid before it is verified.",
        "",
        "ML-DSA-65 is offered here.",
    ];
    assert!(
        states_the_refusal(&prose, 1),
        "the line the sentence wraps onto"
    );
    assert!(
        !states_the_refusal(&prose, 3),
        "a separate paragraph inherits nothing"
    );
}
