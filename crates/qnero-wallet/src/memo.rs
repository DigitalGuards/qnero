//! Memos: padded on the way out, unpadded on the way in, escaped on the way to
//! a terminal.
//!
//! A note ciphertext is a fixed 1731 bytes plus its memo, byte for byte
//! (`qnero_pqcrypto::note_encryption`: the memo rides in its own AEAD payload
//! and `to_bytes` length-prefixes it). The chain publishes those bytes in
//! full, in `Shielded::Ciphertexts` and in the `SlotSettled` event, so an
//! unpadded memo publishes its own exact length to every chain reader. Two
//! things follow from that, and both are why every memo this wallet writes is
//! padded to one size:
//!
//! - `len(ct_1) - len(ct_2)` is the memo's byte count. It correlates any two
//!   payments carrying the same memo string, with no key material at all.
//! - A spend writes a payment and a change note. The change memo is empty, so
//!   an unpadded pair splits the pool's outputs publicly into "went to a
//!   counterparty" and "came back to the sender", which is most of what the
//!   pool exists to hide.
//!
//! The fee is computed from the same total, so it republishes the length in
//! `CiphertextBytesPerFeeQuantum` buckets even when nobody reads the
//! ciphertexts.

use anyhow::{bail, Result};

/// What a `NoteCiphertext` serializes to with an empty memo.
///
/// Fixed by the crypto suite: 19 bytes of framing, an
/// ML-KEM-1024 encapsulation (1568), the note payload under a
/// ChaCha20-Poly1305 tag (128) and the memo's own tag (16).
/// `an_empty_memo_ciphertext_serializes_to_1731_bytes` in `qnero-pqcrypto`
/// pins it against the serializer and `tests/ct_digest.rs` pins it here.
/// Every size below is derived from it.
pub const CIPHERTEXT_FIXED_BYTES: usize = 1731;

/// Every memo this wallet encrypts is exactly this many bytes.
///
/// Two bounds decide it, and the tighter one wins.
///
/// The loose bound is `MaxCiphertextBytes` (2048 in the M4 runtime) minus
/// [`CIPHERTEXT_FIXED_BYTES`], which leaves 317 bytes. A pad over that fails
/// the extrinsic's SCALE decode, after the proof committing to those bytes
/// exists.
///
/// The tight bound is the fee. A slot's payload term is
/// `ceil((len(ct_1) + len(ct_2)) / CiphertextBytesPerFeeQuantum)`, and the
/// runtime sizes that divisor (512) so that an honest pair and a pair padded
/// to the cap land in different buckets: the chain never parses these bytes
/// and `Shielded::Ciphertexts` is never pruned, so without the separation a
/// settler pads both ciphertexts to the cap and writes the extra bytes of
/// permanent state for no extra fee. A pad of 256 put this wallet's own pair
/// at `2 * (1731 + 256) = 3974` bytes, in the same bucket as `2 * 2048 =
/// 4096`, which voided that separation for every real spend on the chain.
/// A pad of 61 puts the pair at 3584 bytes, one bucket below the cap's, and
/// 61 is the largest pad that does.
///
/// `fee::the_wallets_own_pair_stays_a_bucket_below_a_padded_one` is the gate,
/// and `fee::ensure_memo_pad_fits` checks **both** bounds against the runtime
/// the wallet is actually talking to, since this constant is compiled in while
/// `MaxCiphertextBytes` and `CiphertextBytesPerFeeQuantum` are both read from
/// metadata. `fee::largest_separating_pad` is where the 61 comes from, and a
/// runtime that moves either value is refused by name rather than settling at
/// a merged endpoint.
///
/// Zcash's 512-byte memo field is the precedent for padding at all. The size
/// differs because this ciphertext's fixed part is larger and because the
/// chain prices payload bytes.
pub const MEMO_BYTES: usize = 61;

/// The narrowest `balance` table prefix: `{:>10}  {:>12}  {:>7}  {:>7}  ` in
/// `main.rs`, four right-aligned fields at their minimum widths and the two
/// spaces after each.
///
/// It is a floor and not the number to budget against. A leaf index past
/// 9,999,999,999 or a value past 999,999,999,999 widens its own field, so
/// `main.rs` measures the rows it is about to print and passes the width it
/// actually used to [`memo_budget_within`].
pub const BALANCE_PREFIX_COLUMNS: usize = 44;

/// The terminal width assumed when nothing says otherwise.
pub const DEFAULT_TERMINAL_COLUMNS: usize = 80;

/// Columns of memo `balance` prints before it truncates, at the default
/// terminal width and the narrowest prefix.
pub const MEMO_DISPLAY_COLUMNS: usize = DEFAULT_TERMINAL_COLUMNS - BALANCE_PREFIX_COLUMNS;

/// The narrowest memo column worth drawing. Below it the memo moves to a line
/// of its own.
pub const MIN_MEMO_COLUMNS: usize = 16;

/// This terminal's width in columns.
///
/// Asked of the terminal itself, through `TIOCGWINSZ` on standard output.
/// `COLUMNS` is the fallback and 80 is the fallback after that.
///
/// The regression: this used to read `COLUMNS` and nothing else. `COLUMNS` is
/// a shell parameter that bash and zsh maintain without exporting, so a child
/// process sees no such variable and every run took the 80-column default,
/// whatever terminal it was printed into. The budget the table sized its memo
/// column from was therefore a constant, the row was always drawn at 80
/// columns, and on any narrower terminal the tail of a memo the sender chose
/// opened a fresh line at column 1: the forged balance row the escaping in
/// [`render_memo_within`] exists to close, reached without one control
/// character.
///
/// A zero width is what the call answers with when standard output is a pipe
/// or a file on some systems, so it is treated as no answer.
pub fn terminal_columns() -> usize {
    resolve_columns(ioctl_columns(), std::env::var("COLUMNS").ok().as_deref())
}

/// The width decision, with both sources handed in.
///
/// Split out from [`terminal_columns`] because neither source is settable from
/// a test: `cargo test` leaves the process's own standard output attached to
/// whatever the developer ran it from, so the `ioctl` answers a real width on
/// one machine and fails on another.
pub fn resolve_columns(from_terminal: Option<usize>, from_env: Option<&str>) -> usize {
    if let Some(columns) = from_terminal.filter(|columns| *columns > 0) {
        return columns;
    }
    from_env
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|columns| *columns > 0)
        .unwrap_or(DEFAULT_TERMINAL_COLUMNS)
}

/// `TIOCGWINSZ` on standard output, or `None` when it is not a terminal.
fn ioctl_columns() -> Option<usize> {
    // SAFETY: `winsize` is written by the kernel on success and read only
    // then. The file descriptor is the process's own standard output, and a
    // failed call leaves the structure zeroed by this initializer.
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let answered = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) };
    if answered != 0 || size.ws_col == 0 {
        return None;
    }
    Some(size.ws_col as usize)
}

/// The memo column for a row whose fields occupy `prefix_columns`, or `None`
/// when this terminal cannot hold the prefix and a usable memo column both.
///
/// There is no floor. A floor is a budget that overrides the terminal, which
/// is the same failure as never reading the terminal at all: the old one held
/// the column at sixteen columns, so a 40-column terminal was handed a
/// 60-column row. `None` is what a terminal too narrow for the table says, and
/// `main.rs` answers it by putting the memo on a line of its own rather than
/// letting the row wrap.
pub fn memo_budget_within(prefix_columns: usize) -> Option<usize> {
    budget_within(terminal_columns(), prefix_columns)
}

/// The budget decision, with the width handed in. See [`resolve_columns`].
pub fn budget_within(columns: usize, prefix_columns: usize) -> Option<usize> {
    let budget = columns.saturating_sub(prefix_columns);
    (budget >= MIN_MEMO_COLUMNS).then_some(budget)
}

/// Pad a memo to [`MEMO_BYTES`] with trailing zeros.
pub fn pad_memo(memo: &str) -> Result<Vec<u8>> {
    let bytes = memo.as_bytes();
    if bytes.len() > MEMO_BYTES {
        bail!(
            "the memo is {} bytes and this wallet pads every memo to {MEMO_BYTES}. A longer one \
             would make this ciphertext a different length from every other note's, which is the \
             leak the padding exists to close.",
            bytes.len()
        );
    }
    let mut padded = vec![0u8; MEMO_BYTES];
    padded[..bytes.len()].copy_from_slice(bytes);
    Ok(padded)
}

/// Strip the padding a received memo carries.
///
/// Trailing zero bytes, the way the padding writes them. A memo from a sender
/// that does not pad passes through unchanged unless it ends in NUL, which a
/// text memo does not.
pub fn unpad_memo(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// Render a memo for a terminal, at the default budget.
pub fn render_memo(memo: &str) -> String {
    render_memo_within(memo, MEMO_DISPLAY_COLUMNS)
}

/// Render a memo for a terminal, inside `columns` display columns.
///
/// A memo is remote input: anyone holding this wallet's address can send it a
/// note, and the memo rides along. Printed byte for byte it is an escape
/// sequence injection into the operator's terminal. `\r\x1b[2K` erases the
/// line just written and lets the sender redraw the balance table with leaf
/// indices, values and spent flags of their choosing; `\x1b]52;c;...\x07`
/// writes the sender's own address into the clipboard the operator then pastes
/// into `send --to`. Bidi controls reorder a line without any escape at all.
///
/// So everything outside printable ASCII is escaped as `\u{..}`, and the
/// result is capped at `columns`, which the caller sizes from the terminal
/// width minus the table's own prefix. One note is one row.
///
/// The escaping is deliberately wider than the set of characters that can
/// drive a terminal. Counting characters is only the same as counting columns
/// while every character is one column wide: an East Asian Wide glyph costs
/// two columns and a combining mark costs none, so a budget that counted
/// characters let a sender of 64 full-width digits draw 128 columns, wrap the
/// row on any ordinary terminal, and shape the continuation line into a
/// forged balance row without using one control byte. U+200B, U+200D, U+2028
/// and U+2029 are none of them `char::is_control`, and the first two also make
/// two different memos render identically. Escaping the lot makes character
/// count and column count the same number by construction, which is the only
/// version of this that stays true when someone adds a field to the table.
///
/// The store keeps the raw memo: serde_json escapes control characters on the
/// way to the file, and a wallet that rewrote what it received could not show
/// an operator what was actually sent.
pub fn render_memo_within(memo: &str, columns: usize) -> String {
    const ELLIPSIS: &str = "...";
    let columns = columns.max(ELLIPSIS.len());
    let pieces: Vec<String> = memo
        .chars()
        .map(|character| {
            if needs_escaping(character) {
                format!("\\u{{{:02x}}}", character as u32)
            } else {
                character.to_string()
            }
        })
        .collect();
    // Every piece is printable ASCII, so its character count is its column
    // count.
    let total: usize = pieces.iter().map(String::len).sum();
    if total <= columns {
        return pieces.concat();
    }
    let budget = columns - ELLIPSIS.len();
    let mut out = String::new();
    let mut used = 0usize;
    for piece in pieces {
        if used + piece.len() > budget {
            break;
        }
        used += piece.len();
        out.push_str(&piece);
    }
    out.push_str(ELLIPSIS);
    out
}

/// Whether a character may not reach a terminal as itself.
///
/// Everything outside printable ASCII. The controls move the cursor and start
/// escape sequences and the bidi overrides reorder a line without one, which
/// is the reason the escaping exists; the rest is escaped so that one
/// character is one column and the truncation above can hold a row to its
/// width. See [`render_memo_within`].
fn needs_escaping(character: char) -> bool {
    !matches!(character, ' '..='~')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the padding exists for: every memo this wallet writes
    /// produces a ciphertext of one length, so no observer reads a memo's size
    /// off the chain and no spend's change note is the shorter of the pair.
    #[test]
    fn every_padded_memo_is_the_same_length() {
        let lengths: Vec<usize> = ["", "x", "payment to B", &"m".repeat(MEMO_BYTES)]
            .iter()
            .map(|memo| pad_memo(memo).expect("it fits").len())
            .collect();
        assert!(lengths.iter().all(|len| *len == MEMO_BYTES), "{lengths:?}");
    }

    #[test]
    fn padding_round_trips_through_unpadding() {
        for memo in ["", "x", "payment to B", "a memo with spaces and 1234"] {
            let padded = pad_memo(memo).expect("it fits");
            assert_eq!(unpad_memo(&padded), memo.as_bytes(), "{memo}");
        }
        // Nothing but zeros is an empty memo, and an unpadded memo from
        // another wallet passes through.
        assert_eq!(unpad_memo(&[0u8; MEMO_BYTES]), b"");
        assert_eq!(unpad_memo(b"unpadded"), b"unpadded");
    }

    #[test]
    fn a_memo_longer_than_the_pad_is_refused() {
        let error = pad_memo(&"m".repeat(MEMO_BYTES + 1)).expect_err("it does not fit");
        assert!(error.to_string().contains("pads every memo"));
    }

    /// The regression: a memo is remote input and was printed byte for byte,
    /// so any sender could drive the operator's terminal through
    /// `qnero-wallet balance`.
    #[test]
    fn a_memo_cannot_carry_an_escape_sequence_to_the_terminal() {
        let hostile = "\r\x1b[2K       4          9000        3    unspent  attacker's row";
        let rendered = render_memo(hostile);
        assert!(
            !rendered.contains('\x1b'),
            "an ESC byte survived: {rendered}"
        );
        assert!(!rendered.contains('\r'), "a CR survived: {rendered}");
        assert!(rendered.contains("\\u{1b}"), "{rendered}");
        assert!(rendered.contains("\\u{0d}"), "{rendered}");

        // OSC 52 writes the sender's address into the operator's clipboard.
        let clipboard = render_memo("\x1b]52;c;cXExYWJj\x07");
        assert!(!clipboard.contains('\x1b'));
        assert!(!clipboard.contains('\u{7}'));

        // Bidi overrides reorder a line with no escape byte at all.
        let bidi = render_memo("paid \u{202e}0001 to bob");
        assert!(!bidi.contains('\u{202e}'), "{bidi}");
    }

    /// The regression, measured where it shows: on the wire. Two ciphertexts
    /// of different lengths, published side by side in `SlotSettled` and in
    /// `Shielded::Ciphertexts`, name which of a spend's outputs is the
    /// sender's change and how many bytes the payment's memo was.
    #[test]
    fn padded_memos_produce_ciphertexts_of_one_length() {
        let alice = qnero_notes::SpendingKey::from_bytes([7u8; 32]);
        let bob = qnero_notes::SpendingKey::from_bytes([9u8; 32]);
        let note = qnero_notes::Note::new(
            alice.pk(),
            1_000,
            qnero_notes::Digest::hash_bytes(&[b"rho"]),
            qnero_notes::Digest::hash_bytes(&[b"r"]),
        )
        .expect("a note");

        let measure = |key: &qnero_notes::SpendingKey, memo: &str| {
            qnero_notes::encrypt_note(
                &key.incoming_viewing_key().encapsulation_key(),
                &note,
                &pad_memo(memo).expect("it fits"),
                &[3u8; 32],
            )
            .expect("it encrypts")
            .to_bytes()
            .len()
        };

        // A payment to somebody else with a memo, and the sender's own change
        // note with none: the pair the chain publishes together.
        let payment = measure(&bob, "payment to B");
        let change = measure(&alice, "");
        assert_eq!(payment, change);
        assert_eq!(measure(&bob, &"m".repeat(MEMO_BYTES)), payment);
        assert_eq!(measure(&bob, "x"), payment);
    }

    /// One note is one row, measured the way a terminal measures one.
    ///
    /// The regression: the budget counted characters and the table prints a
    /// 44-column prefix before the memo, so a memo of full-width characters
    /// cost two columns each, drew a row past any ordinary terminal width and
    /// wrapped, and the continuation line was drawn entirely from bytes the
    /// sender chose. That is the forged balance row the escaping exists to
    /// stop, reached without one control character. Everything outside
    /// printable ASCII is escaped now, so one character is one column, and the
    /// budget is the terminal width less the prefix.
    #[test]
    fn a_long_memo_is_truncated_to_one_row() {
        let row = |memo: &str| BALANCE_PREFIX_COLUMNS + render_memo(memo).chars().count();

        let rendered = render_memo(&"m".repeat(MEMO_BYTES));
        assert!(rendered.ends_with("..."));
        assert!(
            row(&"m".repeat(MEMO_BYTES)) <= DEFAULT_TERMINAL_COLUMNS,
            "an ASCII memo overflowed the row: {} columns",
            row(&"m".repeat(MEMO_BYTES))
        );

        // Full-width digits: two columns each to a terminal, one `char` each
        // to `chars().count()`. Escaped, each is eight ASCII columns and the
        // budget sees every one of them.
        let wide = "\u{ff10}".repeat(MEMO_BYTES / 3);
        let rendered = render_memo(&wide);
        assert!(!rendered.contains('\u{ff10}'), "{rendered}");
        assert!(
            row(&wide) <= DEFAULT_TERMINAL_COLUMNS,
            "a full-width memo overflowed the row: {} columns",
            row(&wide)
        );

        // Neither a zero-width character nor a line separator is a control
        // character, and both were printed as themselves: the first makes two
        // different memos render identically, the second breaks the row in
        // terminals and log viewers.
        for hidden in ['\u{200b}', '\u{200d}', '\u{2028}', '\u{2029}'] {
            let rendered = render_memo(&format!("paid{hidden}bob"));
            assert!(!rendered.contains(hidden), "{rendered}");
            assert!(rendered.contains("\\u{"), "{rendered}");
        }
        assert_ne!(render_memo("paid\u{200b}bob"), render_memo("paidbob"));

        assert_eq!(render_memo("short"), "short");
        assert_eq!(render_memo(""), "");
    }

    /// The regression: the budget was sized from `COLUMNS` alone.
    ///
    /// `COLUMNS` is a shell parameter that bash and zsh maintain without
    /// exporting, so `std::env::var` fails in every child process and the
    /// budget was the 80-column default whatever terminal `balance` was
    /// printed into. A row was therefore always drawn at 80 columns, and on a
    /// 64-column terminal the last sixteen of them opened a fresh line at
    /// column 1 made entirely of printable ASCII the sender chose: the forged
    /// balance row the escaping exists to close, reached with no control
    /// character at all.
    ///
    /// The terminal is asked first now, and it wins: an exported `COLUMNS`
    /// left behind by a resized window cannot override the real width either.
    #[test]
    fn the_width_comes_from_the_terminal_before_the_environment() {
        assert_eq!(resolve_columns(Some(64), Some("80")), 64);
        assert_eq!(resolve_columns(Some(200), None), 200);
        // No terminal: a pipe, a file, or a `COLUMNS` a shell did export.
        assert_eq!(resolve_columns(None, Some("64")), 64);
        assert_eq!(resolve_columns(None, Some(" 132 ")), 132);
        assert_eq!(resolve_columns(None, None), DEFAULT_TERMINAL_COLUMNS);
        // A width of zero is what the call answers with for a pipe on some
        // systems, and neither source is trusted to be a number.
        assert_eq!(resolve_columns(Some(0), None), DEFAULT_TERMINAL_COLUMNS);
        assert_eq!(resolve_columns(None, Some("0")), DEFAULT_TERMINAL_COLUMNS);
        assert_eq!(
            resolve_columns(None, Some("wide")),
            DEFAULT_TERMINAL_COLUMNS
        );
    }

    /// The other half of the same regression: a floor is a budget that
    /// overrides the terminal.
    ///
    /// The old budget was `columns - prefix`, floored at sixteen, so a
    /// 40-column terminal was handed a 16-column memo column and a 60-column
    /// row. Nothing is floored now: a terminal that cannot hold the table and
    /// a usable memo column both says so, and `main.rs` puts the memo on a
    /// line of its own rather than letting the row wrap into one.
    #[test]
    fn a_terminal_too_narrow_for_the_table_gets_no_memo_column() {
        assert_eq!(budget_within(80, BALANCE_PREFIX_COLUMNS), Some(36));
        assert_eq!(budget_within(64, BALANCE_PREFIX_COLUMNS), Some(20));
        // Exactly the narrowest column worth drawing.
        assert_eq!(
            budget_within(
                BALANCE_PREFIX_COLUMNS + MIN_MEMO_COLUMNS,
                BALANCE_PREFIX_COLUMNS
            ),
            Some(MIN_MEMO_COLUMNS)
        );
        // One column narrower, and with the old floor this was `Some(16)`.
        assert_eq!(
            budget_within(
                BALANCE_PREFIX_COLUMNS + MIN_MEMO_COLUMNS - 1,
                BALANCE_PREFIX_COLUMNS
            ),
            None
        );
        assert_eq!(budget_within(40, BALANCE_PREFIX_COLUMNS), None);
        assert_eq!(budget_within(10, BALANCE_PREFIX_COLUMNS), None);
        // A wider prefix, which is what a leaf index past ten digits or a
        // value past twelve draws, takes its columns from the memo and not
        // from the terminal.
        assert_eq!(budget_within(80, BALANCE_PREFIX_COLUMNS + 4), Some(32));
    }

    /// The budget is the terminal's width less the table's own prefix, so the
    /// row fits whatever terminal it is printed into.
    #[test]
    fn the_budget_leaves_room_for_the_table_prefix() {
        assert_eq!(
            MEMO_DISPLAY_COLUMNS,
            DEFAULT_TERMINAL_COLUMNS - BALANCE_PREFIX_COLUMNS
        );
        // A narrow terminal still gets a usable column, and a wide one is not
        // truncated to the default.
        assert_eq!(render_memo_within("abcdefghij", 6), "abc...");
        assert_eq!(render_memo_within("abcdefghij", 10), "abcdefghij");
        assert!(render_memo_within(&"m".repeat(MEMO_BYTES), 200).len() == MEMO_BYTES);
    }
}
