/**
 * Memos, on the way to a screen.
 *
 * A memo is remote input: whoever paid this wallet chose every byte of it. The
 * CLI escapes one because a terminal takes control sequences; a browser does
 * not, and it has the siblings instead, which are worse in one way each:
 *
 * - U+200B and U+200D are zero width, so two different memos render
 *   identically and a reader cannot tell a payment from an impostor of it.
 * - The bidi controls (U+202A to U+202E, U+2066 to U+2069) reorder a line with
 *   no visible character at all, so a memo can rearrange the text around it.
 * - A combining mark applied to nothing stacks onto whatever the renderer put
 *   before it, which is the wallet's own label.
 *
 * So everything outside printable ASCII is escaped to `\u{..}` before it
 * reaches the DOM, the same rule `crates/qnero-wallet/src/memo.rs` applies. The
 * column arithmetic that module carries does not come with it: `TIOCGWINSZ` is
 * a terminal question and CSS answers the browser's version.
 *
 * The element that holds the result is `unicode-bidi: isolate` as well
 * (`app.css`), because escaping is a property of this function and isolation
 * is a property of the box, and a memo rendered anywhere else should still not
 * reorder its neighbours.
 */

/** The printable ASCII range, space through tilde. */
const PRINTABLE_LOW = 0x20;
const PRINTABLE_HIGH = 0x7e;

/**
 * A memo as it may be shown.
 *
 * Code points rather than UTF-16 units, so an emoji escapes as one `\u{...}`
 * rather than as two halves of a surrogate pair that mean nothing to a reader.
 */
export function escapeMemo(memo: string): string {
  let out = '';
  for (const character of memo) {
    const code = character.codePointAt(0);
    if (code !== undefined && code >= PRINTABLE_LOW && code <= PRINTABLE_HIGH) {
      out += character;
      continue;
    }
    out += `\\u{${(code ?? 0).toString(16)}}`;
  }
  return out;
}

/**
 * The escaped memo, cut to `budget` characters with an ellipsis.
 *
 * The cut happens after escaping, so a budget is a count of characters that
 * will actually be drawn rather than of bytes that may each become six.
 */
export function renderMemo(memo: string, budget = 120): string {
  const escaped = escapeMemo(memo);
  if (escaped.length <= budget) {
    return escaped;
  }
  return `${escaped.slice(0, Math.max(0, budget - 1))}…`;
}

/**
 * Whether a memo is only the characters that survive the escape unchanged.
 *
 * What the send screen tells somebody typing: a memo with anything else in it
 * still sends and still decrypts, and it will be shown escaped at the other
 * end, so the wallet says so before it is sent rather than after.
 */
export function memoIsPlainAscii(memo: string): boolean {
  return escapeMemo(memo) === memo;
}
