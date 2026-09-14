/**
 * Memos on the way to a screen.
 *
 * A memo is remote input: whoever paid this wallet chose every byte of it. The
 * command-line wallet escapes one because a terminal takes control sequences,
 * and a browser has the siblings, which are worse in one way each: a
 * zero-width character makes two different memos render identically, a bidi
 * control reorders the line around it with nothing visible, and a combining
 * mark applied to nothing stacks onto whatever the renderer drew before it,
 * which is the wallet's own label.
 */

import { describe, expect, it } from 'vitest';

import { escapeMemo, memoIsPlainAscii, renderMemo } from '../src/lib/memo';

describe('escaping a memo', () => {
  it('leaves printable ASCII alone', () => {
    const memo = 'rent, March. Thanks! ~#$%^&*()_+ 12345';
    expect(escapeMemo(memo)).toBe(memo);
    expect(memoIsPlainAscii(memo)).toBe(true);
  });

  it('escapes a zero-width character, which two memos could otherwise share', () => {
    expect(escapeMemo('pay​me')).toBe('pay\\u{200b}me');
    expect(memoIsPlainAscii('pay​me')).toBe(false);
  });

  it('escapes the bidi controls, which reorder a line with nothing drawn', () => {
    for (const control of ['‪', '‫', '‬', '‭', '‮', '⁦', '⁩']) {
      expect(escapeMemo(`a${control}b`)).toBe(
        `a\\u{${control.codePointAt(0)?.toString(16) ?? ''}}b`,
      );
    }
  });

  it('escapes a combining mark, which would stack onto the label beside it', () => {
    expect(escapeMemo('́')).toBe('\\u{301}');
  });

  it('escapes a newline, so a memo cannot forge a second line of interface', () => {
    expect(escapeMemo('paid\nin full')).toBe('paid\\u{a}in full');
  });

  it('escapes an emoji as one code point rather than two halves of a pair', () => {
    // U+1F600 is one code point and two UTF-16 units. Escaping the units
    // produces two surrogate escapes, which mean nothing to a reader.
    expect(escapeMemo('\u{1f600}')).toBe('\\u{1f600}');
  });
});

describe('rendering a memo into a cell', () => {
  it('leaves a short memo whole', () => {
    expect(renderMemo('lunch')).toBe('lunch');
  });

  it('cuts to the budget after escaping, so the budget counts drawn characters', () => {
    // Sixteen escaped code points are 96 characters, well past a budget of 20.
    const memo = '​'.repeat(16);
    const rendered = renderMemo(memo, 20);
    expect(rendered).toHaveLength(20);
    expect(rendered.endsWith('…')).toBe(true);
  });

  it('does not cut a memo that only looks long before escaping', () => {
    const memo = 'x'.repeat(120);
    expect(renderMemo(memo, 120)).toBe(memo);
  });
});
