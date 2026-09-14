import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A long value shown whole: an address, a miner key, a seed.
 *
 * Whole rather than shortened, and selectable in one gesture. A Qnero address
 * carries an ML-KEM-1024 encapsulation key, so there is no short form and
 * there is no checksummed prefix that means anything on its own: showing the
 * first and last few characters would invite comparing two addresses by their
 * ends, which is exactly the comparison an attacker can win.
 *
 * That argument is about a value being used: an address being paid, a key
 * being copied into a node's environment. A value being recognised is
 * [`Hash`]'s job, and the lock screen uses that one: nobody compares
 * addresses to work out which wallet this browser holds.
 *
 * `tone="secret"` is the stronger border and nothing warmer. The warm hue in
 * this palette belongs to the one action a screen is for: see `tokens.css`.
 */
export function Address({
  value,
  className,
  testId,
  tone = 'default',
}: {
  value: string;
  className?: string;
  testId?: string;
  tone?: 'default' | 'secret';
}): ReactNode {
  return (
    <p
      data-testid={testId}
      className={cn(
        // Capped and scrollable rather than 2600 characters tall. The whole
        // value stays in the box and `user-select: all` still takes all of it
        // in one gesture, so nothing is hidden from a copy or from a reader.
        //
        // The cap is a whole number of line boxes: ten 16 px lines plus the
        // 8 px padding on each side plus the two borders. `max-h-44` is 176 px,
        // which leaves 158 px of content box, which is 9.875 lines, so every
        // long value ended on a row of glyphs sliced at 87.5% of its height
        // and read as a rendering fault rather than as a box that scrolls.
        'mm-secret elev-inset my-2 max-h-[calc(10*16px+16px+2px)] overflow-y-auto rounded-field',
        'border p-2 text-meta leading-4',
        tone === 'secret'
          ? 'border-edge-strong bg-field text-ink'
          : 'border-edge bg-field text-ink',
        className,
      )}
    >
      {value}
    </p>
  );
}

/** A hash, shortened, with the whole value one hover away. */
export function Hash({
  value,
  head = 10,
  tail = 8,
}: {
  value: string;
  head?: number;
  tail?: number;
}): ReactNode {
  const body = value.replace(/^0x/, '');
  const short = body.length <= head + tail + 1 ? body : `${body.slice(0, head)}…${body.slice(-tail)}`;
  return (
    <span className="font-mono text-meta" title={body}>
      {short}
    </span>
  );
}

/**
 * A note's state.
 *
 * Four states rather than two, because "unspent" and "spent" leave out the two
 * that matter most when something has gone wrong: a note this wallet wrote and
 * the chain has not confirmed, and a note whose leaf a reorg took away, which
 * is held with its secrets and counted in no balance.
 */
export function Pill({
  state,
}: {
  state: 'unspent' | 'spent' | 'pending' | 'off chain';
}): ReactNode {
  const tone =
    state === 'unspent'
      ? 'border-positive/40 text-positive'
      : state === 'spent'
        ? 'border-edge text-muted'
        : state === 'pending'
          // Brightness rather than hue: the warm band is the accent's.
          ? 'border-edge-strong text-ink'
          : 'border-destructive/45 text-destructive';
  return (
    <span
      className={cn(
        'inline-block rounded-control border px-1.5 py-px text-label uppercase tracking-label',
        tone,
      )}
    >
      {state}
    </span>
  );
}
