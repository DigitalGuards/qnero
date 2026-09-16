import { useState, type ReactNode } from 'react';

import { cn } from '../../utils/cn';
import { Button } from './Button';

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
  lines = 10,
  expandable = false,
}: {
  value: string;
  className?: string;
  testId?: string;
  tone?: 'default' | 'secret';
  /** How many 16 px line boxes the value is given before it scrolls. */
  lines?: number;
  /**
   * Whether the box opens to the whole value on request.
   *
   * The receive screen collapses the address to three lines, because the code
   * above it is what a payment is made from and sixty-five lines of hex between
   * the code and the rest of the screen is a scroller inside the page scroll.
   * Nothing is hidden from a copy: `user-select: all` still takes all of it.
   */
  expandable?: boolean;
}): ReactNode {
  const [whole, setWhole] = useState(false);
  const shown = expandable && !whole ? 3 : lines;
  return (
    // Two boxes, and the split is the fix. Capped and scrollable rather than
    // 2600 characters tall, but a scroll container's bottom padding is
    // scrollable area that content paints into rather than a band that clips
    // it, so budgeting both paddings in one `max-height` cut the last visible
    // line horizontally through the middle of its glyphs and read as a
    // rendering fault rather than as a box that scrolls. The padding is on the
    // outer box and the cap is on the inner one, where it is a whole number of
    // 16 px line boxes and nothing else.
    //
    // The whole value stays in the box and `user-select: all` still takes all
    // of it in one gesture, so nothing is hidden from a copy or from a reader.
    <div
      className={cn(
        'elev-inset my-2 rounded-field border p-2',
        tone === 'secret' ? 'border-edge-strong bg-field' : 'border-edge bg-field',
        className,
      )}
    >
      <p
        data-testid={testId}
        className="mm-secret m-0 overflow-y-auto text-meta leading-4 text-ink"
        style={{ maxHeight: `${shown * 16}px` }}
      >
        {value}
      </p>
      {expandable && (
        <Button
          variant="quiet"
          // The label is 11 px and the target around it is a thumb's.
          className="mt-1 min-h-11 sm:min-h-0"
          data-testid="show-whole-address"
          onClick={() => {
            setWhole(!whole);
          }}
        >
          {whole ? 'Show less' : 'Show whole'}
        </Button>
      )}
    </div>
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
