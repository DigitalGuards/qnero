import { describe, expect, it } from 'vitest';

import {
  latestCoinbase,
  panelCount,
  rollingBlockTimeMs,
  settledNullifiers,
  settlementOf,
  summarise,
  type BlockState,
  type BlockSummary,
} from '../src/chain/blocks';
import type { EventRecord } from '../src/lib/events';
import { parseHeader } from '../src/lib/header';
import settlementFixture from './fixtures/events-settlement.json' with { type: 'json' };
import headerFixture from './fixtures/header-settlement.json' with { type: 'json' };

const events = settlementFixture.records as unknown as EventRecord[];

/** What a node below its state window answers, verbatim in shape. */
const DISCARDED =
  'State already discarded for 0x1be8d507e55a4fbcccacf450182ee5cd1db7e9afb6be0b9e88835fda10ed57c4';

function block(height: number, state: BlockState): BlockSummary {
  const header = parseHeader({ ...headerFixture.header, number: `0x${height.toString(16)}` });
  return summarise(headerFixture.hash, header, state);
}

/** The block as the node answers it when it still keeps the state. */
function read(height = 10): BlockSummary {
  return block(height, { events, timestampMs: 1_757_000_000_000, error: null });
}

/**
 * The same block on a node that has pruned the state under it. The body is
 * archived and the events are gone, which is exactly what `fetchBlockState`
 * returns: no events, no timestamp, and the node's message.
 */
function pruned(height = 10): BlockSummary {
  return block(height, { events: [], timestampMs: null, error: DISCARDED });
}

describe('a settlement read against one extrinsic', () => {
  it('reads the slots the block published', () => {
    const answer = settlementOf(read(), 2);
    expect(answer.kind).toBe('read');
    expect(answer.kind === 'read' ? answer.settlement?.slots : null).toHaveLength(1);
  });

  it('answers "nothing settled here" for an extrinsic in a block it did read', () => {
    const answer = settlementOf(read(), 0);
    expect(answer).toStrictEqual({ kind: 'read', settlement: null });
  });

  it('refuses to call an unread event log an extrinsic that settled nothing', () => {
    // The whole point. `decodeSettlements([])` is `[]` on a pruned block just
    // as it is on a timestamp inherent, so a page that looks only at the list
    // tells a reader that a spend which published two nullifiers and two
    // commitments settled no slot, permanently, on the one page whose subject
    // is what a settlement publishes.
    const answer = settlementOf(pruned(), 2);
    expect(answer.kind).toBe('not-read');
    expect(answer).not.toStrictEqual({ kind: 'read', settlement: null });
    expect(answer.kind === 'not-read' ? answer.error : '').toBe(DISCARDED);
  });

  it('keeps the two apart for the same extrinsic index in the same block', () => {
    expect(settlementOf(read(), 2).kind).toBe('read');
    expect(settlementOf(pruned(), 2).kind).toBe('not-read');
  });
});

describe('the rolling block time', () => {
  // Newest first, the order the home page holds them in.
  const window = (samples: readonly (number | null)[]): BlockSummary[] =>
    samples.map((timestampMs, offset) =>
      block(100 - offset, {
        events: [],
        timestampMs,
        error: timestampMs === null ? DISCARDED : null,
      }),
    );

  it('divides the span by the heights it spans, not by the samples that answered', () => {
    // Twelve consecutive blocks, 6 s apart, newest first.
    const full = window(Array.from({ length: 12 }, (_unused, offset) => 1_000_000 - offset * 6_000));
    expect(rollingBlockTimeMs(full)).toBe(6_000);
  });

  it('costs nothing in accuracy when two blocks in the window went unread', () => {
    const samples = Array.from({ length: 12 }, (_unused, offset) => 1_000_000 - offset * 6_000);
    const gapped = window(samples.map((value, offset) => (offset === 3 || offset === 7 ? null : value)));
    // Ten samples spanning eleven intervals. Dividing by the samples minus one
    // reported 7,333 ms here, a fifth high, and through the hash-rate estimate
    // a fifth low, under a note saying the window was twelve blocks.
    expect(rollingBlockTimeMs(gapped)).toBe(6_000);
  });

  it('reads the same whichever end of the window the gap is at', () => {
    const samples = Array.from({ length: 12 }, (_unused, offset) => 1_000_000 - offset * 6_000);
    const head = window(samples.map((value, offset) => (offset < 2 ? null : value)));
    const tail = window(samples.map((value, offset) => (offset > 9 ? null : value)));
    expect(rollingBlockTimeMs(head)).toBe(6_000);
    expect(rollingBlockTimeMs(tail)).toBe(6_000);
  });

  it('has nothing to say about one block, or about none', () => {
    expect(rollingBlockTimeMs([])).toBeNull();
    expect(rollingBlockTimeMs(window([1_000_000]))).toBeNull();
    expect(rollingBlockTimeMs(window([1_000_000, null]))).toBeNull();
  });

  it('leaves genesis out, because a zero timestamp is not a time', () => {
    const genesis = block(0, { events: [], timestampMs: 0, error: null });
    const first = block(1, { events: [], timestampMs: 1_000_000, error: null });
    const second = block(2, { events: [], timestampMs: 1_006_000, error: null });
    expect(rollingBlockTimeMs([second, first, genesis])).toBe(6_000);
  });
});

describe('what the newest block says about its coinbase', () => {
  it('names the note when a state read answered and held one', () => {
    const answer = latestCoinbase('ready', [read()]);
    expect(answer.kind).toBe('minted');
    expect(answer.kind === 'minted' ? answer.note.leafIndex : null).toBe(12);
  });

  it('claims the absence only when a read that answered held no coinbase', () => {
    const empty = block(10, { events: [], timestampMs: 1_000_000, error: null });
    expect(latestCoinbase('ready', [empty])).toStrictEqual({ kind: 'none' });
  });

  it('says nothing about emission while the window is still being read', () => {
    expect(latestCoinbase('loading', [])).toStrictEqual({ kind: 'reading' });
  });

  it('says nothing about emission when the window read failed', () => {
    // One dropped socket during the twelve-block read is enough, and the note
    // stays on screen: "the newest block minted no note" is a checkable claim
    // about a block this page never opened.
    expect(latestCoinbase('error', [])).toStrictEqual({
      kind: 'unread',
      why: 'recent-read-failed',
    });
  });

  it('says nothing about emission when the newest block’s state was not kept', () => {
    expect(latestCoinbase('ready', [pruned()])).toStrictEqual({
      kind: 'unread',
      why: 'state-not-kept',
    });
  });
});

/* -- what a count is allowed to say ------------------------------------ */

/** One settled slot, with the two nullifiers a caller names. */
function settling(height: number, nullifiers: readonly string[]): BlockSummary {
  const base = block(height, { events: [], timestampMs: 1_000_000, error: null });
  const output = { leafIndex: 0, commitment: '0xcc', ciphertextBytes: 1792 };
  return {
    ...base,
    settlements: nullifiers.map((nullifier, index) => ({
      extrinsicIndex: index + 2,
      segments: 1,
      declaredSlots: 1,
      feePlanck: 0n,
      authorFeePlanck: 0n,
      slots: [{ nullifiers: [`${nullifier}a`, `${nullifier}b`], outputs: [output, output] }],
    })),
  };
}

describe('a panel title over an event log that did not answer', () => {
  it('counts what the block published when the state answered', () => {
    expect(panelCount([], null)).toBe('(0)');
    expect(panelCount([1, 2, 3], null)).toBe('(3)');
    expect(panelCount(Array.from({ length: 1234 }, () => 0), null)).toBe('(1,234)');
  });

  it('prints no count at all over an unread one', () => {
    // The whole point. `decodeSettlements([])` is the empty list on a block the
    // node kept no state for just as it is on a block that settled nothing, so
    // a title built from the list length reads "Settlements (0)" over a body
    // that says the read failed, and the title is the half a reader believes.
    expect(panelCount([], DISCARDED)).toBe('(not counted)');
    expect(panelCount([], DISCARDED)).not.toBe('(0)');
  });
});

describe('the settled-nullifier figure', () => {
  const walked = (count: number, capped = false) => ({ count, capped });

  it('adds the window to the walk when every block above the baseline answered', () => {
    const settled = settledNullifiers({
      baseline: walked(4),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 12,
      window: 'ready',
      blocks: [settling(12, ['0x01']), settling(11, ['0x02']), settling(10, ['0x03'])],
    });
    // The baseline block's own settlement is already inside the walk, so only
    // the two blocks above it are added, at two nullifiers each.
    expect(settled).toStrictEqual({
      kind: 'counted',
      count: 8,
      capped: false,
      unreadBlocks: 0,
    });
  });

  it('counts one nullifier once however many blocks in the window carry it', () => {
    const settled = settledNullifiers({
      baseline: walked(0),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 12,
      window: 'ready',
      blocks: [settling(12, ['0x01']), settling(11, ['0x01'])],
    });
    expect(settled.kind === 'counted' ? settled.count : null).toBe(2);
  });

  it('marks the figure and names the blocks whose state did not answer', () => {
    // The regression. A block in the window that the node kept no state for
    // decodes to no settlements at all, so adding the window blindly drops
    // every nullifier that block settled and prints the short number as a
    // total, with nothing on the page saying a block went unread.
    const settled = settledNullifiers({
      baseline: walked(4),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 12,
      window: 'ready',
      blocks: [settling(12, ['0x01']), pruned(11)],
    });
    expect(settled).toStrictEqual({
      kind: 'counted',
      count: 6,
      capped: false,
      unreadBlocks: 1,
    });
    expect(settled.kind === 'counted' ? settled.unreadBlocks : null).not.toBe(0);
  });

  it('counts a height the window never produced a block for as unread too', () => {
    // `fetchRecent` drops a height the node answered no hash for. The
    // shortfall is then in the window's own length, and every block it did
    // return answered for its state.
    const settled = settledNullifiers({
      baseline: walked(4),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 13,
      window: 'ready',
      blocks: [settling(13, ['0x01'])],
    });
    expect(settled).toStrictEqual({
      kind: 'counted',
      count: 6,
      capped: false,
      unreadBlocks: 2,
    });
  });

  it('leaves the count of unread blocks unknown when the window read failed', () => {
    const settled = settledNullifiers({
      baseline: walked(4),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 12,
      window: 'error',
      blocks: [],
    });
    expect(settled).toStrictEqual({
      kind: 'counted',
      count: 4,
      capped: false,
      unreadBlocks: null,
    });
  });

  it('carries the walk’s own page-budget floor through', () => {
    const settled = settledNullifiers({
      baseline: walked(25_000, true),
      baselineError: null,
      baselineNumber: 10,
      headNumber: 10,
      window: 'ready',
      blocks: [settling(10, ['0x01'])],
    });
    expect(settled).toStrictEqual({
      kind: 'counted',
      count: 25_000,
      capped: true,
      unreadBlocks: 0,
    });
  });

  it('has no count to mark when the walk itself did not answer', () => {
    expect(
      settledNullifiers({
        baseline: null,
        baselineError: DISCARDED,
        baselineNumber: 10,
        headNumber: 12,
        window: 'ready',
        blocks: [settling(12, ['0x01'])],
      }),
    ).toStrictEqual({ kind: 'not-counted', why: DISCARDED });
  });

  it('says nothing while either half is still being read', () => {
    const pending = {
      baselineError: null,
      baselineNumber: 10,
      headNumber: 12,
      blocks: [],
    } as const;
    expect(
      settledNullifiers({ ...pending, baseline: null, window: 'ready' }),
    ).toStrictEqual({ kind: 'counting' });
    expect(
      settledNullifiers({ ...pending, baseline: walked(4), window: 'loading' }),
    ).toStrictEqual({ kind: 'counting' });
  });
});
