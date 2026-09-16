/**
 * When the page is still reading, and when it has something to show.
 *
 * The socket opening and the first head arriving are one wait to a reader:
 * the page is a skeleton through both. The status flipped to live the moment
 * the socket answered, so the progress bar and the sentence in the header's
 * slot came off a screen that still carried no figure, and the slot sat empty
 * for as long as the head seed took. On a public node that is a round trip.
 */

import { describe, expect, it } from 'vitest';

import { isReading } from '../src/app/chainContext';
import type { Head } from '../src/app/chainContext';

const head: Head = {
  hash: '0x2e3139d53b05f7c78e6d1ff73748608690877965a294f2110f2705b2b6773f37',
  header: {
    number: 27,
    parentHash: `0x${'11'.repeat(32)}`,
    stateRoot: `0x${'22'.repeat(32)}`,
    extrinsicsRoot: `0x${'33'.repeat(32)}`,
    zkTreeRoot: `0x${'44'.repeat(32)}`,
    digestItems: [],
    authorLabel: null,
    seal: null,
  },
};

describe('the reading state', () => {
  it('holds while the socket is opening', () => {
    expect(isReading({ status: 'connecting', head: null })).toBe(true);
  });

  it('holds after the socket answers, until the first head lands', () => {
    expect(isReading({ status: 'live', head: null })).toBe(true);
  });

  it('ends when there is a height to print', () => {
    expect(isReading({ status: 'live', head })).toBe(false);
  });

  it('is over on a failure, which is a page with its own heading and button', () => {
    expect(isReading({ status: 'failed', head: null })).toBe(false);
  });

  it('is over on a dropped socket, which the header says in its own words', () => {
    expect(isReading({ status: 'offline', head: null })).toBe(false);
    expect(isReading({ status: 'offline', head })).toBe(false);
  });
});
