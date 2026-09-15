/**
 * The fee floor, the memo pad and note selection.
 *
 * Every case here has a counterpart in `crates/qnero-wallet/src/fee.rs` or
 * `select.rs`, on the same fixture, because the two implementations have to
 * agree about what a spend costs: a browser that computed a lower floor would
 * pay for a proof and read `PayloadUnderpaid`, and one that computed a
 * different pad would publish its own ciphertext length.
 */

import { describe, expect, it } from 'vitest';

import type { ShieldedConstants } from '../src/chain/api';
import {
  ensureCiphertextFits,
  ensureMemoPadFits,
  largestSeparatingPad,
  memoPadSeparationWarning,
  slotFeeFloor,
  submissionFeeFloor,
} from '../src/wallet/fee';
import { collapseRows, MAX_INPUTS, reachableTotal, selectNotes, spendable } from '../src/wallet/select';
import type { NoteRow, NoteSecret, StoredNote } from '../src/wallet/model';

/** The M4 runtime's four constants. */
function runtime(): ShieldedConstants {
  return {
    blockHashWindow: 256,
    minLeafFee: 1n,
    ciphertextBytesPerFeeQuantum: 512,
    maxCiphertextBytes: 2048,
  };
}

/** What `qnero-notes` pins: a fixed ciphertext, a 61-byte pad. */
const FIXED = 1731;
const MEMO = 61;
const PADDED = FIXED + MEMO;

describe('the fee floor', () => {
  it('matches the two endpoints the circuit document pins', () => {
    // Two real ciphertexts (3462 bytes) pay eight steps of fee; two padded to the
    // cap (4096) pay nine.
    expect(slotFeeFloor(runtime(), FIXED, FIXED)).toBe(8n);
    expect(slotFeeFloor(runtime(), 2048, 2048)).toBe(9n);
  });

  it('rounds a started fee bucket up to a whole one', () => {
    expect(slotFeeFloor(runtime(), 1, 0)).toBe(2n);
    expect(slotFeeFloor(runtime(), 512, 0)).toBe(2n);
    expect(slotFeeFloor(runtime(), 513, 0)).toBe(3n);
    expect(slotFeeFloor(runtime(), 0, 0)).toBe(1n);
  });

  it('equals the whole-submission floor for one transfer', () => {
    const slot = slotFeeFloor(runtime(), PADDED, PADDED);
    expect(submissionFeeFloor(runtime(), 1n, BigInt(2 * PADDED))).toBe(slot);
  });

  it('does not divide by zero on a runtime that declares a zero divisor', () => {
    // The pallet clamps the divisor to one for the same reason: a node is free
    // to answer whatever it likes for a constant, and the arithmetic would
    // fail before any error path ran.
    const broken = { ...runtime(), ciphertextBytesPerFeeQuantum: 0 };
    expect(slotFeeFloor(broken, FIXED, FIXED)).toBe(1n + 3462n);
    expect(submissionFeeFloor(broken, 1n, 3462n)).toBe(1n + 3462n);
  });
});

describe('the memo pad', () => {
  it('keeps this wallet\'s own pair a fee bucket below a pair padded to the cap', () => {
    const sent = slotFeeFloor(runtime(), PADDED, PADDED);
    const capped = slotFeeFloor(runtime(), 2048, 2048);
    expect(sent).toBeLessThan(capped);
  });

  it('is the largest pad the M4 runtime separates', () => {
    expect(largestSeparatingPad(runtime(), FIXED)).toBe(MEMO);
    // One byte more and the separation is gone, which is what "largest" means.
    expect(slotFeeFloor(runtime(), PADDED + 1, PADDED + 1)).toBe(
      slotFeeFloor(runtime(), 2048, 2048),
    );
  });

  it('refuses a runtime whose cap a padded ciphertext does not fit, naming the pad', () => {
    const narrow = { ...runtime(), maxCiphertextBytes: 1780 };
    expect(() => {
      ensureMemoPadFits(narrow, PADDED, MEMO, FIXED);
    }).toThrow(/1780/);
    // The advice is the pad, because no memo length reaches this branch.
    expect(() => {
      ensureMemoPadFits(narrow, PADDED, MEMO, FIXED);
    }).toThrow(/pad is what has to shrink/);
  });

  it('warns and still sends when a runtime merges the two fee buckets', () => {
    expect(memoPadSeparationWarning(runtime(), PADDED, MEMO, FIXED)).toBeNull();

    // The divisor doubled, the cap untouched. The cap check still passes,
    // because 1792 is under 2048, and the separation the pad was chosen for is
    // gone: a settler can pad both outputs to the cap and pay what an honest
    // spend pays.
    const widened = { ...runtime(), ciphertextBytesPerFeeQuantum: 1024 };
    expect(slotFeeFloor(widened, PADDED, PADDED)).toBe(slotFeeFloor(widened, 2048, 2048));
    const warning = memoPadSeparationWarning(widened, PADDED, MEMO, FIXED);
    expect(warning).toMatch(/prices nothing/);
    expect(warning).toMatch(/1024/);
    expect(warning).toMatch(/divisor is what has to come down/);
    // A chain-wide property is not this spend's refusal.
    expect(() => {
      ensureMemoPadFits(widened, PADDED, MEMO, FIXED);
    }).not.toThrow();
  });

  it('names the smaller pad when one would restore the separation', () => {
    // At 1160 bytes to the fee bucket a pair may reach 3480 bytes, so each
    // ciphertext may reach 1740 and the pad is 9.
    const slightly = { ...runtime(), ciphertextBytesPerFeeQuantum: 1160 };
    expect(largestSeparatingPad(slightly, FIXED)).toBe(9);
    expect(memoPadSeparationWarning(slightly, PADDED, MEMO, FIXED)).toMatch(/down to 9 bytes/);
  });

  it('refuses an oversized ciphertext before proving', () => {
    expect(() => {
      ensureCiphertextFits(runtime(), 2048, MEMO, 'payment');
    }).not.toThrow();
    expect(() => {
      ensureCiphertextFits(runtime(), 2049, MEMO, 'payment');
    }).toThrow(/caps one at 2048/);
  });
});

function note(value: number, leafIndex: number, extra: Partial<StoredNote> = {}): StoredNote {
  return {
    commitment: `cm${leafIndex}`,
    leafIndex,
    blockNumber: 1,
    value: String(value),
    origin: 'transfer',
    spent: false,
    spentSeenAtBlock: null,
    onChain: true,
    secret: { v: 1, iv: '', ct: '' },
    ...extra,
  };
}

describe('note selection', () => {
  it('takes one note when it covers the target', () => {
    const chosen = selectNotes([note(1000, 0), note(400, 1)], 300n);
    expect(chosen.notes).toHaveLength(1);
    expect(chosen.notes[0]?.value).toBe('1000');
  });

  it('adds a second only when the first falls short', () => {
    const chosen = selectNotes([note(200, 0), note(400, 1), note(50, 2)], 500n);
    expect(chosen.notes.map((entry) => entry.value)).toEqual(['400', '200']);
  });

  it('refuses a balance spread over three notes, with the reachable total', () => {
    expect(() => selectNotes([note(100, 0), note(100, 1), note(100, 2)], 250n)).toThrow(
      /reach 2\.00 QNR/,
    );
    expect(() => selectNotes([note(100, 0), note(100, 1), note(100, 2)], 250n)).toThrow(
      /3\.00 QNR held in total/,
    );
  });

  it('counts the fee as part of the target', () => {
    expect(() => selectNotes([note(300, 0)], 300n)).not.toThrow();
    expect(() => selectNotes([note(300, 0)], 301n)).toThrow();
  });

  it('breaks ties on the lowest leaf index so a retry proves the same leaf', () => {
    const chosen = selectNotes([note(100, 7), note(100, 3)], 100n);
    expect(chosen.notes[0]?.leafIndex).toBe(3);
  });

  it('says so when the wallet holds nothing', () => {
    expect(() => selectNotes([], 1n)).toThrow(/no unspent notes/);
  });

  it('reaches at most two notes, which is what a leaf has slots for', () => {
    expect(MAX_INPUTS).toBe(2);
    expect(reachableTotal([note(10, 0), note(20, 1), note(30, 2)])).toBe(50n);
  });
});

describe('the spendable set', () => {
  const nullifierOf = (stored: StoredNote): string =>
    stored.commitment === 'cm0' || stored.commitment === 'cm1' ? 'shared' : stored.commitment;

  it('holds one member per nullifier, and it is the larger one', () => {
    // A sender picks each note's randomness, so a repeated pair is two notes
    // sharing one nullifier of which at most one can ever settle. Both are
    // held; the set is counted once, at the member a spend would use.
    const candidates = spendable([note(100, 0), note(400, 1), note(50, 2)], nullifierOf);
    expect(candidates.map((entry) => entry.value).sort()).toEqual(['400', '50']);
  });

  it('breaks a conflict tie on the lowest leaf index', () => {
    const candidates = spendable([note(100, 1), note(100, 0)], nullifierOf);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.leafIndex).toBe(0);
  });

  it('leaves out a spent note and one whose leaf a reorg took away', () => {
    const notes = [
      note(100, 5, { spent: true }),
      note(200, 6, { onChain: false }),
      note(300, 7),
    ];
    const candidates = spendable(notes, (stored) => stored.commitment);
    expect(candidates.map((entry) => entry.value)).toEqual(['300']);
  });
});

/**
 * The table under the headings, collapsed by the same rule as the headings.
 *
 * The balance counts a conflict set once, at the member a spend would use, and
 * the notes table printed every member with its own amount. A reader adding
 * the rows got a number the chain will never back, under a heading that had
 * already collapsed. `crates/qnero-wallet/src/store.rs` collapses its own rows
 * for this exact complaint.
 */
describe('the notes table', () => {
  function row(note: StoredNote, nullifier: string | null, members = 1): NoteRow {
    const secret: NoteSecret | null =
      nullifier === null ? null : { rho: '', r: '', nullifier, memo: '' };
    return { note, secret, conflictMembers: members };
  }

  it('prints one row per nullifier, at the member a spend would use', () => {
    const rows = collapseRows([
      row(note(100, 0), 'shared', 2),
      row(note(400, 1), 'shared', 2),
      row(note(50, 2), 'own'),
    ]);
    expect(rows.map((entry) => entry.note.value)).toEqual(['400', '50']);
    expect(rows[0]?.conflictMembers).toBe(2);
  });

  it('keeps the member a spend could use over a larger one it could not', () => {
    // The balance's unspent heading counts only what a spend can reach, so a
    // table whose surviving row was the spent member would print an amount
    // that is in no heading at all.
    const rows = collapseRows([
      row(note(900, 0, { spent: true }), 'shared', 2),
      row(note(100, 1), 'shared', 2),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.note.value).toBe('100');
  });

  it('breaks a tie on the lowest leaf index, as selection does', () => {
    const rows = collapseRows([row(note(100, 3), 'shared', 2), row(note(100, 1), 'shared', 2)]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.note.leafIndex).toBe(1);
  });

  it('collapses nothing while the wallet is locked, because no nullifier opens', () => {
    const rows = collapseRows([row(note(100, 0), null), row(note(400, 1), null)]);
    expect(rows).toHaveLength(2);
  });

  it('sums to what the unspent heading says, which is the whole complaint', () => {
    const rows = collapseRows([
      row(note(100, 0), 'shared', 2),
      row(note(400, 1), 'shared', 2),
      row(note(50, 2), 'own'),
    ]);
    const table = rows
      .filter((entry) => entry.note.onChain && !entry.note.spent)
      .reduce((sum, entry) => sum + BigInt(entry.note.value), 0n);
    const heading = spendable(
      rows.map((entry) => entry.note),
      (stored) => (stored.commitment === 'cm0' || stored.commitment === 'cm1' ? 'shared' : stored.commitment),
    ).reduce((sum, stored) => sum + BigInt(stored.value), 0n);
    expect(table).toBe(heading);
  });
});
