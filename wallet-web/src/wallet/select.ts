/**
 * Choosing which notes to spend.
 *
 * The leaf circuit has exactly two input slots, so a spend reaches at most two
 * notes and the rest of a balance is unreachable in one transaction. Largest
 * first, because that is the selection that reaches the largest payment from a
 * given wallet and it keeps the note count falling rather than growing a tail
 * of dust a two-input circuit can never sweep.
 *
 * Ties break on the lowest leaf index. Two notes of equal value are otherwise
 * ordered by however the store was written, and a wallet that picked
 * differently on a retry would prove a different leaf and pay for a second
 * proof.
 *
 * This mirrors `crates/qnero-wallet/src/select.rs`, including the message,
 * because "consolidate first" is the only thing a person can do about it.
 */

import type { NoteRow, StoredNote } from './model';

/** Input slots in the leaf circuit. */
export const MAX_INPUTS = 2;

/**
 * The notes a spend may choose from.
 *
 * On chain, unspent, and one member per nullifier: a private batch constrains
 * its two nullifiers pairwise distinct, so two members of a conflict set in
 * one leaf is a proof that fails in circuit. The member a spend uses is the
 * largest, ties on the lowest leaf index, which is the same rule that counts
 * the set once in a balance.
 */
export function spendable(
  notes: readonly StoredNote[],
  nullifierOf: (note: StoredNote) => string,
): StoredNote[] {
  const best = new Map<string, StoredNote>();
  for (const note of notes) {
    if (note.spent || !note.onChain) {
      continue;
    }
    const nullifier = nullifierOf(note);
    const held = best.get(nullifier);
    if (held === undefined || beats(note, held)) {
      best.set(nullifier, note);
    }
  }
  return [...best.values()];
}

function beats(candidate: StoredNote, held: StoredNote): boolean {
  const a = BigInt(candidate.value);
  const b = BigInt(held.value);
  if (a !== b) {
    return a > b;
  }
  return candidate.leafIndex < held.leafIndex;
}

export interface Selection {
  notes: StoredNote[];
  total: bigint;
}

/**
 * Up to [`MAX_INPUTS`] notes covering `target`, largest first.
 *
 * `target` is the payment plus the fee: both leave the pool, and the balance
 * equation the circuit enforces is `inputs = outputs + fee`.
 */
export function selectNotes(candidates: readonly StoredNote[], target: bigint): Selection {
  const sorted = [...candidates].sort((a, b) => {
    const valueA = BigInt(a.value);
    const valueB = BigInt(b.value);
    if (valueA !== valueB) {
      return valueA > valueB ? -1 : 1;
    }
    return a.leafIndex - b.leafIndex;
  });

  const chosen: StoredNote[] = [];
  let total = 0n;
  for (const note of sorted.slice(0, MAX_INPUTS)) {
    chosen.push(note);
    total += BigInt(note.value);
    if (total >= target) {
      return { notes: chosen, total };
    }
  }

  if (sorted.length === 0) {
    throw new Error('this wallet holds no unspent notes');
  }
  const held = sorted.reduce((sum, note) => sum + BigInt(note.value), 0n);
  throw new Error(
    `this spend needs ${target} quanta and the ${chosen.length} largest of ${sorted.length} ` +
      `unspent notes reach ${total} (${held} held in total). A spend has ${MAX_INPUTS} input ` +
      'slots, so consolidate first: send yourself the largest notes to merge them.',
  );
}

/** What one spend can reach: the two largest spendable notes, and no more. */
export function reachableTotal(candidates: readonly StoredNote[]): bigint {
  return [...candidates]
    .sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : -1))
    .slice(0, MAX_INPUTS)
    .reduce((sum, note) => sum + BigInt(note.value), 0n);
}

/**
 * One row per nullifier, for a table a reader adds up.
 *
 * A sender chooses `rho` and `r`, so a repeated pair yields two notes sharing
 * one nullifier of which at most one can ever settle. Both are held, because
 * refusing the second on arrival decides by arrival order and the sender
 * controls that. The balance headings count the set once, at the member a
 * spend would use, and the table under them printed every member with its own
 * amount: a reader adding the rows got a number the chain will never back.
 *
 * The surviving member is the one a spend would choose, which is the rule
 * `spendable` uses and the rule `crates/qnero-wallet/src/store.rs` collapses
 * on: a member a spend could use outranks one it could not, then the larger
 * value, then the lower leaf index. The count of members stays on the row it
 * survives as, so the conflict is still visible.
 *
 * A locked wallet opens no secret, so the key falls back to the commitment and
 * nothing collapses. That is the same fallback the balance uses, and the two
 * agree in that state as well.
 */
export function collapseRows(rows: readonly NoteRow[]): NoteRow[] {
  const best = new Map<string, NoteRow>();
  for (const row of rows) {
    const key = row.secret?.nullifier ?? row.note.commitment;
    const held = best.get(key);
    if (held === undefined || outranksForDisplay(row.note, held.note)) {
      // A `Map` keeps the position a key was first inserted at, so re-setting
      // one keeps the table's order stable as the winner changes.
      best.set(key, row);
    }
  }
  return [...best.values()];
}

function outranksForDisplay(candidate: StoredNote, held: StoredNote): boolean {
  const candidateUsable = candidate.onChain && !candidate.spent;
  const heldUsable = held.onChain && !held.spent;
  if (candidateUsable !== heldUsable) {
    return candidateUsable;
  }
  return beats(candidate, held);
}
