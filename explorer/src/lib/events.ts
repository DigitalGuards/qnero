/**
 * Block events, normalised and decoded.
 *
 * Records arrive as `{ phase, section, method, fields }`, where the field
 * names come from the runtime's own metadata rather than from a compiled-in
 * position. That matters here: this runtime has changed event layouts inside
 * one `spec_version`, so a positional read is a decoder that goes quietly
 * wrong instead of loudly missing.
 */

import { decodeU512 } from './difficulty';

export type EventPhase =
  | { kind: 'applyExtrinsic'; index: number }
  | { kind: 'finalization' }
  | { kind: 'initialization' };

export interface EventRecord {
  phase: EventPhase;
  section: string;
  method: string;
  fields: Record<string, unknown>;
}

export function extrinsicIndexOf(phase: EventPhase): number | null {
  return phase.kind === 'applyExtrinsic' ? phase.index : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A chain integer as JSON: a number while it fits a safe integer, hex above that. */
export function asBigInt(value: unknown, what: string): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${what} is not a safe integer: ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    return BigInt(value);
  }
  throw new Error(`${what} is not an integer: ${JSON.stringify(value)}`);
}

export function asNumber(value: unknown, what: string): number {
  const big = asBigInt(value, what);
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${what} is larger than this explorer counts to: ${big}`);
  }
  return Number(big);
}

export function asHex(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new Error(`${what} is not a hex string: ${JSON.stringify(value)}`);
  }
  return value;
}

function field(record: EventRecord, name: string): unknown {
  if (!(name in record.fields)) {
    throw new Error(
      `${record.section}.${record.method} has no field ${name}; the runtime's layout moved`,
    );
  }
  return record.fields[name];
}

function pairOfHex(value: unknown, what: string): [string, string] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${what} is not a pair: ${JSON.stringify(value)}`);
  }
  return [asHex(value[0], `${what}[0]`), asHex(value[1], `${what}[1]`)];
}

function pairOfNumbers(value: unknown, what: string): [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${what} is not a pair: ${JSON.stringify(value)}`);
  }
  return [asNumber(value[0], `${what}[0]`), asNumber(value[1], `${what}[1]`)];
}

export function eventsFor(records: readonly EventRecord[], section: string, method: string): EventRecord[] {
  return records.filter((record) => record.section === section && record.method === method);
}

/* -- coinbase ---------------------------------------------------------- */

export interface CoinbaseNote {
  blockNumber: number;
  leafIndex: number;
  /** The note's inner hash, published in the clear and still opaque: only a matching `cvk` opens it. */
  inner: string;
  valuePlanck: bigint;
  hasCiphertext: boolean;
  /** `MiningRewards::CoinbaseCredited`: emission plus transparent fees, before the settled-fee share. */
  creditedPlanck: bigint | null;
  /** `Shielded::AuthorFeeAccrued` summed over the block: the author's share of settled fees. */
  authorFeePlanck: bigint;
}

export function decodeCoinbase(records: readonly EventRecord[]): CoinbaseNote | null {
  const minted = eventsFor(records, 'shielded', 'CoinbaseMinted')[0];
  if (minted === undefined) {
    return null;
  }
  const credited = eventsFor(records, 'miningRewards', 'CoinbaseCredited')[0];
  const authorFeePlanck = eventsFor(records, 'shielded', 'AuthorFeeAccrued').reduce(
    (total, record) => total + asBigInt(field(record, 'amount'), 'AuthorFeeAccrued.amount'),
    0n,
  );
  return {
    blockNumber: asNumber(field(minted, 'block_number'), 'CoinbaseMinted.block_number'),
    leafIndex: asNumber(field(minted, 'leaf_index'), 'CoinbaseMinted.leaf_index'),
    inner: asHex(field(minted, 'inner'), 'CoinbaseMinted.inner'),
    valuePlanck: asBigInt(field(minted, 'value'), 'CoinbaseMinted.value'),
    hasCiphertext: field(minted, 'has_ciphertext') === true,
    creditedPlanck:
      credited === undefined
        ? null
        : asBigInt(field(credited, 'amount'), 'CoinbaseCredited.amount'),
    authorFeePlanck,
  };
}

/* -- settlements ------------------------------------------------------- */

export interface SettlementOutput {
  leafIndex: number;
  commitment: string;
  /**
   * How many bytes of note ciphertext this output published.
   *
   * The length and not the payload. `SlotSettled` publishes the two lengths
   * and the payloads themselves ride in the block body, where the settlement
   * extrinsic that appended the leaves carries them.
   */
  ciphertextBytes: number;
}

export interface SettlementSlot {
  /**
   * The two nullifiers this slot settled, one per input position. A position
   * holding a real input spends one note and a position holding a dummy
   * publishes a nullifier over no note, so a slot spends one note or two.
   */
  nullifiers: [string, string];
  /** The two leaves this slot appended, an unordered pair: which one is the change is not on chain. */
  outputs: [SettlementOutput, SettlementOutput];
}

export interface Settlement {
  extrinsicIndex: number | null;
  /** `BatchSettled.segments`: circuit segments in the submission. */
  segments: number;
  /** `BatchSettled.slots`: real leaf slots that settled. */
  declaredSlots: number;
  feePlanck: bigint;
  authorFeePlanck: bigint;
  slots: SettlementSlot[];
}

export function decodeSettlements(records: readonly EventRecord[]): Settlement[] {
  const byExtrinsic = new Map<number | null, Settlement>();
  const settlementFor = (phase: EventPhase): Settlement => {
    const index = extrinsicIndexOf(phase);
    const existing = byExtrinsic.get(index);
    if (existing !== undefined) {
      return existing;
    }
    const fresh: Settlement = {
      extrinsicIndex: index,
      segments: 0,
      declaredSlots: 0,
      feePlanck: 0n,
      authorFeePlanck: 0n,
      slots: [],
    };
    byExtrinsic.set(index, fresh);
    return fresh;
  };

  for (const record of records) {
    if (record.section !== 'shielded') {
      continue;
    }
    if (record.method === 'SlotSettled') {
      const nullifiers = pairOfHex(field(record, 'nullifiers'), 'SlotSettled.nullifiers');
      const commitments = pairOfHex(field(record, 'commitments'), 'SlotSettled.commitments');
      const leafIndices = pairOfNumbers(field(record, 'leaf_indices'), 'SlotSettled.leaf_indices');
      const ciphertextBytes = pairOfNumbers(
        field(record, 'ciphertext_bytes'),
        'SlotSettled.ciphertext_bytes',
      );
      settlementFor(record.phase).slots.push({
        nullifiers,
        outputs: [
          {
            leafIndex: leafIndices[0],
            commitment: commitments[0],
            ciphertextBytes: ciphertextBytes[0],
          },
          {
            leafIndex: leafIndices[1],
            commitment: commitments[1],
            ciphertextBytes: ciphertextBytes[1],
          },
        ],
      });
    } else if (record.method === 'BatchSettled') {
      const settlement = settlementFor(record.phase);
      settlement.segments = asNumber(field(record, 'segments'), 'BatchSettled.segments');
      settlement.declaredSlots = asNumber(field(record, 'slots'), 'BatchSettled.slots');
      settlement.feePlanck = asBigInt(field(record, 'fee'), 'BatchSettled.fee');
    } else if (record.method === 'AuthorFeeAccrued') {
      const settlement = settlementFor(record.phase);
      settlement.authorFeePlanck += asBigInt(field(record, 'amount'), 'AuthorFeeAccrued.amount');
    }
  }

  // A block's coinbase accrues an author fee in the finalization phase with no
  // settlement beside it, and that share belongs to the coinbase.
  return [...byExtrinsic.values()].filter((settlement) => settlement.slots.length > 0);
}

/* -- shield entries ---------------------------------------------------- */

export interface ShieldEntry {
  extrinsicIndex: number | null;
  /** The payer's account. A shield is a signed extrinsic, so this is on chain beside the amount. */
  who: string;
  valuePlanck: bigint;
  commitment: string;
  leafIndex: number;
  entryIndex: number;
  /** How many bytes of note ciphertext this shield published. The payload is in the block body. */
  ciphertextBytes: number;
}

export function decodeShieldEntries(records: readonly EventRecord[]): ShieldEntry[] {
  return eventsFor(records, 'shielded', 'Shielded').map((record) => ({
    extrinsicIndex: extrinsicIndexOf(record.phase),
    who: String(field(record, 'who')),
    valuePlanck: asBigInt(field(record, 'value'), 'Shielded.value'),
    commitment: asHex(field(record, 'commitment'), 'Shielded.commitment'),
    leafIndex: asNumber(field(record, 'leaf_index'), 'Shielded.leaf_index'),
    entryIndex: asNumber(field(record, 'entry_index'), 'Shielded.entry_index'),
    ciphertextBytes: asNumber(field(record, 'ciphertext_bytes'), 'Shielded.ciphertext_bytes'),
  }));
}

/* -- failures ---------------------------------------------------------- */

export interface DispatchFailure {
  extrinsicIndex: number | null;
  /** The outer `DispatchError` variant: `callFiltered`, `module`, `token` and so on. */
  kind: string;
  detail: string | null;
  /** Refused by `QneroCallFilter`: a valid extrinsic that entered the block, paid its fee and then failed. */
  filtered: boolean;
}

export function decodeFailures(records: readonly EventRecord[]): DispatchFailure[] {
  return eventsFor(records, 'system', 'ExtrinsicFailed').map((record) => {
    const error = field(record, 'dispatch_error');
    let kind = 'unknown';
    let detail: string | null = null;
    if (typeof error === 'string') {
      kind = error;
    } else if (isRecord(error)) {
      const [first] = Object.keys(error);
      if (first !== undefined) {
        kind = first;
        const inner = error[first];
        detail = typeof inner === 'string' ? inner : JSON.stringify(inner);
      }
    }
    return {
      extrinsicIndex: extrinsicIndexOf(record.phase),
      kind,
      detail,
      filtered: kind.toLowerCase() === 'callfiltered',
    };
  });
}

/* -- tree and difficulty ----------------------------------------------- */

export function decodeLeafInsertions(records: readonly EventRecord[]): number[] {
  return eventsFor(records, 'zkTree', 'LeafInserted').map((record) =>
    asNumber(field(record, 'index'), 'LeafInserted.index'),
  );
}

export interface DifficultyAdjustment {
  oldDifficulty: bigint;
  newDifficulty: bigint;
  observedBlockTimeMs: number;
}

export function decodeDifficultyAdjustment(
  records: readonly EventRecord[],
): DifficultyAdjustment | null {
  const record = eventsFor(records, 'qPoW', 'DifficultyAdjusted')[0];
  if (record === undefined) {
    return null;
  }
  return {
    oldDifficulty: decodeU512(asHex(field(record, 'old_difficulty'), 'DifficultyAdjusted.old')),
    newDifficulty: decodeU512(asHex(field(record, 'new_difficulty'), 'DifficultyAdjusted.new')),
    observedBlockTimeMs: asNumber(
      field(record, 'observed_block_time'),
      'DifficultyAdjusted.observed_block_time',
    ),
  };
}

/** Every extrinsic index the block reports a success for. */
export function successfulExtrinsics(records: readonly EventRecord[]): Set<number> {
  const out = new Set<number>();
  for (const record of eventsFor(records, 'system', 'ExtrinsicSuccess')) {
    const index = extrinsicIndexOf(record.phase);
    if (index !== null) {
      out.add(index);
    }
  }
  return out;
}
