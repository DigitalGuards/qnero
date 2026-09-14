/**
 * Header digest logs.
 *
 * The block author is not an event and not a storage item. It is the 32-byte
 * payload of the `PreRuntime` digest item whose consensus engine id is
 * `pow_`. The runtime turns that preimage into an account through a Poseidon
 * rehash; either form is a per-block label and neither groups two blocks by
 * the same miner, because the preimage is `H(cvk, parent_hash)` and the parent
 * hash changes every block.
 */

import { bytesToHex, hexToBytes, readCompact } from './hex';

/** `POW_ENGINE_ID`, the four bytes `pow_`. */
export const POW_ENGINE_ID = '0x706f775f';

export type DigestItemKind =
  | 'other'
  | 'consensus'
  | 'seal'
  | 'preRuntime'
  | 'runtimeEnvironmentUpdated'
  | 'unknown';

export interface DigestItem {
  kind: DigestItemKind;
  /** Consensus engine id, for the three items that carry one. */
  engine: string | null;
  /** Payload bytes, hex. */
  payload: string | null;
}

/**
 * One `DigestItem` as `chain_getHeader` hands it over: the SCALE encoding of
 * that item alone, hex.
 *
 * The variant indices are `sp_runtime::generic::DigestItem`'s own: 0 `Other`,
 * 4 `Consensus`, 5 `Seal`, 6 `PreRuntime`, 8 `RuntimeEnvironmentUpdated`.
 */
export function decodeDigestItem(hex: string): DigestItem {
  const bytes = hexToBytes(hex);
  const variant = bytes[0];
  if (variant === undefined) {
    throw new Error('an empty digest item');
  }
  const withEngine = (kind: DigestItemKind): DigestItem => {
    const engine = bytes.slice(1, 5);
    if (engine.length !== 4) {
      throw new Error(`a ${kind} digest item carries no consensus engine id`);
    }
    const { value, next } = readCompact(bytes, 5);
    const payload = bytes.slice(next, next + value);
    if (payload.length !== value) {
      throw new Error(`a ${kind} digest item claims ${value} bytes and carries ${payload.length}`);
    }
    return { kind, engine: bytesToHex(engine), payload: bytesToHex(payload) };
  };
  switch (variant) {
    case 0: {
      const { value, next } = readCompact(bytes, 1);
      return { kind: 'other', engine: null, payload: bytesToHex(bytes.slice(next, next + value)) };
    }
    case 4:
      return withEngine('consensus');
    case 5:
      return withEngine('seal');
    case 6:
      return withEngine('preRuntime');
    case 8:
      return { kind: 'runtimeEnvironmentUpdated', engine: null, payload: null };
    default:
      return { kind: 'unknown', engine: null, payload: null };
  }
}

export function decodeDigestLogs(logs: readonly string[]): DigestItem[] {
  return logs.map(decodeDigestItem);
}

/**
 * The block's author label: the `pow_` pre-runtime payload.
 *
 * Display it as an opaque per-block label. It is `H(cvk, parent_hash)`, so two
 * blocks from one miner carry unrelated labels and a table that grouped by it
 * would be grouping nothing.
 */
export function authorLabel(items: readonly DigestItem[]): string | null {
  for (const item of items) {
    if (item.kind === 'preRuntime' && item.engine === POW_ENGINE_ID && item.payload !== null) {
      return item.payload;
    }
  }
  return null;
}

/** The seal, which carries the RandomX nonce and extra nonce. */
export function sealPayload(items: readonly DigestItem[]): string | null {
  for (const item of items) {
    if (item.kind === 'seal' && item.engine === POW_ENGINE_ID) {
      return item.payload;
    }
  }
  return null;
}
