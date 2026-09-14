/**
 * The anchor: a header as its preimage rather than its hash.
 *
 * The spend circuit recomputes `block_hash = Poseidon2(preimage)` and
 * publishes the result, so a wallet holding only the hash cannot prove. It has
 * to rebuild the five header fields plus the digest blob, and the digest blob
 * is the part that goes wrong: `chain_getHeader` hands over one hex string per
 * `DigestItem`, and what the chain hashes is the `Digest` struct's own
 * encoding, zero padded or truncated to `DIGEST_LOGS_SIZE`.
 *
 * A sealed header encodes to exactly that size with no slack. The padding is
 * there for a header that does not, and there is deliberately no length check:
 * one would refuse what the chain accepts.
 *
 * **The rebuild is checked before anything is proved.** The wasm module
 * exports `headerBlockHash`, which is the circuit's own hash function over
 * this preimage, and the wallet compares it against `chain_getBlockHash`. The
 * alternative is paying for a 33-second proof and reading `BlockHashMismatch`
 * off the pool. The explorer deliberately never recomputes a block hash for
 * the same reason it is done here rather than in TypeScript: Poseidon2 over
 * Goldilocks is not something a second implementation should exist for.
 */

import { bytesToHex, hexToBytes } from '../lib/hex';
import { concatBytes, encodeCompact } from '../lib/scale';

/** The digest blob length the header hash commits to. */
export const DIGEST_LOGS_SIZE = 110;

/** A header preimage, field for field, in the shape the prover takes. */
export interface Anchor {
  parent_hash: string;
  block_number: number;
  state_root: string;
  extrinsics_root: string;
  zk_tree_root: string;
  /** Exactly `DIGEST_LOGS_SIZE` bytes, hex, no `0x`. */
  digest_logs: string;
}

/** A header as `chain_getHeader` returns it, with the field no stock header has. */
export interface RawChainHeader {
  parentHash: string;
  number: string;
  stateRoot: string;
  extrinsicsRoot: string;
  zkTreeRoot: string;
  digest: { logs: string[] };
}

function requireHex(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new Error(`a header's ${what} is not a hex string`);
  }
  return value;
}

export function parseRawHeader(raw: unknown): RawChainHeader {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('chain_getHeader returned no header');
  }
  const source = raw as Record<string, unknown>;
  const digest = source['digest'];
  const logsValue =
    typeof digest === 'object' && digest !== null
      ? (digest as Record<string, unknown>)['logs']
      : undefined;
  const logs = Array.isArray(logsValue) ? logsValue.map((log) => requireHex(log, 'digest log')) : [];
  const number = source['number'];
  if (typeof number !== 'string') {
    throw new Error("a header's number is not a hex string");
  }
  return {
    parentHash: requireHex(source['parentHash'], 'parentHash'),
    number,
    stateRoot: requireHex(source['stateRoot'], 'stateRoot'),
    extrinsicsRoot: requireHex(source['extrinsicsRoot'], 'extrinsicsRoot'),
    zkTreeRoot: requireHex(source['zkTreeRoot'], 'zkTreeRoot'),
    digest: { logs },
  };
}

/** The 110-byte digest blob: `compact(len) ++ concat(items)`, padded. */
export function digestBytes(logs: readonly string[]): Uint8Array {
  const encoded = concatBytes([encodeCompact(logs.length), ...logs.map((log) => hexToBytes(log))]);
  const padded = new Uint8Array(DIGEST_LOGS_SIZE);
  padded.set(encoded.subarray(0, DIGEST_LOGS_SIZE));
  return padded;
}

function strip(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2) : hex;
}

/** One header, as the anchor of a spend. */
export function anchorFromHeader(header: RawChainHeader): Anchor {
  return {
    parent_hash: strip(header.parentHash),
    block_number: Number(BigInt(header.number)),
    state_root: strip(header.stateRoot),
    extrinsics_root: strip(header.extrinsicsRoot),
    zk_tree_root: strip(header.zkTreeRoot),
    digest_logs: strip(bytesToHex(digestBytes(header.digest.logs))),
  };
}
