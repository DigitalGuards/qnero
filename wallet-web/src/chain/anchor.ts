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

import { bytesToHex, hexToBytes, leBytesToBigInt, readCompact } from '../lib/hex';
import { concatBytes, encodeCompact } from '../lib/scale';

/** The digest blob length the header hash commits to. */
export const DIGEST_LOGS_SIZE = 110;

/** The Goldilocks modulus, `2^64 - 2^32 + 1`. */
export const GOLDILOCKS_MODULUS = 0xffffffff00000001n;

/**
 * A Blake2-256 header root, as the four Goldilocks limbs the chain hashes.
 *
 * `stateRoot` and `extrinsicsRoot` are Blake2-256 outputs, so each of their
 * four 8-byte little-endian limbs lands at or above the Goldilocks modulus
 * about once in four billion, and the chain does not care: `HeaderInputs::new`
 * reduces both roots mod p and `Header::hash` hashes what comes out. The
 * prover module used to take them through a strict decode that refused a limb
 * at or above p, so a wallet could not anchor at such a block at all.
 *
 * The reduction is one conditional subtraction, because `2p` overflows a u64,
 * which is the same arithmetic `Goldilocks::as_canonical_u64` does. Doing it
 * here means the bytes handed to the prover are already canonical, so a
 * deployed module that still has the strict decode takes them and hashes them
 * to the value the chain hashes.
 */
export function canonicalBlakeRoot(hex: string): string {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new Error(`a header root is ${bytes.length} bytes where a Blake2-256 output is 32`);
  }
  for (let limb = 0; limb < 4; limb += 1) {
    const offset = limb * 8;
    let value = leBytesToBigInt(bytes.subarray(offset, offset + 8));
    if (value >= GOLDILOCKS_MODULUS) {
      value -= GOLDILOCKS_MODULUS;
    }
    for (let byte = 0; byte < 8; byte += 1) {
      bytes[offset + byte] = Number((value >> BigInt(8 * byte)) & 0xffn);
    }
  }
  return strip(bytesToHex(bytes));
}

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

/**
 * One header, as the anchor of a spend.
 *
 * The two Blake2 roots are reduced here, for the reason `canonicalBlakeRoot`
 * gives: the chain reduces them and a prover module may refuse them raw. The
 * two Poseidon2 fields go through untouched, because their limbs are circuit
 * outputs and are canonical already; a header carrying one that is not is a
 * header the prover should refuse.
 */
export function anchorFromHeader(header: RawChainHeader): Anchor {
  return {
    parent_hash: strip(header.parentHash),
    block_number: Number(BigInt(header.number)),
    state_root: canonicalBlakeRoot(header.stateRoot),
    extrinsics_root: canonicalBlakeRoot(header.extrinsicsRoot),
    zk_tree_root: strip(header.zkTreeRoot),
    digest_logs: strip(bytesToHex(digestBytes(header.digest.logs))),
  };
}

/** `DigestItem::PreRuntime`'s SCALE variant index. */
const PRE_RUNTIME_VARIANT = 6;

/** `sp_consensus_qpow::POW_ENGINE_ID`, the four bytes consensus tags with. */
const POW_ENGINE_ID = [0x70, 0x6f, 0x77, 0x5f];

/**
 * The 32 bytes of the block author's label, out of the pre-runtime digest
 * item.
 *
 * The item is `DigestItem::PreRuntime(POW_ENGINE_ID, label)` and the label is
 * `H("qnero/author-label", cvk, parent_hash)`, which
 * `qnero_note_core::MinerKey::author_label` derives. `cvk` is the miner's
 * secret, so nobody can compute another wallet's label and nobody can group
 * one operator's blocks; the wallet that holds the key recomputes its own and
 * compares.
 *
 * The header's hash commits to the digest, so this is authenticated by the
 * same recomputation that authenticates the rest of the header. That is what
 * makes it usable for deciding which blocks this wallet mined: a node cannot
 * present one of this wallet's blocks as somebody else's without changing the
 * hash. `RawHeader::author_label` in `crates/qnero-wallet/src/chain.rs` reads
 * the identical item.
 *
 * `null` when there is no such item, which is a block no Qnero node built.
 */
export function authorLabelFromHeader(header: RawChainHeader): string | null {
  for (const log of header.digest.logs) {
    const bytes = hexToBytes(log);
    if (bytes.length < 6 || bytes[0] !== PRE_RUNTIME_VARIANT) {
      continue;
    }
    if (!POW_ENGINE_ID.every((byte, index) => bytes[1 + index] === byte)) {
      continue;
    }
    const { value: length, next } = readCompact(bytes, 5);
    if (length !== 32 || bytes.length - next !== 32) {
      continue;
    }
    return bytesToHex(bytes.subarray(next)).slice(2);
  }
  return null;
}
