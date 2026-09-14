/**
 * A chain a sync can be driven against: headers, block ranges and a tree.
 *
 * A sync decides what kind of note each leaf holds from what the headers
 * commit to, so a fixture that only lists leaves is no longer a chain. This
 * builds the rest of one: a header per block, each carrying the commitment
 * tree root after exactly the leaves that block appended and the author label
 * of whoever mined it, and the recomputations a wallet checks them with.
 *
 * The hashes here are not Poseidon2. What stands in for the module is a cheap
 * deterministic fold, which is all these tests need: what they cover is which
 * answers a wallet refuses, and the module's own hash rules are covered in
 * Rust, against the pallet, where the chain is.
 */

import type { RawChainHeader } from '../../src/chain/anchor';
import type { SyncChain, SyncCrypto } from '../../src/wallet/sync';

/**
 * The hash this fixture's node serves at a height, on the branch `tag` names.
 *
 * The tag is what makes two branches of one fixture: a node on a different
 * branch answers a different hash from the fork height up and the same hash
 * below it, which is a reorg as a wallet sees one.
 */
export function hashAtHeight(height: number, tag = ''): string {
  return `${tag}${height}`.padStart(64, '0');
}

/** The hash a shape's node serves at a height, branch included. */
export function hashOf(shape: ChainShape, height: number): string {
  const forked = shape.forkTag !== undefined && height >= (shape.forkFrom ?? 0);
  return hashAtHeight(height, forked ? shape.forkTag : '');
}

/**
 * The genesis of this fixture's chain.
 *
 * It is block zero's own hash and not a separate constant: a sync walks the
 * headers down to a hash it already trusts, and for a first pass that hash is
 * the genesis the store is bound to.
 */
export const GENESIS = hashAtHeight(0);

/** This wallet's author label for a block with this parent. */
export function ourLabel(parentHash: string): string {
  return fold(new TextEncoder().encode(`ours:${strip(parentHash)}`));
}

/** Somebody else's, which no key in a test produces. */
export function foreignLabel(block: number): string {
  return fold(new TextEncoder().encode(`theirs:${block}`));
}

function strip(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

/** A 32-byte digest of some bytes, deterministic and cheap. */
function fold(bytes: Uint8Array): string {
  let low = 0x811c9dc5 >>> 0;
  let high = 0x01000193 >>> 0;
  for (const byte of bytes) {
    low = Math.imul(low ^ byte, 0x01000193) >>> 0;
    high = Math.imul(high + byte + 1, 0x85ebca6b) >>> 0;
  }
  const word = `${low.toString(16).padStart(8, '0')}${high.toString(16).padStart(8, '0')}`;
  return word.repeat(4);
}

/** The root over the first `count` leaves of a leaf-hash buffer. */
export function rootOver(leafHashes: Uint8Array, count: number): string {
  const prefix = leafHashes.subarray(0, count * 32);
  const tagged = new Uint8Array(prefix.length + 4);
  tagged.set(prefix);
  tagged[prefix.length] = count & 0xff;
  tagged[prefix.length + 1] = (count >> 8) & 0xff;
  return fold(tagged);
}

/** What a fixture says about the chain behind its leaves. */
export interface ChainShape {
  head: number;
  leafCount: number;
  /** The block each leaf was appended in. Must not decrease with the index. */
  blockOf(index: number): number;
  /** Each leaf's commitment, hex with no `0x`. */
  commitmentAt(index: number): string;
  /** Blocks this wallet's own miner key authored. */
  ours?: ReadonlySet<number>;
  /** A leaf whose `Shielded::LeafBlocks` this node answers nothing for. */
  withheldBlocks?: ReadonlySet<number>;
  /** A leaf this node dates to a block its own headers do not put it in. */
  misdated?: ReadonlyMap<number, number>;
  /** A block whose header this node serves with a field changed after the hash was fixed. */
  lyingHeaders?: ReadonlySet<number>;
  /** What `ZkTree::LeafCount` answers, where the chain is longer. */
  shortLeafCount?: number;
  /** Blocks whose header carries no pre-runtime item, so no author label. */
  unlabelled?: ReadonlySet<number>;
  /**
   * Which branch this fixture's node is on, mixed into every hash at or above
   * `forkFrom`.
   *
   * A node above this wallet's newest checkpoint picks every header field, so
   * two fixtures that agree below a height and disagree above it are the same
   * chain to the wallet until a checkpoint at a shared height says otherwise.
   */
  forkTag?: string;
  /** The lowest height `forkTag` applies to. */
  forkFrom?: number;
}

/** Every leaf hash of the chain, `32 * n` bytes. */
export function leafBytes(shape: ChainShape): Uint8Array {
  const out = new Uint8Array(shape.leafCount * 32);
  for (let index = 0; index < shape.leafCount; index += 1) {
    const hex = strip(shape.commitmentAt(index)).padStart(64, '0');
    for (let byte = 0; byte < 32; byte += 1) {
      out[index * 32 + byte] = Number.parseInt(hex.slice(byte * 2, byte * 2 + 2), 16);
    }
  }
  return out;
}

/** Leaves folded into the tree by the end of a block. */
export function countAt(shape: ChainShape, block: number): number {
  let count = 0;
  while (count < shape.leafCount && shape.blockOf(count) <= block) {
    count += 1;
  }
  return count;
}

function headerAt(shape: ChainShape, bytes: Uint8Array, number: number): RawChainHeader {
  const parentHash = number === 0 ? `0x${'00'.repeat(32)}` : `0x${hashOf(shape, number - 1)}`;
  const label = shape.ours?.has(number) === true ? ourLabel(parentHash) : foreignLabel(number);
  const item = `0x06706f775f80${label}`;
  return {
    parentHash,
    number: `0x${number.toString(16)}`,
    stateRoot: shape.lyingHeaders?.has(number) === true ? `0x${'ee'.repeat(32)}` : `0x${'22'.repeat(32)}`,
    extrinsicsRoot: `0x${'33'.repeat(32)}`,
    zkTreeRoot: `0x${rootOver(bytes, countAt(shape, number))}`,
    digest: { logs: shape.unlabelled?.has(number) === true ? [] : [item] },
  };
}

/** The three reads a sync makes of the chain behind its leaves. */
export function chainParts(shape: ChainShape): Pick<SyncChain, 'headers' | 'leafBlocks' | 'leafHashes'> {
  const bytes = leafBytes(shape);
  return {
    // Descending, `top` first, which is the order the parent links can be
    // followed in and the order the read layer hands them over in.
    headers: (anchor, top, onHeader, onProgress) => {
      // `onProgress` counts the headers of this chunk, one-based, the way
      // `fetchHeaderRange` does: a chunked walk reports its position from the
      // block it stands on, so the count a test reads is the count an operator
      // reads.
      let seen = 0;
      for (let number = top.number; number >= anchor; number -= 1) {
        onHeader(headerAt(shape, bytes, number));
        seen += 1;
        onProgress?.(seen);
      }
      return Promise.resolve();
    },
    leafBlocks: (from, to) => {
      const out: (number | null)[] = [];
      for (let index = from; index < to; index += 1) {
        out.push(
          shape.withheldBlocks?.has(index) === true
            ? null
            : (shape.misdated?.get(index) ?? shape.blockOf(index)),
        );
      }
      return Promise.resolve(out);
    },
    leafHashes: (to) => Promise.resolve(bytes.slice(0, to * 32)),
  };
}

/** The three recomputations a sync checks those reads with. */
export function cryptoParts(
  shape: ChainShape,
): Pick<SyncCrypto, 'headerHashes' | 'authorLabels' | 'blockRoots'> {
  return {
    headerHashes: (headers) =>
      Promise.resolve(
        headers.map((header) =>
          shape.lyingHeaders?.has(header.block_number) === true
            ? `0x${fold(new TextEncoder().encode(`changed:${header.block_number}`))}`
            : `0x${hashOf(shape, header.block_number)}`,
        ),
      ),
    authorLabels: (parentHashes) => Promise.resolve(parentHashes.map((hash) => ourLabel(hash))),
    blockRoots: (leafHashes, counts) =>
      Promise.resolve(counts.map((count) => rootOver(leafHashes, count))),
  };
}
