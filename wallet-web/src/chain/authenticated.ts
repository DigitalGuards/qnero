/** State and body integrity relative to a rehashed, selected header. Chain
 * selection still relies on the configured trusted node and wallet
 * checkpoints. */
import type { ChainContext } from './api';
import { anchorFromHeader, parseRawHeader, type RawChainHeader } from './anchor';
import { normaliseHash } from '../lib/hex';
import type { ProverClient } from '../worker/client';

export type StateProofVerifier = Pick<ProverClient,
  'headerBlockHash' | 'readStateProof' | 'readStatePrefix' | 'extrinsicsRoot'>;

const verifiers = new WeakMap<ChainContext, StateProofVerifier>();
const roots = new WeakMap<ChainContext, Map<string, Promise<string>>>();
const MAX_PROOF_BYTES = 64 * 1024 * 1024;
const MAX_PROOF_NODES = 1_000_000;
const MAX_PREFIX_ENTRIES = 1_000_000;

/**
 * The largest body this will hash, in bytes.
 *
 * `RuntimeBlockLength` is `BlockLength::max_with_normal_ratio(5 * 1024 * 1024,
 * ..)`, so no block the chain accepts carries more than 5 MiB of extrinsic
 * data. The margin above it covers the compact length prefixes
 * `chain_getBlock` hands each extrinsic over with and leaves the bound a
 * resource guard rather than a second consensus rule: a body inside this and
 * outside the runtime's own limit simply roots to a header no chain published.
 *
 * `qnero-state-proof` holds the same number and the module applies it again
 * behind the worker boundary. This one runs first, before a node's answer is
 * copied across that boundary at all, which is the same discipline
 * `MAX_PROOF_BYTES` above is held to.
 */
export const MAX_BODY_BYTES = 6 * 1024 * 1024;

/**
 * The largest number of extrinsics this will hash.
 *
 * The trie is keyed by `Compact<u32>` of the index, so the construction has no
 * count limit of its own. This one is a memory guard on what a node can hand
 * over before anything is allocated per item.
 */
export const MAX_BODY_EXTRINSICS = 65_536;

export function bindStateProofVerifier(context: ChainContext, verifier: StateProofVerifier): void {
  verifiers.set(context, verifier);
  roots.delete(context);
}

function verifierFor(context: ChainContext): StateProofVerifier {
  const verifier = verifiers.get(context);
  if (verifier === undefined) {
    throw new Error('authenticated state reads require the wallet verification worker');
  }
  return verifier;
}

export function authenticatedHeaderHash(context: ChainContext, header: RawChainHeader): Promise<string> {
  return verifierFor(context).headerBlockHash(anchorFromHeader(header));
}

export async function authenticatedStateRoot(context: ChainContext, at: string): Promise<string> {
  const verifier = verifierFor(context);
  let cache = roots.get(context);
  if (cache === undefined) {
    cache = new Map();
    roots.set(context, cache);
  }
  const key = normaliseHash(at);
  let pending = cache.get(key);
  if (pending === undefined) {
    if (cache.size >= 64) cache.clear();
    pending = (async () => {
      const header = parseRawHeader(await context.send('chain_getHeader', [at]));
      if (normaliseHash(await verifier.headerBlockHash(anchorFromHeader(header))) !== key) {
        throw new Error('storage header does not hash to the requested block');
      }
      return header.stateRoot;
    })();
    cache.set(key, pending);
    pending.catch(() => cache.delete(key));
  }
  return pending;
}

async function proofAt(context: ChainContext, keys: string[], at: string): Promise<string[]> {
  const answer = await context.send<{ at: string; proof: string[] }>('state_getReadProof', [keys, at]);
  if (normaliseHash(answer.at) !== normaliseHash(at)) {
    throw new Error('state proof belongs to a different block');
  }
  if (!Array.isArray(answer.proof) || answer.proof.length > MAX_PROOF_NODES) {
    throw new Error('state proof has too many nodes');
  }
  let bytes = 0;
  for (const node of answer.proof) {
    if (typeof node !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(node)) {
      throw new Error('state proof contains an invalid node');
    }
    bytes += (node.length - 2) / 2;
    if (bytes > MAX_PROOF_BYTES) throw new Error('state proof exceeds the verification memory budget');
  }
  return answer.proof;
}

export async function authenticatedValues(
  context: ChainContext, keys: string[], at: string,
): Promise<(string | null)[]> {
  if (keys.length === 0) return [];
  const root = await authenticatedStateRoot(context, at);
  return verifierFor(context).readStateProof(root, await proofAt(context, keys, at), keys);
}

/** Request every public key and prove the complete prefix locally. Only public
 * keys returned by broad enumeration are sent back in proof requests. */
export async function authenticatedPrefix(
  context: ChainContext, prefix: string, at: string, page: number,
  stillWanted?: () => boolean, onProgress?: (seen: number) => void,
): Promise<[string, string][]> {
  if (!Number.isInteger(page) || page < 1 || page > 4096) throw new Error('invalid state prefix page size');
  const root = await authenticatedStateRoot(context, at);
  const nodes = new Set(await proofAt(context, [prefix], at));
  let bytes = [...nodes].reduce((total, node) => total + (node.length - 2) / 2, 0);
  let cursor: string | null = null;
  let seen = 0;
  for (;;) {
    if (stillWanted?.() === false) throw new Error('the authenticated state scan was abandoned');
    const keys: string[] = await context.send<string[]>('state_getKeysPaged', [prefix, page, cursor, at]);
    if (!Array.isArray(keys) || keys.length > page) throw new Error('invalid state key page');
    let last: string | null = cursor;
    for (const key of keys) {
      if (typeof key !== 'string' || !/^0x(?:[0-9a-f]{2})*$/.test(key) ||
          !key.startsWith(prefix.toLowerCase()) || (last !== null && key <= last)) {
        throw new Error('state key page is outside the prefix or does not advance');
      }
      last = key;
    }
    seen += keys.length;
    if (seen > MAX_PREFIX_ENTRIES) throw new Error('state prefix exceeds the supported scan size');
    if (keys.length > 0) {
      for (const node of await proofAt(context, keys, at)) {
        if (!nodes.has(node)) bytes += (node.length - 2) / 2;
        nodes.add(node);
      }
    }
    if (bytes > MAX_PROOF_BYTES || nodes.size > MAX_PROOF_NODES) {
      throw new Error('state prefix proof exceeds the verification memory budget');
    }
    onProgress?.(seen);
    if (keys.length < page) break;
    cursor = last;
  }
  return verifierFor(context).readStatePrefix(root, [...nodes], prefix);
}

/**
 * One block's body, authenticated against the `extrinsicsRoot` in its own
 * header.
 *
 * Note ciphertexts are in block bodies and in no state map, so this is the
 * read that makes an incoming payment readable at all. Three steps, and the
 * order of them is the whole authentication:
 *
 * 1. The header at `at` is fetched and rehashed from its own preimage. A
 *    header that does not hash to the name it was asked for carries nothing:
 *    its `extrinsicsRoot` is then a number a node chose.
 * 2. The body at `at` is fetched.
 * 3. The body is rooted by the module, which builds the construction
 *    `frame_system` makes while `system_version` is 1, and the answer is
 *    compared against the header's field.
 *
 * What that buys is completeness as well as integrity. A state read
 * authenticates one key at a time and an absent answer has to be caught by a
 * rule about which keys a leaf owes; a body roots as a whole, so a node that
 * drops one extrinsic, reorders two, or appends one reaches a root no header
 * carries. There is no per-payload absence left to detect.
 *
 * `at` must be a hash this caller already trusts, which in a scan is a block
 * of the header walk. This selects no chain and verifies no proof of work.
 * `Chain::authenticated_body` in `crates/qnero-wallet/src/chain.rs` is the
 * same three steps in the same order.
 */
export async function authenticatedBody(context: ChainContext, at: string): Promise<string[]> {
  const verifier = verifierFor(context);
  const key = normaliseHash(at);
  const header = parseRawHeader(await context.send('chain_getHeader', [at]));
  if (normaliseHash(await verifier.headerBlockHash(anchorFromHeader(header))) !== key) {
    throw new Error(
      `the header this node served for block ${at} hashes to another block. The preimage is ` +
        'what authenticates the extrinsicsRoot a body is checked against, so a header that does ' +
        'not hash to its own name authenticates no body. Nothing has been changed.',
    );
  }

  const block = await context.send<{ block?: { extrinsics?: unknown } }>('chain_getBlock', [at]);
  const extrinsics = block.block?.extrinsics;
  if (!Array.isArray(extrinsics)) {
    throw withheldBody(at);
  }
  if (extrinsics.length > MAX_BODY_EXTRINSICS) {
    throw new Error(
      `this node served a body for block ${at} carrying ${extrinsics.length} extrinsics, above ` +
        `the ${MAX_BODY_EXTRINSICS} this wallet will hash. Nothing has been read from it.`,
    );
  }
  let bytes = 0;
  for (const extrinsic of extrinsics) {
    if (typeof extrinsic !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(extrinsic)) {
      throw new Error(`this node served a body for block ${at} containing an extrinsic that is not hex`);
    }
    bytes += (extrinsic.length - 2) / 2;
    if (bytes > MAX_BODY_BYTES) {
      throw new Error(
        `this node served a body for block ${at} above ${MAX_BODY_BYTES} bytes, which is more ` +
          'than `RuntimeBlockLength` lets a block carry. Nothing has been read from it.',
      );
    }
  }

  const body = extrinsics as string[];
  const recomputed = normaliseHash(await verifier.extrinsicsRoot(body));
  if (recomputed !== normaliseHash(header.extrinsicsRoot)) {
    throw new Error(
      `the body this node served for block ${at} roots to 0x${recomputed} where the ` +
        `extrinsicsRoot in the header it hashes to is ${header.extrinsicsRoot}. The body is ` +
        'what carries every note ciphertext, so a body the header does not carry is a node ' +
        'answering with extrinsics this chain did not include. Nothing has been changed.',
    );
  }
  return body;
}

/**
 * A block whose body this node will not serve.
 *
 * The one failure the body path has that the state path did not: a node that
 * answers the header and refuses, or empties, the block beside it. There is no
 * per-payload absence to detect any more, because a body roots as a whole, so
 * this is the whole of it.
 *
 * It is refused rather than read as a block that carried nothing. A block that
 * appended leaves carried the extrinsics that appended them, so an answer with
 * no body in it is an answer withheld, and scanning past it would step over
 * every payment in that block and write a watermark above it.
 * `withheld_body` in `crates/qnero-wallet/src/chain.rs` says the same.
 */
function withheldBody(at: string): Error {
  return new Error(
    `this node served a header for block ${at} and no body beside it. The block body is where ` +
      'every note ciphertext this chain publishes lives, so a block with no body is a payment ' +
      'nobody can find, and a pass that stepped over it would write a watermark above the whole ' +
      'block. Nothing has been changed: scan progress and notes are unchanged, and another ' +
      'node, or this one once it has the block, answers the same pass.',
  );
}
