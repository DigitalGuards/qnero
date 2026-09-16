/** State integrity relative to a rehashed, selected header. Chain selection
 * still relies on the configured trusted node and wallet checkpoints. */
import type { ChainContext } from './api';
import { anchorFromHeader, parseRawHeader, type RawChainHeader } from './anchor';
import { normaliseHash } from '../lib/hex';
import type { ProverClient } from '../worker/client';

export type StateProofVerifier = Pick<ProverClient,
  'headerBlockHash' | 'readStateProof' | 'readStatePrefix'>;

const verifiers = new WeakMap<ChainContext, StateProofVerifier>();
const roots = new WeakMap<ChainContext, Map<string, Promise<string>>>();
const MAX_PROOF_BYTES = 64 * 1024 * 1024;
const MAX_PROOF_NODES = 1_000_000;
const MAX_PREFIX_ENTRIES = 1_000_000;

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
