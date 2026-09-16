/** Read-layer tests substitute the crypto worker while exercising the actual
 * authenticated RPC transport. Rust tests cover the trie codec itself. */
import type { ChainContext } from '../../src/chain/api';
import type { Anchor } from '../../src/chain/anchor';
import { bindStateProofVerifier } from '../../src/chain/authenticated';

export function fixtureProof(at: string, entries: Iterable<[string, string | null]>): unknown {
  return { at, proof: [`0x${Buffer.from(JSON.stringify([...entries])).toString('hex')}`] };
}

export function fixtureHeader(number = 0): unknown {
  return {
    parentHash: `0x${'00'.repeat(32)}`, number: `0x${number.toString(16)}`,
    stateRoot: `0x${'11'.repeat(32)}`, extrinsicsRoot: `0x${'22'.repeat(32)}`,
    zkTreeRoot: `0x${'00'.repeat(32)}`, digest: { logs: [] },
  };
}

export function bindFixtureProofs(context: ChainContext, hash: (anchor: Anchor) => string): ChainContext {
  const entries = (nodes: string[]): Map<string, string | null> => {
    const map = new Map<string, string | null>();
    for (const node of nodes) {
      for (const [key, value] of JSON.parse(Buffer.from(node.slice(2), 'hex').toString()) as
          [string, string | null][]) map.set(key, value);
    }
    return map;
  };
  bindStateProofVerifier(context, {
    headerBlockHash: (anchor) => Promise.resolve(hash(anchor)),
    readStateProof: (_root, nodes, keys) => Promise.resolve(keys.map((key) => entries(nodes).get(key) ?? null)),
    readStatePrefix: (_root, nodes, prefix) => Promise.resolve(
      [...entries(nodes)].filter((entry): entry is [string, string] =>
        entry[0].startsWith(prefix) && entry[1] !== null).sort(([a], [b]) => a.localeCompare(b))),
  });
  return context;
}
