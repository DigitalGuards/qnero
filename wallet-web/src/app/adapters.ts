/**
 * The two interfaces `wallet/sync.ts` takes, wired to the real chain and the
 * real worker.
 *
 * They are interfaces so the sync rules can be driven by a test with a
 * recording transport and a fake prover, which is how the privacy property is
 * checked: it is a property of the request stream, and no assertion over an
 * answer can see it.
 */

import type { ChainContext } from '../chain/api';
import { authenticatedBody } from '../chain/authenticated';
import { blockPayloads } from '../chain/body';
import {
  blockHashAt,
  fetchHead,
  fetchHeaderRange,
  fetchLeafBlocks,
  fetchLeafHashes,
  fetchLeaves,
  fetchTreeTotals,
  fetchUsedNullifiers,
} from '../chain/reads';
import type { ProverClient } from '../worker/client';
import type { ProverLimits } from '../worker/protocol';
import type { ScannedNote, SyncChain, SyncCrypto } from '../wallet/sync';

/**
 * The chain seam, wired to the real read layer.
 *
 * `limits` is the module's own, and what the sync takes from it is
 * `max_tree_depth`: a 4-ary tree of that depth holds `4 ** depth` leaves, and
 * the read layer refuses a `LeafCount` above it, so one storage answer cannot
 * open an unbounded scan window.
 */
export function chainAdapter(context: ChainContext, limits: ProverLimits): SyncChain {
  return {
    storageDrift: context.storageDrift,
    anchorWindow: context.constants.blockHashWindow,
    head: () => fetchHead(context),
    genesisHash: async () => {
      const hash = await blockHashAt(context, 0);
      if (hash === null) {
        throw new Error('this node has no block zero, so it cannot say which chain it serves');
      }
      return hash;
    },
    blockHashAt: (height) => blockHashAt(context, height),
    treeShape: (at) => fetchTreeTotals(context, at, limits.max_tree_depth),
    leaves: (from, to, at, leafCount, onProgress) =>
      fetchLeaves(context, from, to, at, leafCount, onProgress),
    // The body is fetched, rooted against the `extrinsicsRoot` the caller
    // carried out of the header walk that rehashed the header hashing to `at`,
    // and walked down to the payloads its calls carry. Composed here rather
    // than in either half, so nothing can take a body without the root check
    // that authenticates it.
    payloads: async (at, extrinsicsRoot) =>
      blockPayloads(context.bodyLayout, await authenticatedBody(context, at, extrinsicsRoot)),
    usedNullifiers: (at, onProgress) => fetchUsedNullifiers(context, at, undefined, onProgress),
    headers: (anchor, top, onHeader, onProgress) =>
      fetchHeaderRange(context, anchor, top, onHeader, onProgress),
    leafBlocks: (from, to, at) => fetchLeafBlocks(context, from, to, at),
    // `to` is `ZkTree::LeafCount` read at this same block, so it is both the
    // end of the range and the count an answer is measured against: below it a
    // leaf that is absent or is the tree's own pad is refused by name.
    leafHashes: (to, at, onProgress) => fetchLeafHashes(context, 0, to, at, to, onProgress),
  };
}

export function cryptoAdapter(prover: ProverClient): SyncCrypto {
  return {
    decryptBatch: async (items) => {
      const answers = await prover.decryptBatch(
        items.map((item) => ({ ciphertext: item.ciphertext })),
      );
      return answers.map((answer) =>
        answer === null
          ? null
          : ({
              value: BigInt(answer.value),
              rho: answer.rho,
              r: answer.r,
              commitment: answer.commitment,
              nullifier: answer.nullifier,
              memo: answer.memo,
            } satisfies ScannedNote),
      );
    },
    coinbaseBatch: async (items) => {
      const answers = await prover.coinbaseBatch(
        items.map((item) => ({
          index: item.index,
          blockNumber: item.blockNumber,
          value: item.value.toString(),
          genesisHash: item.genesisHash,
          commitment: item.commitment,
        })),
      );
      return answers.map((answer) =>
        answer === null
          ? null
          : ({
              value: BigInt(answer.value),
              rho: answer.rho,
              r: answer.r,
              commitment: answer.commitment,
              nullifier: answer.nullifier,
              memo: answer.memo,
              // Carried across the boundary: the scan decides ownership at a
              // coinbase position by the rebuild and reads the author label
              // only as a cross-check against it.
              mined: answer.mined === true,
            } satisfies ScannedNote),
      );
    },
    entryRhoMatches: (blockNumber, rho, entryCount) =>
      prover.entryRhoMatches(blockNumber, rho, entryCount),
    headerHashes: (headers) => prover.headerBlockHashes(headers),
    authorLabels: (parentHashes) => prover.authorLabels(parentHashes),
    blockRoots: (leafHashes, counts) => prover.blockRoots(leafHashes, counts),
  };
}
