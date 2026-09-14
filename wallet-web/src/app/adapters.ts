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
import {
  blockHashAt,
  fetchHead,
  fetchLeaves,
  fetchTreeTotals,
  fetchUsedNullifiers,
} from '../chain/reads';
import type { ProverClient } from '../worker/client';
import type { ScannedNote, SyncChain, SyncCrypto } from '../wallet/sync';

export function chainAdapter(context: ChainContext): SyncChain {
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
    treeShape: (at) => fetchTreeTotals(context, at),
    leaves: (from, to, at, onProgress) => fetchLeaves(context, from, to, at, onProgress),
    usedNullifiers: (at, onProgress) => fetchUsedNullifiers(context, at, undefined, onProgress),
    entryCount: (at) => fetchEntryCount(context, at),
  };
}

async function fetchEntryCount(context: ChainContext, at: string): Promise<bigint> {
  const { entryCount } = await fetchTreeTotals(context, at);
  return entryCount;
}

export function cryptoAdapter(prover: ProverClient): SyncCrypto {
  return {
    decryptBatch: async (items) => {
      const answers = await prover.decryptBatch(
        items.map((item) => ({
          index: item.index,
          ciphertext: item.ciphertext,
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
          ciphertext: item.ciphertext,
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
            } satisfies ScannedNote),
      );
    },
    entryRho: (blockNumber, entryIndex) => prover.entryRho(blockNumber, entryIndex),
  };
}
