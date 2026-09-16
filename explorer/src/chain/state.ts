/**
 * Chain-wide state: the head, the difficulty, the tree, the pool.
 *
 * Difficulty comes from `QPoWApi_get_difficulty` rather than from
 * `QPoW::CurrentDifficulty`, because the storage item reads back null before
 * the first retarget, where the effective value is the chain spec's
 * `InitialDifficulty`, and the runtime call resolves that case.
 */

import { decodeU512 } from '../lib/difficulty';
import { hexToBytes, leBytesToBigInt } from '../lib/hex';
import { storage, type ChainContext } from './api';

async function stateCallHex(context: ChainContext, method: string): Promise<string> {
  return context.provider.send<string>('state_call', [method, '0x']);
}

async function stateCallInt(context: ChainContext, method: string): Promise<bigint> {
  return leBytesToBigInt(hexToBytes(await stateCallHex(context, method)));
}

export interface ConsensusConstants {
  seedEpochBlocks: number;
  seedEpochLag: number;
  /** Legacy compatibility value. It is not a confirmation or finality threshold. */
  maxReorgDepth: number;
  /**
   * The chain's target block time, in milliseconds, or null when the node
   * cannot say.
   *
   * Read rather than assumed. The interval is chain state since spec 104, so
   * one node binary serves a 120 000 ms public chain and a 12 000 ms dev chain,
   * and every block count this page turns into a duration needs the chain's own
   * answer. The observed inter-block time stays what the hash-rate estimate
   * divides by: that is what the network is doing, and this is what it is
   * aiming at.
   *
   * Null is the spec-103 node. `QPoWApi` declares version 2 for this method and
   * a node still on 103 declares version 1 and answers "function not found".
   * That is a fact about that node, so the other three constants are read
   * without it and survive it.
   */
  targetBlockTimeMs: number | null;
}

export async function fetchConsensusConstants(context: ChainContext): Promise<ConsensusConstants> {
  const [epoch, lag, reorg] = await Promise.all([
    stateCallInt(context, 'QPoWApi_get_seed_epoch_blocks'),
    stateCallInt(context, 'QPoWApi_get_seed_epoch_lag'),
    stateCallInt(context, 'QPoWApi_get_max_reorg_depth'),
  ]);
  // Its own call, and its own failure. Sharing the promise above would have let
  // a runtime that predates spec 104 cost this panel all four constants over
  // the one method it does not have.
  let targetBlockTimeMs: number | null = null;
  try {
    targetBlockTimeMs = Number(await stateCallInt(context, 'QPoWApi_get_target_block_time'));
  } catch {
    targetBlockTimeMs = null;
  }
  return {
    seedEpochBlocks: Number(epoch),
    seedEpochLag: Number(lag),
    maxReorgDepth: Number(reorg),
    targetBlockTimeMs,
  };
}

export interface TreeState {
  leafCount: bigint;
  depth: number;
  root: string;
}

export interface PoolState {
  poolValuePlanck: bigint;
  entryCount: bigint;
}

export interface ChainSnapshot {
  headNumber: number;
  headHash: string;
  /** The node's irreversible checkpoint. New networks retain genesis; confirmations stay probabilistic. */
  finalizedNumber: number;
  finalizedHash: string;
  difficulty: bigint;
  lastBlockDurationMs: number;
  tree: TreeState;
  pool: PoolState;
}

export async function fetchSnapshot(context: ChainContext): Promise<ChainSnapshot> {
  const headHash = await context.provider.send<string>('chain_getBlockHash', []);
  const finalizedHash = await context.provider.send<string>('chain_getFinalizedHead', []);
  const [head, finalized, difficultyHex, duration, leafCount, depth, root, poolValue, entryCount] =
    await Promise.all([
      context.provider.send<{ number: string }>('chain_getHeader', [headHash]),
      context.provider.send<{ number: string }>('chain_getHeader', [finalizedHash]),
      stateCallHex(context, 'QPoWApi_get_difficulty'),
      stateCallInt(context, 'QPoWApi_get_last_block_duration'),
      storage(context, 'zkTree', 'leafCount')(),
      storage(context, 'zkTree', 'depth')(),
      storage(context, 'zkTree', 'root')(),
      storage(context, 'shielded', 'poolValue')(),
      storage(context, 'shielded', 'entryCount')(),
    ]);
  return {
    headNumber: Number(BigInt(head.number)),
    headHash,
    finalizedNumber: Number(BigInt(finalized.number)),
    finalizedHash,
    difficulty: decodeU512(difficultyHex),
    lastBlockDurationMs: Number(duration),
    tree: {
      leafCount: BigInt(leafCount.toString()),
      depth: Number(depth.toString()),
      root: root.toHex(),
    },
    pool: {
      poolValuePlanck: BigInt(poolValue.toString()),
      entryCount: BigInt(entryCount.toString()),
    },
  };
}

export interface NullifierCount {
  count: number;
  /** True when the page limit was reached first, so `count` is a floor rather than a total. */
  capped: boolean;
}

const NULLIFIER_PAGE = 1000;

/**
 * The size of the settled nullifier set.
 *
 * `UsedNullifiers` is `Blake2_128Concat` and grows forever, so counting it
 * means paging its keys and gets slower every day. This is capped, says so
 * when it hits the cap, and never blocks the rest of a page.
 *
 * `stillWanted` stops the paging. A walk of twenty-five pages outlives a block
 * on any link with latency, and without this every new head would stack
 * another walk on top of the last one and throw all but the newest away.
 */
export async function countNullifiers(
  context: ChainContext,
  at: string,
  pageLimit: number,
  stillWanted?: () => boolean,
): Promise<NullifierCount> {
  const prefix = storage(context, 'shielded', 'usedNullifiers').keyPrefix();
  let count = 0;
  let cursor: string | null = null;
  for (let page = 0; page < pageLimit; page += 1) {
    if (stillWanted?.() === false) {
      return { count, capped: true };
    }
    const params: unknown[] = [prefix, NULLIFIER_PAGE, cursor, at];
    const keys: string[] = await context.provider.send<string[]>('state_getKeysPaged', params);
    if (keys.length === 0) {
      return { count, capped: false };
    }
    count += keys.length;
    if (keys.length < NULLIFIER_PAGE) {
      return { count, capped: false };
    }
    const last = keys.at(-1);
    if (last === undefined) {
      return { count, capped: false };
    }
    // The guard against a node whose cursor stops advancing.
    if (cursor === last) {
      return { count, capped: true };
    }
    cursor = last;
  }
  return { count, capped: true };
}

/**
 * Whether one nullifier is in the settled set.
 *
 * This is a point lookup on a constructed key, which names that nullifier to
 * whoever runs the node. The search page prints that warning first and runs
 * this only when a reader asks for it.
 *
 * A failure is never turned into a `false` here. "Not in the set" is a
 * privacy-relevant claim and a refused or drifted read establishes nothing, so
 * the rejection reaches the caller and the page shows a third state.
 */
export async function nullifierSeen(
  context: ChainContext,
  nullifier: string,
  at: string,
): Promise<boolean> {
  const key = storage(context, 'shielded', 'usedNullifiers').key(nullifier);
  const value = await context.provider.send<string | null>('state_getStorage', [key, at]);
  return value !== null;
}
