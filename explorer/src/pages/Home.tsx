import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import {
  blockHashAt,
  fetchRecent,
  latestCoinbase,
  rollingBlockTimeMs,
  settledNullifiers,
  type LatestCoinbase,
  type SettledNullifiers,
} from '../chain/blocks';
import { countNullifiers, fetchSnapshot } from '../chain/state';
import { estimateHashrate, formatDifficulty, formatHashrate } from '../lib/difficulty';
import { blocksToNextSeed, nextSeedHeight, seedHeight } from '../lib/seed';
import { formatCount, formatQnr, formatSeconds, formatSpan } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Hash, Loading, Notice, Panel } from '../components/ui';
import { RecentBlocks } from './parts/RecentBlocks';

/**
 * The sentence under the latest coinbase.
 *
 * Only one of these is a claim about the chain. The rest say which read has not
 * answered, because a page that read no block cannot report what that block
 * minted, and emission is the one total this chain publishes in full.
 */
function coinbaseNote(coinbase: LatestCoinbase): string {
  if (coinbase.kind === 'minted') {
    return `leaf ${formatCount(coinbase.note.leafIndex)} at block ${formatCount(
      coinbase.note.blockNumber,
    )}`;
  }
  if (coinbase.kind === 'none') {
    return 'the newest block minted no note';
  }
  if (coinbase.kind === 'reading') {
    return 'reading the newest block';
  }
  switch (coinbase.why) {
    case 'recent-read-failed':
      return 'the recent-block read did not answer, so this is not an absence';
    case 'state-not-kept':
      return 'state not kept at the newest block, so its coinbase could not be read';
    case 'no-block':
      return 'no block in the window to read';
  }
}

/**
 * The sentence under the settled-nullifier figure.
 *
 * Two claims are in play and only one of them is about the chain. The figure
 * is a sum of one walk and one window, and either half can come back short, so
 * whatever the page prints has to carry which half did. The other claim is what
 * the number means at all: the chain settles two nullifiers per real slot and
 * one of a slot's two input positions may hold a dummy, so the set bounds the
 * notes this chain has spent from above.
 */
function nullifierNote(settled: SettledNullifiers): string {
  if (settled.kind === 'counting') {
    return 'walking the settled set';
  }
  if (settled.kind === 'not-counted') {
    return 'the node did not answer, so this is not a count';
  }
  const gaps: string[] = [];
  if (settled.capped) {
    gaps.push('the set is unbounded and this walk stops at its page budget');
  }
  if (settled.unreadBlocks === null) {
    gaps.push('the recent-block read did not answer, so the blocks since the baseline are unread');
  } else if (settled.unreadBlocks > 0) {
    gaps.push(
      `${formatCount(settled.unreadBlocks)} ${
        settled.unreadBlocks === 1 ? 'block' : 'blocks'
      } unread, so what they settled is uncounted`,
    );
  }
  if (gaps.length === 0) {
    return 'two per settled slot, and a slot spends one note or two, so this is an upper bound on the notes spent';
  }
  return `at least ${formatCount(settled.count)}: ${gaps.join('; ')}`;
}

export function Home(): ReactNode {
  const { bundle, head } = useChain();
  const headHash = head?.hash ?? null;
  const headNumber = head?.header.number ?? null;

  const ready = bundle !== null && headHash !== null && headNumber !== null;
  const snapshot = useAsync(
    ready ? `snapshot:${headHash}` : null,
    bundle === null || headHash === null ? null : () => fetchSnapshot(bundle.context),
  );
  const recent = useAsync(
    ready ? `recent:${headHash}` : null,
    bundle === null || headNumber === null
      ? null
      : () => fetchRecent(bundle.context, bundle.cache, headNumber, bundle.config.recentBlocks),
  );
  // Walking the whole nullifier key space is twenty-five paged requests and the
  // set only grows, so re-walking it on every imported block would stack a walk
  // per block and throw away all but the last. The walk is pinned to a baseline
  // height that moves once per recent-list window, and the blocks after it are
  // counted from the SlotSettled events the recent list has already decoded.
  // The baseline height is the whole key: resolving its hash inside the read
  // keeps the head out of the key, which is what stops an imported block from
  // restarting the walk. A reorg that replaces the baseline leaves the count
  // off by the settlements in the replaced blocks until the window moves.
  const recentDepth = bundle?.config.recentBlocks ?? 0;
  const baselineNumber =
    headNumber === null || recentDepth <= 0 ? null : Math.floor(headNumber / recentDepth) * recentDepth;
  const counted = useAsync(
    bundle === null || baselineNumber === null ? null : `nullifiers:${baselineNumber}`,
    bundle === null || baselineNumber === null
      ? null
      : async (live) => {
          const at = await blockHashAt(bundle.context, baselineNumber);
          if (at === null) {
            throw new Error(`this chain has no block at height ${baselineNumber}`);
          }
          return countNullifiers(bundle.context, at, bundle.config.nullifierPageLimit, live);
        },
  );
  const seedNumber =
    bundle === null || bundle.constants === null || headNumber === null
      ? null
      : seedHeight(headNumber, bundle.constants.seedEpochBlocks, bundle.constants.seedEpochLag);
  const seedHash = useAsync(
    bundle === null || seedNumber === null || headHash === null
      ? null
      : `seed:${seedNumber}:${headHash}`,
    bundle === null || seedNumber === null ? null : () => blockHashAt(bundle.context, seedNumber),
  );

  if (bundle === null || head === null) {
    return <Loading what="the chain head" />;
  }
  if (bundle.context.storageDrift.length > 0) {
    return (
      <ErrorBox>
        The runtime declares its storage differently from what this build assumes, so every figure
        below would read as empty with no error anywhere:{' '}
        {bundle.context.storageDrift.join('; ')}.
      </ErrorBox>
    );
  }

  const blockTimeMs = recent.status === 'ready' ? rollingBlockTimeMs(recent.value) : null;
  // What the newest block says about its coinbase, or which read did not
  // answer. "The newest block minted no note" is a claim about this chain's
  // emission, and this page invites a reader to total emission block by block,
  // so it is said only when a state read answered and held no coinbase.
  const coinbase = latestCoinbase(recent.status, recent.status === 'ready' ? recent.value : []);
  const observedMs =
    blockTimeMs ?? (snapshot.status === 'ready' ? snapshot.value.lastBlockDurationMs : null);
  const constants = bundle.constants;
  const nextSeed =
    constants === null
      ? null
      : nextSeedHeight(head.header.number, constants.seedEpochBlocks, constants.seedEpochLag);
  const untilRotation =
    constants === null
      ? null
      : blocksToNextSeed(head.header.number, constants.seedEpochBlocks, constants.seedEpochLag);
  const missingConstants =
    bundle.constantsError === null
      ? 'reading the consensus constants'
      : `the runtime did not answer the consensus constants: ${bundle.constantsError}`;

  // The settled set as of the baseline, plus the settlements since, which the
  // recent list has already decoded. Two nullifiers per settled slot, and a
  // block in the window whose state did not answer decodes to no settlements
  // at all, so the blocks that went unread are carried out of the read with
  // the figure and printed beside it.
  const settled = settledNullifiers({
    baseline: counted.status === 'ready' ? counted.value : null,
    baselineError: counted.status === 'error' ? counted.error : null,
    baselineNumber,
    headNumber,
    window: recent.status,
    blocks: recent.status === 'ready' ? recent.value : [],
  });
  const atLeast =
    settled.kind === 'counted' &&
    (settled.capped || settled.unreadBlocks === null || settled.unreadBlocks > 0);

  return (
    <>
      <header className="page__head">
        <h1>{bundle.config.chainName}</h1>
        <p className="page__lede">
          {bundle.context.specName} spec {bundle.context.specVersion}, transaction version{' '}
          {bundle.context.transactionVersion}. Value is private by default: every unit minted after
          genesis is a note, and the figures here are what any reader of the chain can total.{' '}
          <a href={href({ name: 'reveals' })}>What this chain reveals</a>.
        </p>
      </header>

      <Panel title="Head">
        <Fields>
          <Field label="Best block" value={<span className="num">{formatCount(head.header.number)}</span>} />
          <Field label="Best hash" value={<Hash value={head.hash} href={href({ name: 'block', id: head.hash })} />} />
          <Field
            label="Finalized"
            value={
              snapshot.status === 'ready' ? (
                <span className="num">{formatCount(snapshot.value.finalizedNumber)}</span>
              ) : (
                '-'
              )
            }
            note={
              constants === null
                ? 'proof of work with no finality gadget: the blocks near the tip are provisional'
                : `proof of work with no finality gadget: the last ${formatCount(
                    constants.maxReorgDepth,
                  )} blocks are provisional`
            }
          />
          <Field
            label="Block time"
            value={<span className="num">{observedMs === null ? '-' : formatSeconds(observedMs)}</span>}
            note={
              // The target comes from the chain, never from a constant in this
              // build: one node binary serves a 120 s public chain and a 12 s
              // dev chain, and this page is pointed at whichever it is given.
              `${
                blockTimeMs === null
                  ? 'last observed inter-block time'
                  : `mean over the last ${formatCount(bundle.config.recentBlocks)} blocks`
              }${
                constants === null ? '' : `, against a target of ${formatSeconds(constants.targetBlockTimeMs)}`
              }`
            }
          />
        </Fields>
      </Panel>

      <Panel title="Proof of work">
        {snapshot.status === 'error' ? <ErrorBox>{snapshot.error}</ErrorBox> : null}
        <Fields>
          <Field
            label="Difficulty"
            value={
              <span className="num">
                {snapshot.status === 'ready' ? formatDifficulty(snapshot.value.difficulty) : '-'}
              </span>
            }
            note="expected hashes per block"
          />
          <Field
            label="Network hash rate"
            value={
              <span className="num">
                {snapshot.status === 'ready'
                  ? formatHashrate(estimateHashrate(snapshot.value.difficulty, observedMs ?? 0))
                  : '-'}
              </span>
            }
            note={
              // The observed time and not the target: difficulty is expected
              // hashes per block, so dividing by what the chain actually took
              // is what measures the network. A chain running ahead of or
              // behind its target reads as the rate it really has.
              constants === null
                ? 'estimated from difficulty and the observed block time'
                : `estimated from difficulty and the observed block time, not the ${formatSeconds(
                    constants.targetBlockTimeMs,
                  )} target`
            }
          />
          <Field
            label="RandomX seed height"
            value={<span className="num">{seedNumber === null ? '-' : formatCount(seedNumber)}</span>}
            note={
              seedNumber === null ? (
                missingConstants
              ) : seedHash.status === 'ready' && seedHash.value !== null ? (
                <Hash value={seedHash.value} href={href({ name: 'block', id: seedHash.value })} />
              ) : (
                'computed from the height; the chain holds no seed'
              )
            }
          />
          <Field
            label="Next seed height"
            value={<span className="num">{nextSeed === null ? '-' : formatCount(nextSeed)}</span>}
            note={
              constants === null || untilRotation === null
                ? missingConstants
                : `rotates in ${formatCount(untilRotation)} blocks, about ${formatSpan(
                    untilRotation * constants.targetBlockTimeMs,
                  )} at this chain's target; epoch ${formatCount(
                    constants.seedEpochBlocks,
                  )} blocks (${formatSpan(
                    constants.seedEpochBlocks * constants.targetBlockTimeMs,
                  )}) lag ${formatCount(constants.seedEpochLag)}`
            }
          />
        </Fields>
      </Panel>

      <Panel title="Shielded pool">
        {counted.status === 'error' ? <ErrorBox>{counted.error}</ErrorBox> : null}
        <Fields>
          <Field
            label="Commitment tree leaves"
            value={
              <span className="num">
                {snapshot.status === 'ready' ? formatCount(snapshot.value.tree.leafCount) : '-'}
              </span>
            }
            note={
              snapshot.status === 'ready' ? `depth ${formatCount(snapshot.value.tree.depth)}` : undefined
            }
          />
          <Field
            label="Tree root"
            value={snapshot.status === 'ready' ? <Hash value={snapshot.value.tree.root} /> : '-'}
          />
          <Field
            label="Nullifiers settled"
            value={
              <span className="num">
                {settled.kind === 'not-counted'
                  ? '-'
                  : settled.kind === 'counting'
                    ? 'counting'
                    : `${formatCount(settled.count)}${atLeast ? '+' : ''}`}
              </span>
            }
            note={nullifierNote(settled)}
          />
          <Field
            label="Pool value"
            value={
              <span className="num">
                {snapshot.status === 'ready' ? formatQnr(snapshot.value.pool.poolValuePlanck) : '-'}
              </span>
            }
            note={
              snapshot.status === 'ready'
                ? `${formatCount(snapshot.value.pool.entryCount)} ${
                    snapshot.value.pool.entryCount === 1n ? 'entry has' : 'entries have'
                  } been shielded`
                : undefined
            }
          />
          <Field
            label="Latest coinbase"
            value={
              <span className="num">
                {coinbase.kind === 'minted' ? formatQnr(coinbase.note.valuePlanck) : '-'}
              </span>
            }
            note={coinbaseNote(coinbase)}
          />
        </Fields>
      </Panel>

      <Notice>
        <p>
          The block author shown on every page is the 32-byte pre-runtime label{' '}
          <span className="mono">H(cvk, parent_hash)</span>. It changes every block, so two blocks
          from one miner carry unrelated labels and no table on this site can group a miner&rsquo;s
          income.
        </p>
      </Notice>

      <Panel title="Recent blocks">
        {recent.status === 'error' ? <ErrorBox>{recent.error}</ErrorBox> : null}
        {recent.status === 'loading' ? <Loading what="recent blocks" /> : null}
        {recent.status === 'ready' ? (
          recent.value.length === 0 ? (
            <Empty>No blocks yet.</Empty>
          ) : (
            <RecentBlocks blocks={recent.value} />
          )
        ) : null}
      </Panel>
    </>
  );
}
