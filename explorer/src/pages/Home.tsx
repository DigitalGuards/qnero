import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { blockHashAt, fetchRecent, rollingBlockTimeMs } from '../chain/blocks';
import { countNullifiers, fetchSnapshot } from '../chain/state';
import { estimateHashrate, formatDifficulty, formatHashrate } from '../lib/difficulty';
import { blocksToNextSeed, nextSeedHeight, seedHeight } from '../lib/seed';
import { formatCount, formatQnr, formatSeconds } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Hash, Loading, Notice, Panel } from '../components/ui';
import { RecentBlocks } from './parts/RecentBlocks';

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
  const latest = recent.status === 'ready' ? recent.value[0] : undefined;
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
  // recent list has already decoded. Two nullifiers per settled slot.
  const sinceBaseline =
    recent.status === 'ready' && baselineNumber !== null
      ? recent.value
          .filter((block) => block.header.number > baselineNumber)
          .flatMap((block) => block.settlements)
          .flatMap((settlement) => settlement.slots)
          .flatMap((slot) => slot.nullifiers)
      : [];
  const nullifierCount =
    counted.status === 'ready' ? counted.value.count + new Set(sinceBaseline).size : null;

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
              blockTimeMs === null
                ? 'last observed inter-block time'
                : `mean over the last ${formatCount(bundle.config.recentBlocks)} blocks`
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
            note="estimated from difficulty and the observed block time"
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
                : `rotates in ${formatCount(untilRotation)} blocks, epoch ${formatCount(
                    constants.seedEpochBlocks,
                  )} lag ${formatCount(constants.seedEpochLag)}`
            }
          />
        </Fields>
      </Panel>

      <Panel title="Shielded pool">
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
                {nullifierCount === null
                  ? counted.status === 'error'
                    ? '-'
                    : 'counting'
                  : `${formatCount(nullifierCount)}${counted.status === 'ready' && counted.value.capped ? '+' : ''}`}
              </span>
            }
            note={
              counted.status === 'ready' && counted.value.capped
                ? 'a floor: the set is unbounded and this count stops at its page budget'
                : 'each settled slot spends two'
            }
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
                {latest?.coinbase === undefined || latest.coinbase === null
                  ? '-'
                  : formatQnr(latest.coinbase.valuePlanck)}
              </span>
            }
            note={
              latest?.coinbase == null
                ? 'the newest block minted no note'
                : `leaf ${formatCount(latest.coinbase.leafIndex)} at block ${formatCount(
                    latest.coinbase.blockNumber,
                  )}`
            }
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
