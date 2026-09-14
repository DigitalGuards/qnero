import { useState, type ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { fetchDetail, type BlockDetail } from '../chain/blocks';
import { findExtrinsic } from '../chain/search';
import { formatBytes, formatCount } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Hash, Loading, Notice, Panel } from '../components/ui';
import { SettlementView } from './parts/SettlementView';

interface Located {
  detail: BlockDetail;
  index: number;
  scanned: number;
}

/**
 * A settlement, found by extrinsic hash.
 *
 * There is no indexer behind this site, so a bare hash is a bounded walk
 * backwards from the tip. Links from a block page carry the block they came
 * from, which makes the common path one read.
 */
export function Settlement({ hash, at }: { hash: string; at: string | null }): ReactNode {
  const { bundle, head } = useChain();
  const [scanned, setScanned] = useState(0);

  const located = useAsync<Located | null>(
    bundle === null || head === null ? null : `settlement:${hash}:${at ?? 'scan'}`,
    bundle === null || head === null
      ? null
      : async () => {
          if (at !== null) {
            const detail = await fetchDetail(bundle.context, at);
            const match = detail.extrinsics.find(
              (extrinsic) => extrinsic.hash.toLowerCase() === hash.toLowerCase(),
            );
            if (match === undefined) {
              return null;
            }
            return { detail, index: match.index, scanned: 1 };
          }
          const result = await findExtrinsic(
            bundle.context,
            hash,
            head.header.number,
            bundle.config.searchWindowBlocks,
            setScanned,
          );
          if (result.found === null) {
            return null;
          }
          return { detail: result.found.detail, index: result.found.index, scanned: result.scanned };
        },
  );

  if (bundle === null) {
    return <Loading what="the chain head" />;
  }
  if (located.status === 'loading') {
    return (
      <>
        <header className="page__head">
          <h1>Settlement</h1>
          <p className="page__lede">
            <Hash value={hash} full />
          </p>
        </header>
        <Loading
          what={
            at === null
              ? `blocks, ${formatCount(scanned)} of ${formatCount(bundle.config.searchWindowBlocks)} read`
              : 'the block'
          }
        />
      </>
    );
  }
  if (located.status === 'error') {
    return <ErrorBox>{located.error}</ErrorBox>;
  }
  if (located.value === null) {
    return (
      <>
        <header className="page__head">
          <h1>Settlement</h1>
        </header>
        <Empty>
          No extrinsic with hash <Hash value={hash} full /> in the last{' '}
          {formatCount(bundle.config.searchWindowBlocks)} blocks. An older one is still on the
          chain; this site holds no index, so it looks back a fixed distance and no further.
        </Empty>
      </>
    );
  }

  const { detail, index } = located.value;
  const extrinsic = detail.extrinsics[index];
  const settlement = detail.settlements.find((entry) => entry.extrinsicIndex === index);
  const window = Number(bundle.context.api.consts['shielded']?.['blockHashWindow']?.toString() ?? '0');

  return (
    <>
      <header className="page__head">
        <h1>Settlement</h1>
        <p className="page__lede">
          <Hash value={hash} full />
        </p>
      </header>

      <Panel title="Submission">
        <Fields>
          <Field
            label="Call"
            value={<span className="mono">{extrinsic?.name ?? 'unresolved'}</span>}
            note="unsigned: a settlement pays no signer and carries no account"
          />
          <Field
            label="Included in"
            value={
              <a href={href({ name: 'block', id: detail.hash })}>
                block {formatCount(detail.header.number)}
              </a>
            }
          />
          <Field
            label="Size"
            value={<span className="num">{extrinsic === undefined ? '-' : formatBytes(extrinsic.byteLength)}</span>}
            note="proof and ciphertexts"
          />
          <Field
            label="Anchor block"
            value={
              window === 0 ? (
                'inside the runtime’s block-hash window'
              ) : (
                <span className="num">
                  a canonical block in {formatCount(Math.max(0, detail.header.number - window))} to{' '}
                  {formatCount(detail.header.number - 1)}
                </span>
              )
            }
            note="the exact height is a public input inside the proof, which this explorer does not open"
          />
        </Fields>
      </Panel>

      <Panel title="Slots">
        {settlement === undefined ? (
          <Empty>This extrinsic settled no slot.</Empty>
        ) : (
          <SettlementView settlement={settlement} blockHeight={detail.header.number} />
        )}
      </Panel>

      <Notice>
        <p>
          What this publishes: that some notes were spent, how many slots settled, which nullifiers
          entered the settled set, which commitments were appended and at which leaf indices, the
          size of each ciphertext, and the fee.
        </p>
        <p>
          What it does not: who sent anything, who received anything, how much moved, and which
          note any nullifier spends. A nullifier is a Poseidon2 output with no published relation to
          a leaf, and a commitment is a hash over a note nothing on chain opens. The two outputs of
          a slot are a pair with no order: the wallet draws the payment&rsquo;s output slot per
          spend, so which one is the sender&rsquo;s change is not on chain.
        </p>
        <p>
          One thing is weaker than it reads. A slot names the two nullifiers spent together and the
          two leaves that spend created, so a payment and its change are publicly a pair. The anchor
          this proof was built against is a public input too, and the gap between it and this block
          tracks the prover&rsquo;s speed. Neither is sortable anywhere on this site.
        </p>
      </Notice>
    </>
  );
}
