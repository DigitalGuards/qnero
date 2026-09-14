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
}

/**
 * One extrinsic, found by hash.
 *
 * There is no indexer behind this site, so a bare hash is a bounded walk
 * backwards from the tip. Links from a block page carry the block they came
 * from, which makes the common path one read.
 *
 * The page is titled by what the extrinsic is. A settlement gets the
 * settlement's statement of what a spend publishes and what it does not;
 * anything else gets neither, because that statement over a timestamp inherent
 * would say a block's clock spent notes.
 */
export function Settlement({ hash, at }: { hash: string; at: string | null }): ReactNode {
  const { bundle, head } = useChain();
  const [scanned, setScanned] = useState(0);

  const located = useAsync<{ found: Located | null; stopped: string | null }>(
    bundle === null || head === null ? null : `settlement:${hash}:${at ?? 'scan'}`,
    bundle === null || head === null
      ? null
      : async () => {
          if (at !== null) {
            const detail = await fetchDetail(bundle.context, at);
            const match = detail.extrinsics.find(
              (extrinsic) => extrinsic.hash.toLowerCase() === hash.toLowerCase(),
            );
            return {
              found: match === undefined ? null : { detail, index: match.index },
              stopped: null,
            };
          }
          const result = await findExtrinsic(
            bundle.context,
            hash,
            head.header.number,
            bundle.config.searchWindowBlocks,
            setScanned,
          );
          return {
            found:
              result.found === null
                ? null
                : { detail: result.found.detail, index: result.found.index },
            stopped: result.stopped,
          };
        },
  );

  if (bundle === null) {
    return <Loading what="the chain head" />;
  }
  if (located.status === 'loading') {
    return (
      <>
        <header className="page__head">
          <h1>Extrinsic</h1>
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
  if (located.value.found === null) {
    return (
      <>
        <header className="page__head">
          <h1>Extrinsic</h1>
        </header>
        <Empty>
          No extrinsic with hash <Hash value={hash} full /> in the last{' '}
          {formatCount(bundle.config.searchWindowBlocks)} blocks
          {located.value.stopped === null ? '' : `, and ${located.value.stopped}`}. An older one is
          still on the chain; this site holds no index, so it looks back a fixed distance and no
          further.
        </Empty>
      </>
    );
  }

  const { detail, index } = located.value.found;
  const extrinsic = detail.extrinsics[index];
  const settlement = detail.settlements.find((entry) => entry.extrinsicIndex === index);
  const constant = bundle.context.api.consts['shielded']?.['blockHashWindow'];
  const window = constant === undefined ? null : Number(constant.toString());
  const isSettlement = settlement !== undefined;

  return (
    <>
      <header className="page__head">
        <h1>{isSettlement ? 'Settlement' : 'Extrinsic'}</h1>
        <p className="page__lede">
          <Hash value={hash} full />
        </p>
      </header>

      <Panel title="Submission">
        <Fields>
          <Field
            label="Call"
            value={<span className="mono">{extrinsic?.name ?? 'unresolved'}</span>}
            note={
              extrinsic?.kind === 'signed'
                ? 'signed: this extrinsic carries an account'
                : 'unsigned: it pays no signer and carries no account'
            }
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
            note={isSettlement ? 'proof and ciphertexts' : undefined}
          />
          {!isSettlement ? null : (
            <Field
              label="Anchor block"
              value={
                window === null ? (
                  'a canonical block inside the runtime’s block-hash window'
                ) : (
                  <>
                    a canonical block in{' '}
                    <span className="num">
                      {formatCount(Math.max(0, detail.header.number - window))}
                    </span>{' '}
                    to <span className="num">{formatCount(detail.header.number - 1)}</span>
                  </>
                )
              }
              note="the exact height is a public input inside the proof, which this explorer does not open"
            />
          )}
        </Fields>
      </Panel>

      <Panel title="Slots">
        {settlement === undefined ? (
          <Empty>This extrinsic settled no slot.</Empty>
        ) : (
          <SettlementView settlement={settlement} blockHeight={detail.header.number} />
        )}
      </Panel>

      {settlement === undefined ? null : (
        <Notice>
          <p>
            What this publishes: that some notes were spent, how many slots settled, which
            nullifiers entered the settled set, which commitments were appended and at which leaf
            indices, the size of each ciphertext, and the fee.
          </p>
          <p>
            What it does not: who sent anything, who received anything, and how much moved. Nothing
            on chain joins a nullifier to the leaf it spent, and a commitment is a hash over a note
            nothing on chain opens. What a slot does join is its own two outputs to its own two
            nullifiers, so a payment and its change are publicly a pair. Which of the two is the
            change is hidden only because the wallet draws the payment&rsquo;s output slot per
            spend, so the pair is rendered here with no order.
          </p>
          <p>
            The anchor this proof was built against is a public input too, and the gap between it
            and this block tracks the prover&rsquo;s speed. Neither that gap nor a ciphertext size
            is sortable anywhere on this site.
          </p>
        </Notice>
      )}
    </>
  );
}
