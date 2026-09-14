import { useState, type ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { fetchDetail, settlementOf, type BlockDetail } from '../chain/blocks';
import { findExtrinsic } from '../chain/search';
import { formatBytes, formatCount } from '../lib/units';
import { Empty, Field, Fields, Hash, Loading, NotRead, Notice, Panel } from '../components/ui';
import { Problem } from './parts/Problem';
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
 *
 * What the extrinsic is comes out of the block's events, and events are state.
 * A node that has pruned the state at this block still serves the body, so the
 * read can come back empty for a spend that published two nullifiers and two
 * commitments. That case is written as a third one here. The page keeps the
 * neutral title, says the state was not kept, and claims neither that this
 * settled nothing nor that it settled anything.
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
    // The same shape the block page fails in: what kind of page this is, the
    // value it was opened by, the node's own message, and a way out. A bare
    // error box here was a dead end, on the page a reader reaches by following
    // a link or pasting a hash.
    return (
      <Problem heading="Extrinsic" value={hash}>
        {located.error}
      </Problem>
    );
  }
  if (located.value.found === null) {
    return (
      <>
        <header className="page__head">
          <h1>Extrinsic</h1>
        </header>
        {at === null ? (
          <Empty>
            No extrinsic with hash <Hash value={hash} full /> in the last{' '}
            {formatCount(bundle.config.searchWindowBlocks)} blocks
            {located.value.stopped === null ? '' : `, and ${located.value.stopped}`}. An older one
            is still on the chain; this site holds no index, so it looks back a fixed distance and
            no further.
          </Empty>
        ) : (
          // One block was read, the one the link carried, so the walk's sentence
          // would claim five hundred blocks this page never opened.
          <Empty>
            No extrinsic with hash <Hash value={hash} full /> in{' '}
            <a href={href({ name: 'block', id: at })}>the block this link carried</a>, which is the
            only block this page read. A reorg can replace the block a link was built from.{' '}
            <a href={href({ name: 'settlement', hash, at: null })}>
              Look back {formatCount(bundle.config.searchWindowBlocks)} blocks instead
            </a>
            .
          </Empty>
        )}
      </>
    );
  }

  const { detail, index } = located.value.found;
  const extrinsic = detail.extrinsics[index];
  const read = settlementOf(detail, index);
  const settlement = read.kind === 'read' ? read.settlement : null;
  const constant = bundle.context.api.consts['shielded']?.['blockHashWindow'];
  const window = constant === undefined ? null : Number(constant.toString());
  const isSettlement = settlement !== null;

  return (
    <>
      <header className="page__head">
        <h1>{isSettlement ? 'Settlement' : 'Extrinsic'}</h1>
        <p className="page__lede">
          <Hash value={hash} full />
        </p>
      </header>

      {read.kind === 'not-read' ? (
        <Notice>
          <p>
            The node answered no state at this block, so the events that say what this extrinsic
            settled could not be read: {read.error}. Whether this is a settlement, and what it
            published if it is, are among the things this page could not establish. The header and
            the body are archived, and those are what it still shows.
          </p>
        </Notice>
      ) : null}

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
        {read.kind === 'not-read' ? (
          <NotRead what="the settlement" error={read.error} />
        ) : settlement === null ? (
          <Empty>This extrinsic settled no slot.</Empty>
        ) : (
          <SettlementView settlement={settlement} blockHeight={detail.header.number} />
        )}
      </Panel>

      {settlement === null ? null : (
        <Notice>
          <p>
            What this publishes: how many slots settled, which nullifiers entered the settled set,
            which commitments were appended and at which leaf indices, the size of each ciphertext,
            and the fee.
          </p>
          <p>
            A slot has two input positions and its two nullifiers mark both consumed. A position
            holding a real input spends one note; a position holding a dummy input publishes a
            nullifier over no note. At least one position of a settled slot is real, so a slot
            spends one note or two, and the nullifiers below count positions.
          </p>
          <p>
            What it does not: who sent anything, who received anything, how much moved, and which
            of a slot&rsquo;s two nullifiers stands for a note. Nothing on chain joins a nullifier
            to the leaf it spent, and a commitment is a hash over a note nothing on chain opens.
            What a slot does join is its own two outputs to its own two nullifiers, so a payment
            and its change are publicly a pair. Which of the two is the change is hidden only
            because the wallet draws the payment&rsquo;s output slot per spend, so the pair is
            rendered here with no order.
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
