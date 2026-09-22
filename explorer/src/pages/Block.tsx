import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { storageAt } from '../chain/api';
import {
  blockHashAt,
  fetchDetail,
  panelCount,
  type BlockDetail,
  type ExtrinsicRow,
} from '../chain/blocks';
import { decodeU512, formatDifficulty } from '../lib/difficulty';
import { seedHeight } from '../lib/seed';
import {
  formatAgo,
  formatBytes,
  formatCount,
  formatQnr,
  formatUtc,
  REFERENCE_CIPHERTEXT_BYTES,
} from '../lib/units';
import {
  Empty,
  Field,
  Fields,
  Hash,
  NotRead,
  Notice,
  PageSkeleton,
  Panel,
  TableWrap,
  Why,
} from '../components/ui';
import { Problem } from './parts/Problem';
import { SettlementLink, SettlementView } from './parts/SettlementView';

function isHash(id: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(id);
}

export function Block({ id }: { id: string }): ReactNode {
  const { bundle, head } = useChain();
  const resolved = useAsync(
    bundle === null ? null : `resolve:${id}`,
    bundle === null
      ? null
      : async () => {
          if (isHash(id)) {
            return id;
          }
          if (!/^[0-9]+$/.test(id)) {
            throw new Error(`${id} is neither a height nor a 32-byte hash`);
          }
          const hash = await blockHashAt(bundle.context, Number(id));
          if (hash === null) {
            throw new Error(`this chain has no block at height ${id}`);
          }
          return hash;
        },
  );
  const hash = resolved.status === 'ready' ? resolved.value : null;
  const detail = useAsync(
    bundle === null || hash === null ? null : `detail:${hash}`,
    bundle === null || hash === null ? null : () => fetchDetail(bundle.context, hash),
  );
  const storedDifficulty = useAsync(
    bundle === null || hash === null ? null : `difficulty:${hash}`,
    bundle === null || hash === null
      ? null
      : async () => {
          const query = await storageAt(bundle.context, hash, 'qPoW', 'currentDifficulty');
          const value = await query();
          return value.isEmpty ? null : decodeU512(value.toHex());
        },
  );

  if (resolved.status === 'error') {
    return (
      <Problem heading="Block" value={id}>
        {resolved.error}
      </Problem>
    );
  }
  if (bundle === null || detail.status === 'loading' || resolved.status === 'loading') {
    return (
      <PageSkeleton
        title={null}
        panels={[
          { title: 'Summary', fields: 5 },
          { title: 'Header', fields: 6 },
        ]}
      />
    );
  }
  if (detail.status === 'error') {
    return (
      <Problem heading="Block" value={id}>
        {detail.error}
      </Problem>
    );
  }

  const block = detail.value;
  const minedAt = block.difficulty?.oldDifficulty ?? null;
  const afterRetarget =
    block.difficulty?.newDifficulty ??
    (storedDifficulty.status === 'ready' ? storedDifficulty.value : null);
  const constants = bundle.constants;
  const seed =
    constants === null
      ? null
      : seedHeight(block.header.number, constants.seedEpochBlocks, constants.seedEpochLag);
  const isSettlement = (index: number): boolean =>
    block.settlements.some((settlement) => settlement.extrinsicIndex === index);

  return (
    <>
      <header className="page__head">
        {/* Two 32 px buttons beside the heading. They were 13 px inline links
            8 px apart at the end of an ISO timestamp with milliseconds in it. */}
        <div className="page__head--pager">
          <h1>Block {formatCount(block.header.number)}</h1>
          <div className="pager pager--head">
            {block.header.number === 0 ? null : (
              <a
                className="button button--icon"
                href={href({ name: 'block', id: block.header.parentHash })}
                aria-label="Previous block"
                title="Previous block"
              >
                &larr;
              </a>
            )}
            {head === null || block.header.number >= head.header.number ? null : (
              <a
                className="button button--icon"
                href={href({ name: 'block', id: String(block.header.number + 1) })}
                aria-label="Next block"
                title="Next block"
              >
                &rarr;
              </a>
            )}
          </div>
        </div>
      </header>

      {block.stateError === null ? null : (
        <Notice>
          <p>
            The node answered no state at this block, so the coinbase, the settlements, the entries,
            the outcomes and this block&rsquo;s retarget below are empty because they could not be
            read: {block.stateError}. The header and the body are archived, and those are what this
            page still shows.
          </p>
        </Notice>
      )}

      {/* What happened in this block, before the 275 hex characters of how it
          was sealed. The page used to open on the header in storage order: the
          first human number was at about y 760 and the block's answer, its
          coinbase and its settlements, began 1.6 screens down. */}
      <Panel title="Summary">
        <Fields>
          <Field
            label="Time"
            value={
              block.timestampMs === null || block.timestampMs === 0
                ? 'none'
                : `${formatUtc(block.timestampMs)}, ${formatAgo(block.timestampMs)}`
            }
            note={
              block.timestampMs === null || block.timestampMs === 0
                ? 'genesis carries none and a pruned block no longer answers for one'
                : undefined
            }
            wide
          />
          <Field
            label="Coinbase"
            display
            value={
              <span className="num">
                {block.coinbase === null ? '-' : formatQnr(block.coinbase.valuePlanck)}
              </span>
            }
            note={
              block.coinbase !== null
                ? undefined
                : block.stateError === null
                  ? 'this block minted no coinbase note'
                  : 'state not kept at this block, so this is not an absence'
            }
          />
          <Field
            label="Settlements"
            display
            value={
              <span className="num">
                {block.stateError === null ? formatCount(block.settlements.length) : '-'}
              </span>
            }
            note={block.stateError === null ? undefined : 'not counted: the state read failed'}
          />
          <Field
            label="Shield entries"
            display
            value={
              <span className="num">
                {block.stateError === null ? formatCount(block.entries.length) : '-'}
              </span>
            }
            note={block.stateError === null ? undefined : 'not counted: the state read failed'}
          />
          <Field
            label="Extrinsics"
            display
            value={<span className="num">{formatCount(block.extrinsics.length)}</span>}
            note="the body is archived, so this count is read whatever the state answers"
          />
        </Fields>
      </Panel>

      <Panel title="Header">
        <Fields>
          {/* The block hash is the one value shown whole: it is what a reader
              came here holding or is about to paste somewhere. The rest are
              head and tail with the whole value one press away. */}
          <Field label="Hash" value={<Hash value={block.hash} full copy />} wide />
          <Field
            label="Parent"
            value={
              // Genesis names an all-zero parent that is no block, which is why
              // the lede drops "previous" there too.
              block.header.number === 0 ? (
                <Hash value={block.header.parentHash} copy />
              ) : (
                <Hash
                  value={block.header.parentHash}
                  href={href({ name: 'block', id: block.header.parentHash })}
                  copy
                />
              )
            }
            note={block.header.number === 0 ? 'genesis has no parent on this chain' : undefined}
            wide
          />
          <Field
            label="Author label"
            value={
              block.header.authorLabel === null ? (
                <span className="dim">none</span>
              ) : (
                <Hash value={block.header.authorLabel} copy />
              )
            }
            note="H(cvk, parent_hash): a label for this block alone, which changes with the parent"
            wide
          />
          <Field label="zk tree root" value={<Hash value={block.header.zkTreeRoot} copy />} wide />
          <Field label="State root" value={<Hash value={block.header.stateRoot} copy />} />
          <Field label="Extrinsics root" value={<Hash value={block.header.extrinsicsRoot} copy />} />
          <Field
            label="Mined at difficulty"
            value={<span className="num">{minedAt === null ? '-' : formatDifficulty(minedAt)}</span>}
            note={
              minedAt !== null
                ? 'from this block’s retarget'
                : block.stateError === null
                  ? 'no retarget event in this block'
                  : 'state not kept at this block, so the retarget event could not be read'
            }
          />
          <Field
            label="Difficulty after"
            value={
              <span className="num">{afterRetarget === null ? '-' : formatDifficulty(afterRetarget)}</span>
            }
            note={
              block.difficulty !== null
                ? `observed block time ${formatCount(block.difficulty.observedBlockTimeMs)} ms`
                : storedDifficulty.status === 'error'
                  ? 'the node did not answer QPoW::CurrentDifficulty at this block'
                  : storedDifficulty.status === 'loading'
                    ? 'reading QPoW::CurrentDifficulty at this block'
                    : storedDifficulty.value === null
                      ? 'the chain holds no QPoW::CurrentDifficulty at this block'
                      : 'QPoW::CurrentDifficulty at this block'
            }
          />
          <Field
            label="RandomX seed height"
            value={<span className="num">{seed === null ? '-' : formatCount(seed)}</span>}
            note={
              seed === null
                ? 'the runtime did not answer the seed epoch constants'
                : 'computed from the height; the chain holds no seed'
            }
          />
          <Field
            label="Seal"
            value={block.header.seal === null ? <span className="dim">none</span> : <Hash value={block.header.seal} />}
            note="4-byte nonce and 4-byte extra nonce, the rest pinned to zero"
          />
        </Fields>
      </Panel>

      <Panel title="Coinbase note">
        {block.coinbase === null ? (
          block.stateError === null ? (
            <Empty>This block minted no coinbase note.</Empty>
          ) : (
            <NotRead what="the coinbase note" error={block.stateError} />
          )
        ) : (
          <Fields>
            <Field label="Value" value={<span className="num">{formatQnr(block.coinbase.valuePlanck)}</span>} />
            <Field
              label="Leaf index"
              value={<span className="num">{formatCount(block.coinbase.leafIndex)}</span>}
            />
            <Field
              label="Emission credited"
              value={
                <span className="num">
                  {block.coinbase.creditedPlanck === null
                    ? '-'
                    : formatQnr(block.coinbase.creditedPlanck)}
                </span>
              }
              note="block reward plus transparent fees, before the settled-fee share"
            />
            <Field
              label="Settled fees folded in"
              value={<span className="num">{formatQnr(block.coinbase.authorFeePlanck)}</span>}
            />
            <Field label="Inner hash" value={<Hash value={block.coinbase.inner} copy />} wide
              note="published in the clear and still opaque: recognising it takes the matching coinbase viewing key together with the miner’s address" />
          </Fields>
        )}
      </Panel>

      <Panel title={`Settlements ${panelCount(block.settlements, block.stateError)}`}>
        {block.settlements.length === 0 ? (
          block.stateError === null ? (
            <Empty>No settlement landed in this block.</Empty>
          ) : (
            <NotRead what="the settlements" error={block.stateError} />
          )
        ) : (
          block.settlements.map((settlement) => {
            const extrinsic =
              settlement.extrinsicIndex === null
                ? undefined
                : block.extrinsics[settlement.extrinsicIndex];
            return (
              <div key={settlement.extrinsicIndex ?? 'finalization'}>
                {extrinsic === undefined ? null : (
                  <p>
                    <SettlementLink txHash={extrinsic.hash} blockHash={block.hash}>
                      {extrinsic.name}, extrinsic {formatCount(extrinsic.index)}
                    </SettlementLink>{' '}
                    · {formatBytes(extrinsic.byteLength)}
                  </p>
                )}
                <SettlementView settlement={settlement} blockHeight={block.header.number} />
              </div>
            );
          })
        )}
      </Panel>

      <Panel title={`Shield entries ${panelCount(block.entries, block.stateError)}`}>
        {block.entries.length === 0 ? (
          block.stateError === null ? (
            <Empty>No transparent value entered the pool in this block.</Empty>
          ) : (
            <NotRead what="the shield entries" error={block.stateError} />
          )
        ) : (
          <>
            {/* Reading matter, so it reads as reading matter. It was a yellow
                box, which is the one colour this site has for state. */}
            <p>A shield is the one linkable event in the system, and it is so by construction.</p>
            <Why summary="Why a shield is linkable">
              <p>
                It is a signed extrinsic, so the payer&rsquo;s account, the exact amount and the
                leaf index are on chain together: the value it moves is transparent until the
                moment it is burned.
              </p>
            </Why>
            <TableWrap label="Shield entries in this block">
              <table>
                <thead>
                  <tr>
                    {/* A phone keeps the three columns a shield reader came
                        for. The signer was 40 characters wide and pushed Value,
                        the one number they came for, off the screen. */}
                    <th className="col--wide" scope="col">
                      Signer
                    </th>
                    <th scope="col">Value</th>
                    <th scope="col">Leaf</th>
                    <th scope="col">Entry</th>
                    <th className="col--wide" scope="col">
                      Commitment
                    </th>
                    <th className="col--wide" scope="col">
                      Ciphertext
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {block.entries.map((entry) => (
                    <tr key={entry.commitment}>
                      <td className="mono col--wide" title={entry.who}>
                        {entry.who.length > 12 ? `${entry.who.slice(0, 12)}…` : entry.who}
                      </td>
                      <td className="num">{formatQnr(entry.valuePlanck)}</td>
                      <td className="num">{formatCount(entry.leafIndex)}</td>
                      <td className="num">{formatCount(entry.entryIndex)}</td>
                      <td className="col--wide">
                        <Hash value={entry.commitment} />
                      </td>
                      <td className="num col--wide">
                        {formatBytes(entry.ciphertextBytes)}
                        {/* A shield entry note, where the cap is still the rule and the
                            pad is still a convention: the exact-length rule is scoped to
                            settlement. A settlement output that is not the reference size
                            is an invariant violation, and `SettlementView` says so. */}
                        {entry.ciphertextBytes === REFERENCE_CIPHERTEXT_BYTES ? '' : ' (non-reference)'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </>
        )}
      </Panel>

      <RefusedCalls block={block} />
      <OtherExtrinsics block={block} isSettlement={isSettlement} />
    </>
  );
}

/**
 * The calls this block admitted and that then failed.
 *
 * A call the runtime's filter refuses is invalid at validation, so it reaches
 * no block and appears here never. The `CallFiltered` rendering below is kept
 * for the one layer the filter still guards at dispatch, an internally
 * dispatched call, which is the only way that error can still reach an event.
 *
 * The panel is dropped only when a state read answered and held no failure. A
 * failure is an event, and an unread event log decodes to none, so dropping the
 * panel over one reported "nothing failed in this block" by absence, on the
 * panel a reader opens to find out whether anything did.
 */
function RefusedCalls({ block }: { block: BlockDetail }): ReactNode {
  if (block.stateError === null && block.failures.length === 0) {
    return null;
  }
  return (
    <Panel title={`Failed calls ${panelCount(block.failures, block.stateError)}`}>
      {block.stateError === null ? null : (
        <NotRead what="the failed calls" error={block.stateError} />
      )}
      {block.failures.length === 0 ? null : (
        <>
          <p>
            A call that failed is still a valid extrinsic, and its arguments stay in the block body.
          </p>
          <Why summary="Why this page names the call and not the arguments">
            <p>
              A call the runtime&rsquo;s filter refuses never gets this far: it is invalid at
              validation, so it enters no block and publishes nothing. What reaches a block is a
              call that was admitted and then failed on its own terms, and its full arguments are in
              the body forever. Reprinting them here would publish them a second time in a form
              built for reading.
            </p>
          </Why>
        </>
      )}
      {block.failures.length === 0 ? null : (
        <TableWrap label="Failed calls in this block">
          <table>
            <thead>
              <tr>
                <th scope="col">Extrinsic</th>
                <th scope="col">Call</th>
                <th scope="col">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {block.failures.map((failure) => {
                const extrinsic =
                  failure.extrinsicIndex === null ? undefined : block.extrinsics[failure.extrinsicIndex];
                return (
                  <tr key={`${failure.extrinsicIndex}-${failure.kind}`}>
                    <td className="num">{failure.extrinsicIndex ?? '-'}</td>
                    <td className="mono">{extrinsic?.name ?? 'unresolved'}</td>
                    <td>
                      {failure.filtered ? 'refused by the call filter' : failure.kind}
                      {failure.detail === null ? '' : ` (${failure.detail})`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Panel>
  );
}

function summaryOf(extrinsic: ExtrinsicRow): string {
  if (extrinsic.unresolved !== null) {
    return `envelope only: ${extrinsic.unresolved}`;
  }
  return extrinsic.kind === 'bare' ? 'unsigned or inherent' : extrinsic.kind;
}

/**
 * Every extrinsic in the block, summarised.
 *
 * Only a settlement links to the settlement page. A timestamp inherent or a
 * coinbase opened there would be titled as a settlement and would carry the
 * settlement's statement of what a spend publishes, over an extrinsic that
 * spent nothing.
 */
function OtherExtrinsics({
  block,
  isSettlement,
}: {
  block: BlockDetail;
  isSettlement: (index: number) => boolean;
}): ReactNode {
  if (block.extrinsics.length === 0) {
    return (
      <Panel title="Extrinsics (0)">
        <Empty>This block carries no extrinsics.</Empty>
      </Panel>
    );
  }
  return (
    <Panel title={`Extrinsics (${formatCount(block.extrinsics.length)})`}>
      <TableWrap label="Extrinsics in this block">
        <table>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Call</th>
              <th className="col--wide" scope="col">
                Kind
              </th>
              <th className="col--wide" scope="col">
                Size
              </th>
              <th className="col--wide" scope="col">
                Hash
              </th>
              <th scope="col">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {block.extrinsics.map((extrinsic) => (
              <tr key={extrinsic.hash}>
                <td className="num">{extrinsic.index}</td>
                {/* The link is on the call, which is the column a phone keeps.
                    On the hash it disappeared with the three columns that drop
                    at phone width, and the row's identity is what it called. A
                    row that leads somewhere is the whole target: the link was
                    14 px tall in a 44 px row. */}
                <td className={isSettlement(extrinsic.index) ? 'mono row-link' : 'mono'}>
                  {isSettlement(extrinsic.index) ? (
                    <SettlementLink txHash={extrinsic.hash} blockHash={block.hash}>
                      {extrinsic.name}
                    </SettlementLink>
                  ) : (
                    extrinsic.name
                  )}
                </td>
                <td className="col--wide">{summaryOf(extrinsic)}</td>
                <td className="num col--wide">{formatBytes(extrinsic.byteLength)}</td>
                <td className="col--wide">
                  <span className="mono" title={extrinsic.hash}>
                    {extrinsic.hash.slice(0, 10)}…
                  </span>
                </td>
                <td className={extrinsic.succeeded === null ? 'dim' : undefined}>
                  {extrinsic.succeeded === null ? (
                    <span title={block.stateError ?? undefined}>state not kept at this block</span>
                  ) : extrinsic.succeeded ? (
                    'succeeded'
                  ) : (
                    'failed'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Panel>
  );
}
