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
import { formatBytes, formatCount, formatQnr, REFERENCE_CIPHERTEXT_BYTES } from '../lib/units';
import {
  Empty,
  Field,
  Fields,
  Hash,
  NotRead,
  Notice,
  PageSkeleton,
  Panel,
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
        <h1>Block {formatCount(block.header.number)}</h1>
        <p className="page__lede">
          {block.timestampMs === null || block.timestampMs === 0
            ? 'no timestamp: genesis carries none and a pruned block no longer answers for one'
            : new Date(block.timestampMs).toISOString()}
          {block.header.number === 0 ? null : (
            <>
              {' · '}
              <a href={href({ name: 'block', id: block.header.parentHash })}>previous</a>
            </>
          )}
          {head === null || block.header.number >= head.header.number ? null : (
            <>
              {' · '}
              <a href={href({ name: 'block', id: String(block.header.number + 1) })}>next</a>
            </>
          )}
        </p>
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

      <Panel title="Header">
        <Fields>
          <Field label="Hash" value={<Hash value={block.hash} full />} wide />
          <Field
            label="Parent"
            value={
              // Genesis names an all-zero parent that is no block, which is why
              // the lede drops "previous" there too.
              block.header.number === 0 ? (
                <Hash value={block.header.parentHash} full />
              ) : (
                <Hash
                  value={block.header.parentHash}
                  href={href({ name: 'block', id: block.header.parentHash })}
                  full
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
                <Hash value={block.header.authorLabel} full />
              )
            }
            note="H(cvk, parent_hash): a label for this block alone, which changes with the parent"
            wide
          />
          <Field label="zk tree root" value={<Hash value={block.header.zkTreeRoot} full />} wide />
          <Field label="State root" value={<Hash value={block.header.stateRoot} />} />
          <Field label="Extrinsics root" value={<Hash value={block.header.extrinsicsRoot} />} />
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
            <Field label="Inner hash" value={<Hash value={block.coinbase.inner} full />} wide
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
            <Notice>
              <p>
                A shield is a signed extrinsic, so the payer&rsquo;s account, the exact amount and
                the leaf index are on chain together. This is the one linkable event in the system,
                and it is linkable by construction: the value it moves is transparent until the
                moment it is burned.
              </p>
            </Notice>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Signer</th>
                    <th scope="col">Value</th>
                    <th scope="col">Leaf</th>
                    <th scope="col">Entry</th>
                    <th scope="col">Commitment</th>
                    <th scope="col">Ciphertext</th>
                  </tr>
                </thead>
                <tbody>
                  {block.entries.map((entry) => (
                    <tr key={entry.commitment}>
                      <td className="mono">{entry.who}</td>
                      <td className="num">{formatQnr(entry.valuePlanck)}</td>
                      <td className="num">{formatCount(entry.leafIndex)}</td>
                      <td className="num">{formatCount(entry.entryIndex)}</td>
                      <td>
                        <Hash value={entry.commitment} />
                      </td>
                      <td className="num">
                        {formatBytes(entry.ciphertextBytes)}
                        {entry.ciphertextBytes === REFERENCE_CIPHERTEXT_BYTES ? '' : ' (non-reference)'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      <RefusedCalls block={block} />
      <OtherExtrinsics block={block} isSettlement={isSettlement} />
    </>
  );
}

/**
 * The calls this block refused, and the ones that failed for another reason.
 *
 * The panel is dropped only when a state read answered and held no failure. A
 * failure is an event, and an unread event log decodes to none, so dropping the
 * panel over one reported "nothing was refused in this block" by absence, on
 * the panel a reader opens to find out whether anything was.
 */
function RefusedCalls({ block }: { block: BlockDetail }): ReactNode {
  const filtered = block.failures.filter((failure) => failure.filtered);
  if (block.stateError === null && block.failures.length === 0) {
    return null;
  }
  return (
    <Panel title={`Refused and failed calls ${panelCount(block.failures, block.stateError)}`}>
      {block.stateError === null ? null : (
        <NotRead what="the refused and failed calls" error={block.stateError} />
      )}
      {filtered.length === 0 ? null : (
        <Notice>
          <p>
            A call the runtime&rsquo;s filter refuses is still a valid extrinsic: it entered this
            block, paid its fee, and then failed. Its full arguments are in the block body forever,
            so a mistaken transparent transfer publishes exactly the sender, recipient and amount
            the chain&rsquo;s policy exists to deny.
          </p>
          <p>
            This page names the call and leaves the arguments where the chain put them. Reprinting
            them here would publish them a second time in a form built for reading.
          </p>
        </Notice>
      )}
      {block.failures.length === 0 ? null : (
        <div className="table-wrap">
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
        </div>
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
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Call</th>
              <th scope="col">Kind</th>
              <th scope="col">Size</th>
              <th scope="col">Hash</th>
              <th scope="col">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {block.extrinsics.map((extrinsic) => (
              <tr key={extrinsic.hash}>
                <td className="num">{extrinsic.index}</td>
                <td className="mono">{extrinsic.name}</td>
                <td>{summaryOf(extrinsic)}</td>
                <td className="num">{formatBytes(extrinsic.byteLength)}</td>
                <td>
                  {isSettlement(extrinsic.index) ? (
                    <SettlementLink txHash={extrinsic.hash} blockHash={block.hash}>
                      <span className="mono">{extrinsic.hash.slice(0, 10)}…</span>
                    </SettlementLink>
                  ) : (
                    <span className="mono" title={extrinsic.hash}>
                      {extrinsic.hash.slice(0, 10)}…
                    </span>
                  )}
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
      </div>
    </Panel>
  );
}
