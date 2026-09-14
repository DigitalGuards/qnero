import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { storageAt } from '../chain/api';
import { blockHashAt, fetchDetail, type BlockDetail, type ExtrinsicRow } from '../chain/blocks';
import { decodeU512, formatDifficulty } from '../lib/difficulty';
import { seedHeight } from '../lib/seed';
import { formatBytes, formatCount, formatQnr, REFERENCE_CIPHERTEXT_BYTES } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Hash, Loading, Notice, Panel } from '../components/ui';
import { SettlementLink, SettlementView } from './parts/SettlementView';

function isHash(id: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(id);
}

export function Block({ id }: { id: string }): ReactNode {
  const { bundle } = useChain();
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
    return <ErrorBox>{resolved.error}</ErrorBox>;
  }
  if (bundle === null || detail.status === 'loading' || resolved.status === 'loading') {
    return <Loading what="the block" />;
  }
  if (detail.status === 'error') {
    return <ErrorBox>{detail.error}</ErrorBox>;
  }

  const block = detail.value;
  const minedAt = block.difficulty?.oldDifficulty ?? null;
  const afterRetarget =
    block.difficulty?.newDifficulty ??
    (storedDifficulty.status === 'ready' ? storedDifficulty.value : null);
  const seed = seedHeight(
    block.header.number,
    bundle.constants.seedEpochBlocks,
    bundle.constants.seedEpochLag,
  );

  return (
    <>
      <header className="page__head">
        <h1>Block {formatCount(block.header.number)}</h1>
        <p className="page__lede">
          {new Date(block.timestampMs).toISOString()} ·{' '}
          <a href={href({ name: 'block', id: String(block.header.number - 1) })}>previous</a> ·{' '}
          <a href={href({ name: 'block', id: String(block.header.number + 1) })}>next</a>
        </p>
      </header>

      <Panel title="Header">
        <Fields>
          <Field label="Hash" value={<Hash value={block.hash} full />} wide />
          <Field
            label="Parent"
            value={<Hash value={block.header.parentHash} href={href({ name: 'block', id: block.header.parentHash })} full />}
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
            note={minedAt === null ? 'no retarget event in this block' : 'from this block’s retarget'}
          />
          <Field
            label="Difficulty after"
            value={
              <span className="num">{afterRetarget === null ? '-' : formatDifficulty(afterRetarget)}</span>
            }
            note={
              block.difficulty === null
                ? 'QPoW::CurrentDifficulty at this block'
                : `observed block time ${formatCount(block.difficulty.observedBlockTimeMs)} ms`
            }
          />
          <Field
            label="RandomX seed height"
            value={<span className="num">{formatCount(seed)}</span>}
            note="computed from the height; the chain holds no seed"
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
          <Empty>This block minted no coinbase note.</Empty>
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
              note="published in the clear and still opaque: only the holder of the matching coinbase viewing key can recognise it" />
          </Fields>
        )}
      </Panel>

      <Panel title={`Settlements (${formatCount(block.settlements.length)})`}>
        {block.settlements.length === 0 ? (
          <Empty>No settlement landed in this block.</Empty>
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

      <Panel title={`Shield entries (${formatCount(block.entries.length)})`}>
        {block.entries.length === 0 ? (
          <Empty>No transparent value entered the pool in this block.</Empty>
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
      <OtherExtrinsics block={block} />
    </>
  );
}

function RefusedCalls({ block }: { block: BlockDetail }): ReactNode {
  const filtered = block.failures.filter((failure) => failure.filtered);
  const other = block.failures.filter((failure) => !failure.filtered);
  if (filtered.length === 0 && other.length === 0) {
    return null;
  }
  return (
    <Panel title={`Refused and failed calls (${formatCount(block.failures.length)})`}>
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
    </Panel>
  );
}

function summaryOf(extrinsic: ExtrinsicRow): string {
  if (extrinsic.unresolved !== null) {
    return `envelope only: ${extrinsic.unresolved}`;
  }
  return extrinsic.kind === 'bare' ? 'unsigned or inherent' : extrinsic.kind;
}

function OtherExtrinsics({ block }: { block: BlockDetail }): ReactNode {
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
                  <SettlementLink txHash={extrinsic.hash} blockHash={block.hash}>
                    <span className="mono">{extrinsic.hash.slice(0, 10)}…</span>
                  </SettlementLink>
                </td>
                <td>{extrinsic.succeeded ? 'succeeded' : 'failed'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
