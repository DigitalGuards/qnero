/**
 * The balance, and the notes under it.
 *
 * MyMonero puts the balance at the top, alone, as the largest thing on the
 * screen, with the transaction list under it, and dims the fractional part so
 * a long number still reads at a glance. Both hold here. What changes is that
 * a shielded wallet's balance is four numbers rather than one, and three of
 * them only appear when something has gone wrong. Rolling them into a single
 * figure is what would hide the state that matters.
 *
 * - **unspent** is spendable, on chain, counted once per nullifier.
 * - **pending** is written by this wallet and not yet met in the tree.
 * - **off chain** is held, with its secrets, and its leaf is gone: a reorg took
 *   the block that carried it and no later block has re-included it.
 * - **reachable** is what one payment can actually move, which is the two
 *   largest notes, because the leaf has two input slots.
 */

import { RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';

import { Button } from '../components/UI/Button';
import { Empty, Notice } from '../components/UI/Notice';
import { Panel } from '../components/UI/Panel';
import { Pill } from '../components/UI/Address';
import { Tooltip } from '../components/UI/Tooltip';
import { Num, Table, TableScroll } from '../components/UI/Table';
import { formatCount, formatStepsAsQnr, splitAmountForDisplay } from '../lib/units';
import { renderMemo } from '../lib/memo';
import type { Balances, NoteRow, RejectedNote } from '../wallet/model';
import type { SyncReport } from '../wallet/sync';

/**
 * The amount, split so the padding can be dimmed and nothing else.
 *
 * Amounts move in steps of 0.01 QNR, so a shielded balance carries exactly two
 * significant decimals and no padding at all: in practice this renders at one
 * weight, which is what MyMonero does for an amount with nothing to pad. See
 * [`splitAmountForDisplay`].
 */
function Amount({ steps, testId }: { steps: bigint; testId?: string }): ReactNode {
  const { significant, pad } = splitAmountForDisplay(formatStepsAsQnr(steps).replace(' QNR', ''));
  return (
    <div className="mm-balance text-ink" data-testid={testId}>
      {significant}
      {pad !== '' && <span className="mm-balance-fraction">{pad}</span>}
      {/* A real space, because the margin is only an optical gap. Without it
          the element's text is "10.00QNR" to anything that reads it rather
          than looks at it: a screen reader, a copy-paste, the `balance-unspent`
          probe in the end-to-end suite. */}{' '}
      <span className="text-ui font-normal text-muted">QNR</span>
    </div>
  );
}

/**
 * One figure, with the sentence that says what it counts.
 *
 * The term is a button because a tooltip has to be reachable by keyboard, and
 * what is inside one is never the only place a thing is said: the notices
 * under this panel carry the same sentences at full length.
 */
function Stat({
  term,
  explains,
  value,
  testId,
}: {
  term: string;
  explains: string;
  value: string;
  testId?: string;
}): ReactNode {
  return (
    <div className="flex justify-between gap-2">
      <dt className="min-w-0">
        <Tooltip label={explains}>
          <button
            type="button"
            className="cursor-help text-left text-muted underline decoration-dotted underline-offset-2"
          >
            {term}
          </button>
        </Tooltip>
      </dt>
      <dd className="font-mono tabular-nums text-ink" data-testid={testId}>
        {value}
      </dd>
    </div>
  );
}

export function BalanceScreen({
  balances,
  notes,
  rejected,
  report,
  syncing,
  syncStage,
  canSync,
  onSync,
}: {
  balances: Balances;
  notes: readonly NoteRow[];
  rejected: readonly RejectedNote[];
  report: SyncReport | null;
  syncing: boolean;
  syncStage: string | null;
  canSync: boolean;
  onSync: () => void;
}): ReactNode {
  const conflicted = notes.filter((row) => row.conflictMembers > 1);
  // Three of these four figures are about something having gone wrong, and a
  // figure that is only interesting when it is not zero is noise when it is.
  // A new wallet showed four dotted-underlined terms over four zeros on a
  // screen whose whole job is one number; MyMonero hides its own secondary
  // balances line outright when there is nothing in it.
  const showReachable = balances.reachable !== balances.unspent;
  const showPending = balances.pending > 0n;
  const showOffChain = balances.offChain > 0n;
  const showCount = balances.noteCount > 0;
  const showStats = showReachable || showPending || showOffChain || showCount;
  return (
    <div className="space-y-3">
      <Panel>
        <Amount steps={balances.unspent} testId="balance-unspent" />
        <p className="mt-1 text-meta text-muted">unspent</p>
        {/* The track count follows the content. Fixed at two columns, the
            common case of one visible figure rendered a half-width row and put
            the number in the middle of the panel with the right half empty,
            which is the screen a wallet lands on the moment its first payment
            arrives. */}
        {showStats && (
          <dl
            className="mt-3 grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-x-4 gap-y-1
              border-t border-edge pt-3 text-meta"
          >
            {showReachable && (
              <Stat
                term="reachable in one payment"
                explains="One payment has two input slots, so it can spend at most two of the
                  transfers this wallet holds. A balance spread over more than two is held and not
                  reachable until it is merged."
                value={formatStepsAsQnr(balances.reachable)}
                testId="balance-reachable"
              />
            )}
            {showPending && (
              <Stat
                term="pending"
                explains="Written by this wallet and not yet met in the tree: the change from your
                  own payment, whose settlement has been submitted."
                value={formatStepsAsQnr(balances.pending)}
                testId="balance-pending"
              />
            )}
            {showOffChain && (
              <Stat
                term="off chain"
                explains="Held with its secrets, and its leaf is gone: a reorg took the block that
                  carried it and no later block has re-included it. It counts in no balance until it
                  comes back."
                value={formatStepsAsQnr(balances.offChain)}
                testId="balance-offchain"
              />
            )}
            {showCount && (
              <Stat
                term="transfers held"
                explains="Every incoming transfer this wallet holds, spent and unspent, on chain and
                  off. The table below collapses a repeated pair to the one a spend could use, so it
                  can be shorter than this."
                value={formatCount(balances.noteCount)}
              />
            )}
          </dl>
        )}
        <div className="mt-3 flex items-center justify-between gap-2 border-t border-edge pt-3">
          <span className="text-meta text-muted">
            {report === null
              ? 'not synced this session'
              : `synced through block ${formatCount(report.head)}`}
          </span>
          <Button variant="action" disabled={syncing || !canSync} data-testid="do-sync" onClick={onSync}>
            <RefreshCw className={syncing ? 'size-3.5 animate-spin' : 'size-3.5'} aria-hidden />
            {syncing ? 'Syncing…' : 'Sync'}
          </Button>
        </div>
      </Panel>

      {syncing && (
        <Notice testId="sync-progress">
          Syncing{syncStage === null ? '' : `: ${syncStage}`}. Every ciphertext on the chain is read
          and tried against this wallet&apos;s viewing key, and the whole set of settled spend
          markers is paged, so the node is never told which leaves or which markers are this
          wallet&apos;s.
        </Notice>
      )}

      {balances.reachable < balances.unspent && (
        <Notice>
          One payment reaches {formatStepsAsQnr(balances.reachable)} of{' '}
          {formatStepsAsQnr(balances.unspent)}. One payment has two input slots, so a balance spread
          over more than two incoming transfers is not reachable in one spend: send yourself the
          largest ones to merge them.
        </Notice>
      )}

      {conflicted.length > 0 && (
        <Notice>
          {conflicted.length} of these transfers would be spent by the same marker as another this
          wallet holds. A sender picks the randomness behind that marker, so a repeated pair is two
          transfers of which at most one can ever settle. Both are held; the larger is the one a
          spend uses, and the pair is counted once.
        </Notice>
      )}

      {report !== null &&
        report.warnings.map((warning) => <Notice key={warning}>{warning}</Notice>)}

      {/*
        Hints, under the warnings and at less weight. A warning is something
        this pass gave up or could not verify, and each one is rare. The
        ciphertext hint fires on nearly every sync, because almost every leaf
        on the chain is somebody else's, so rendering it as a warning made the
        rare signal beside it look like the constant one. It is a prompt for
        an operator waiting on a payment, and it reads as one here.
      */}
      {report !== null && report.hints.length > 0 && (
        <div className="space-y-1 px-1 text-meta text-muted" data-testid="sync-hints">
          {report.hints.map((hint) => (
            <p key={hint}>{hint}</p>
          ))}
        </div>
      )}

      <Panel title="Incoming transfers" flush>
        {notes.length === 0 ? (
          <Empty>
            Nothing received yet. A wallet receives value when somebody pays its address, when a
            node configured with its miner key wins a block, or when a transparent account shields
            into it from the command-line wallet.
          </Empty>
        ) : (
          <TableScroll>
            <Table testId="notes-table">
              <thead>
                <tr>
                  <th>Leaf</th>
                  <th>Block</th>
                  <th className="text-right">Amount</th>
                  <th>
                    <Tooltip
                      label="A shield this wallet made is labelled by matching the chain's own
                        entry counter, and the match is looked for over the newest 64 entries. On a
                        chain with more shields than that, one restored from its seed reads as a
                        transfer. The label moves no value and nothing selects on it."
                    >
                      <button
                        type="button"
                        className="cursor-help text-left uppercase tracking-label underline
                          decoration-dotted underline-offset-2"
                      >
                        Origin
                      </button>
                    </Tooltip>
                  </th>
                  <th>State</th>
                  <th className="w-full">Memo</th>
                </tr>
              </thead>
              <tbody>
                {[...notes]
                  .sort((a, b) => b.note.leafIndex - a.note.leafIndex)
                  .map((row) => (
                    <tr key={row.note.commitment}>
                      <Num>{row.note.leafIndex}</Num>
                      <Num>{row.note.blockNumber ?? '-'}</Num>
                      <Num>{formatStepsAsQnr(BigInt(row.note.value))}</Num>
                      <td>
                        {row.note.origin}
                        {row.conflictMembers > 1 && (
                          <span className="text-muted"> conflict, {row.conflictMembers} members</span>
                        )}
                      </td>
                      <td>
                        <Pill
                          state={
                            !row.note.onChain ? 'off chain' : row.note.spent ? 'spent' : 'unspent'
                          }
                        />
                      </td>
                      <td>
                        {row.secret === null ? (
                          <span className="text-muted">locked</span>
                        ) : row.secret.memo === '' ? (
                          <span className="text-muted">-</span>
                        ) : (
                          <span className="mm-memo">{renderMemo(row.secret.memo)}</span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </Table>
          </TableScroll>
        )}
      </Panel>

      {rejected.length > 0 && (
        <Panel title="Amounts this wallet could not keep" flush>
          <TableScroll>
            <Table>
              <thead>
                <tr>
                  <th>Leaf</th>
                  <th className="text-right">Amount</th>
                  <th className="w-full">Reason</th>
                </tr>
              </thead>
              <tbody>
                {rejected.map((entry) => (
                  <tr key={entry.commitment}>
                    <Num>{entry.leafIndex}</Num>
                    <Num>{formatStepsAsQnr(BigInt(entry.value))}</Num>
                    <td>{entry.reason}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableScroll>
          <p className="px-4 pt-2 text-meta text-muted">
            Provisional. A reorg that orphans the settlement makes the same leaf acceptable, and the
            next sync drops the row and keeps the funds.
          </p>
        </Panel>
      )}

      {report !== null && (
        <Panel title="Last sync" flush>
          {/* Ten figures of instrumentation was the biggest thing under the
              balance, larger than the notes table. It is worth keeping and it
              is not what this screen is for, so it reads on request, the way
              the send screen's prover figures do. The two warning paragraphs
              stay outside the disclosure: an anomaly has to be visible
              without a click. */}
          <details>
            <summary className="cursor-pointer px-4 pt-2 text-meta text-muted">
              What the last sync read
            </summary>
            <TableScroll>
              <Table>
                <tbody>
                  <tr>
                    <td>head</td>
                    <Num>{formatCount(report.head)}</Num>
                    <td>leaves read</td>
                    <Num>{formatCount(report.leavesScanned)}</Num>
                  </tr>
                  <tr>
                    <td>transfers received</td>
                    <Num>{formatCount(report.received)}</Num>
                    <td>settled spend markers</td>
                    <Num>{formatCount(report.nullifierSetSize)}</Num>
                  </tr>
                  <tr>
                    <td>coinbase leaves</td>
                    <Num>{formatCount(report.coinbaseLeaves)}</Num>
                    <td>of them this wallet&apos;s</td>
                    <Num>{formatCount(report.coinbaseReceived)}</Num>
                  </tr>
                  <tr>
                    <td>newly spent</td>
                    <Num>{formatCount(report.newlySpent)}</Num>
                    <td>newly unspent</td>
                    <Num>{formatCount(report.newlyUnspent)}</Num>
                  </tr>
                  <tr>
                    <td>relocated</td>
                    <Num>{formatCount(report.relocated)}</Num>
                    <td>marked off chain</td>
                    <Num>{formatCount(report.vanished)}</Num>
                  </tr>
                </tbody>
              </Table>
            </TableScroll>
          </details>
          {report.heldSpent > 0 && (
            <p className="px-4 pt-2 text-meta text-muted">
              {report.heldSpent} transfer{report.heldSpent === 1 ? '' : 's'} kept marked spent:
              their spend markers are absent from this node&apos;s set, and this node has not yet
              reached the block that settled them. Clearing the flag on that reading would put an
              already spent amount back into selection.
            </p>
          )}
          {report.forkedAt !== null && (
            <p className="px-4 pt-2 text-meta text-muted">
              This node is on a different branch above block {formatCount(report.forkedAt)}. The
              watermark was rewound to there and the leaves were walked again.
            </p>
          )}
        </Panel>
      )}
    </div>
  );
}
