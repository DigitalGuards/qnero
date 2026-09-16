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
 * - **off chain** is held, with its secrets, and its entry in the tree is gone:
 *   a reorg took the block that carried it and no later block re-included it.
 * - **reachable** is what one payment can actually move, which is the two
 *   largest transfers, because one settlement has two input slots.
 */

import { Check, RefreshCw } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router';

import { Amount } from '../components/UI/Amount';
import { Button } from '../components/UI/Button';
import { Notice } from '../components/UI/Notice';
import { Panel } from '../components/UI/Panel';
import { Pill } from '../components/UI/Address';
import { Tooltip } from '../components/UI/Tooltip';
import { Num, Table, TableScroll } from '../components/UI/Table';
import { formatCount, formatStepsAsQnr } from '../lib/units';
import { formatDuration } from '../lib/format';
import { renderMemo } from '../lib/memo';
import { SYNC_PHASES, syncFraction, syncPhaseIndex } from './syncPhases';
import type { Balances, NoteRow, RejectedNote } from '../wallet/model';
import type { SyncReport } from '../wallet/sync';

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
          <button type="button" className="mm-term text-muted">
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

/**
 * A clock that runs while something does, in milliseconds.
 *
 * The sending screen's, kept to the same quarter-second tick: a wait with no
 * clock on it reads as a wait with nothing happening.
 */
function useElapsed(running: boolean): number {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!running) {
      return;
    }
    const started = performance.now();
    const timer = setInterval(() => {
      setElapsed(performance.now() - started);
    }, 250);
    return () => {
      clearInterval(timer);
    };
  }, [running]);
  if (!running && elapsed !== 0) {
    // Adjusted during render rather than in an effect: the reading belongs to
    // the run that produced it, and a run that has ended has no reading.
    setElapsed(0);
  }
  return elapsed;
}

/**
 * A sync, as progress: the bar, the phases in order, and the clock.
 *
 * What it replaces was forty-five words of theory and a spinner inside a
 * disabled button, with stage strings in the explorer's vocabulary. The phase
 * names are this screen's, the counts are the pass's own, and the one sentence
 * under it is the one a reader of a scan wants: nothing about them leaves.
 */
function SyncProgress({
  stage,
  elapsed,
}: {
  stage: { stage: string; detail: string | null } | null;
  elapsed: number;
}): ReactNode {
  const current = syncPhaseIndex(stage?.stage ?? null);
  const detail = current < 0 ? null : stage?.detail;
  return (
    <div className="mt-3 border-t border-edge pt-3" data-testid="sync-progress">
      <div className="elev-inset h-1 w-full overflow-hidden rounded-full bg-field">
        <div
          className="h-full bg-accent-fill transition-[width] duration-300 motion-reduce:transition-none"
          style={{ width: `${Math.min(100, syncFraction(stage?.stage ?? null, detail ?? null) * 100)}%` }}
        />
      </div>
      <ul className="mt-3 list-none space-y-1 p-0 text-meta" data-testid="sync-phases">
        {SYNC_PHASES.map((phase, index) => (
          <li
            key={phase.label}
            className={
              index === current
                ? 'flex justify-between gap-2 text-ink'
                : 'flex justify-between gap-2 text-muted'
            }
            data-state={index < current ? 'done' : index === current ? 'running' : 'waiting'}
          >
            <span>
              {phase.label}
              {index === current && detail !== null && detail !== undefined ? ` ${detail}` : ''}
            </span>
            {index < current && <Check className="mt-0.5 size-3 shrink-0" aria-hidden />}
          </li>
        ))}
      </ul>
      <p className="mt-2 font-mono tabular-nums text-meta text-muted" data-testid="sync-elapsed">
        {formatDuration(elapsed)} elapsed
      </p>
      <p className="mm-note mt-1 text-muted">Your viewing key never leaves this page.</p>
    </div>
  );
}

export function BalanceScreen({
  balances,
  notes,
  rejected,
  readsFrom,
  syncBlocked,
  report,
  syncing,
  syncStage,
  canSync,
  onSync,
}: {
  balances: Balances;
  notes: readonly NoteRow[];
  rejected: readonly RejectedNote[];
  /**
   * The block this wallet starts reading the chain at: its birthday, or zero.
   *
   * On the status line rather than in a banner. A wallet that quietly started
   * above a transfer is a balance quietly short, so the number is on the
   * screen; whose claim it is, and what an honest node that disagrees does
   * with it, is a sentence behind the Last sync disclosure.
   */
  readsFrom: number;
  /**
   * Why reading the chain is unavailable, or null.
   *
   * A disabled control with nothing beside it is a wallet that has stopped and
   * will not say why: the prover case had no signal anywhere outside Settings,
   * and the no-node case had a red dot in the header and nothing here.
   */
  syncBlocked: string | null;
  report: SyncReport | null;
  syncing: boolean;
  /** The stage a running pass is in, and what it is counting. */
  syncStage: { stage: string; detail: string | null } | null;
  canSync: boolean;
  onSync: () => void;
}): ReactNode {
  const elapsed = useElapsed(syncing);
  const conflicted = notes.filter((row) => row.conflictMembers > 1);
  // Newest first, once: the rows and the table are two renderings of one list.
  const ordered = [...notes].sort((a, b) => b.note.leafIndex - a.note.leafIndex);
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
        {/* What this wallet holds: unspent plus the change of its own
            payment, which is written and waiting for the tree. The headline
            read 0.00 QNR the moment after a payment while 6.92 was on its way
            back, a 32 px zero over an 11 px correction, and "what do I have"
            is the question this number answers. */}
        <Amount steps={balances.unspent + balances.pending} testId="balance-held" />
        <p className="mt-1 text-meta text-muted" data-testid="balance-line">
          {balances.pending > 0n
            ? `${formatStepsAsQnr(balances.pending)} pending`
            : 'unspent'}
        </p>
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
                explains="Held with its secrets, and its entry in the tree is gone: a reorg took
                  the block that carried it and no later block has re-included it. It counts in no
                  balance until it comes back."
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
        {syncing && <SyncProgress stage={syncStage} elapsed={elapsed} />}
        <div className="mt-3 flex items-center justify-between gap-2 border-t border-edge pt-3">
          <span className="text-meta text-muted" data-testid="sync-status">
            {syncBlocked !== null
              ? syncBlocked
              : report === null
                ? `reads from block ${formatCount(readsFrom)}`
                : `synced through block ${formatCount(report.head)} · reads from block ` +
                  formatCount(readsFrom)}
          </span>
          {/* A utility button, and the accent is not spent here. The wallet
              reads the chain by itself on open and on each new head; this is
              the one for a reader who wants it now. */}
          <Button disabled={syncing || !canSync} data-testid="do-sync" onClick={onSync}>
            <RefreshCw className="size-3.5" aria-hidden />
            {syncing ? 'Reading…' : 'Refresh'}
          </Button>
        </div>
      </Panel>

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
          {conflicted.length} of these transfers repeat another one this wallet holds. A sender
          picks the randomness behind a transfer, so a repeated pair is two transfers of which at
          most one can ever settle. Both are held; the larger is the one a spend uses, and the pair
          is counted once.
        </Notice>
      )}

      {report !== null &&
        report.warnings.map((warning) => <Notice key={warning}>{warning}</Notice>)}

      {/*
        Hints, under the warnings and behind a summary. A warning is something
        this pass gave up or could not verify, and each one is rare. The
        ciphertext hint fires on nearly every sync, because almost every entry
        on the chain is somebody else's, so rendering it as a warning made the
        rare signal beside it look like the constant one; it is 180 words of
        what two unbound values buy an attacker, which is theory, and theory in
        this wallet reads on request. It is a prompt for an operator waiting on
        a payment, and the summary is that prompt.
      */}
      {report !== null && report.hints.length > 0 && (
        <details className="px-1">
          <summary className="cursor-pointer text-meta text-muted">
            Expecting a payment that is not here?
          </summary>
          <div className="mm-note mt-2 space-y-1 text-muted" data-testid="sync-hints">
            {report.hints.map((hint) => (
              <p key={hint}>{hint}</p>
            ))}
          </div>
        </details>
      )}

      <Panel title="Incoming transfers" flush>
        {notes.length === 0 ? (
          /* One sentence and the two things to do about it. The sentence used
             to be thirty-five words ending at the command-line wallet, which
             was the only way in before the public testnet had a faucet. */
          <div className="px-4" data-testid="notes-empty">
            <p className="text-body text-muted">Nothing received yet.</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button asChild data-testid="empty-receive">
                <Link to="/receive">Show my address</Link>
              </Button>
              <Button asChild data-testid="empty-faucet">
                <a href="https://faucet.qnero.io" target="_blank" rel="noreferrer">
                  Get test QNR from the faucet
                </a>
              </Button>
            </div>
          </div>
        ) : (
          <>
            {/* A transfer on a phone is an amount, a state and a memo. The
                six-column table put two chain counters in front of the amount
                and pushed the memo, the only human-readable thing on a
                payment, 115 px off the right edge of a 341 px scroller. */}
            <ul className="list-none p-0 md:hidden" data-testid="notes-rows">
              {ordered.map((row) => (
                  <li
                    key={row.note.commitment}
                    className="border-t border-edge px-4 py-2 first:border-t-0"
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="mm-memo min-w-0 text-body text-ink">
                        {row.secret === null
                          ? 'locked'
                          : row.secret.memo === ''
                            ? ''
                            : renderMemo(row.secret.memo)}
                      </span>
                      <span className="shrink-0 whitespace-nowrap font-mono text-body tabular-nums text-ink">
                        {formatStepsAsQnr(BigInt(row.note.value))}
                      </span>
                    </div>
                    <div className="mt-1 flex items-baseline justify-between gap-2 text-meta text-muted">
                      <span className="flex items-baseline gap-2">
                        <Pill
                          state={
                            !row.note.onChain ? 'off chain' : row.note.spent ? 'spent' : 'unspent'
                          }
                        />
                        {row.note.origin}
                        {row.conflictMembers > 1 && ` conflict, ${row.conflictMembers} members`}
                      </span>
                      <span className="whitespace-nowrap">
                        {row.note.blockNumber === null
                          ? 'no block'
                          : `block ${formatCount(row.note.blockNumber)}`}
                      </span>
                    </div>
                  </li>
              ))}
            </ul>
            <div className="hidden md:block">
            <TableScroll>
              <Table testId="notes-table">
                <thead>
                  <tr>
                    <th>Block</th>
                    <th className="text-right">Amount</th>
                    <th>
                      <Tooltip
                        label="A shield this wallet made is labelled by matching the chain's own
                          entry counter, and the match is looked for over the newest 64 entries. On a
                          chain with more shields than that, one restored from its seed reads as a
                          transfer. The label moves no value and nothing selects on it."
                      >
                        <button type="button" className="mm-term uppercase tracking-label">
                          Origin
                        </button>
                      </Tooltip>
                    </th>
                    <th>State</th>
                    <th className="w-full">Memo</th>
                  </tr>
                </thead>
                <tbody>
                  {ordered.map((row) => (
                      <tr key={row.note.commitment}>
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
            </div>
          </>
        )}
      </Panel>

      {rejected.length > 0 && (
        <Panel title="Amounts this wallet could not keep" flush>
          <TableScroll>
            <Table>
              <thead>
                <tr>
                  <th>Entry</th>
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
          <p className="mm-note px-4 pt-2 text-muted">
            Provisional. A reorg that orphans the settlement makes the same entry acceptable, and
            the next sync drops the row and keeps the funds.
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
                    <td>entries read</td>
                    <Num>{formatCount(report.leavesScanned)}</Num>
                  </tr>
                  <tr>
                    <td>transfers received</td>
                    <Num>{formatCount(report.received)}</Num>
                    <td>spends the chain settled</td>
                    <Num>{formatCount(report.nullifierSetSize)}</Num>
                  </tr>
                  <tr>
                    <td>mining rewards</td>
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
            <p className="mm-note px-4 pt-2 text-muted" data-testid="reads-from">
              This wallet reads the chain from block {formatCount(readsFrom)}. That is this
              node&apos;s claim about where the chain held nothing of this wallet&apos;s, like
              every checkpoint: a node that disagrees at that height is rewound to there.
            </p>
          </details>
          {report.heldSpent > 0 && (
            <p className="mm-note px-4 pt-2 text-muted">
              {report.heldSpent} transfer{report.heldSpent === 1 ? '' : 's'} kept marked spent:
              their spend markers are absent from this node&apos;s set, and this node has not yet
              reached the block that settled them. Clearing the flag on that reading would put an
              already spent amount back into selection.
            </p>
          )}
          {report.forkedAt !== null && (
            <p className="mm-note px-4 pt-2 text-muted">
              This node is on a different branch above block {formatCount(report.forkedAt)}. The
              watermark was rewound to there and the entries were read again.
            </p>
          )}
        </Panel>
      )}
    </div>
  );
}
