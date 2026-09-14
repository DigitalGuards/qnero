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
import { formatCount, formatQuantaAsQnr } from '../lib/units';
import { renderMemo } from '../lib/memo';
import type { Balances, NoteRow, RejectedNote } from '../wallet/model';
import type { SyncReport } from '../wallet/sync';

/** The amount, split so the fractional part can be dimmed. */
function Amount({ quanta, testId }: { quanta: bigint; testId?: string }): ReactNode {
  const [whole, fraction] = formatQuantaAsQnr(quanta).replace(' QNR', '').split('.');
  return (
    <div className="mm-balance text-ink" data-testid={testId}>
      {whole}
      <span className="mm-balance-fraction">.{fraction ?? '00'}</span>
      <span className="ml-2 text-ui font-normal text-muted">QNR</span>
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
  return (
    <div className="space-y-3">
      <Panel>
        <Amount quanta={balances.unspent} />
        <p className="mt-1 text-meta text-muted">
          <span data-testid="balance-unspent">{formatCount(balances.unspent)}</span> quanta unspent
        </p>
        <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 border-t border-edge pt-3 text-meta">
          <Stat
            term="reachable in one payment"
            explains="A leaf has two input slots, so one payment can spend at most two notes. A
              balance spread over more than two is held and not reachable until it is merged."
            value={formatCount(balances.reachable)}
            testId="balance-reachable"
          />
          <Stat
            term="pending"
            explains="Written by this wallet and not yet met in the tree: a change note whose
              settlement has been submitted."
            value={formatCount(balances.pending)}
            testId="balance-pending"
          />
          <Stat
            term="off chain"
            explains="Held with its secrets, and its leaf is gone: a reorg took the block that
              carried it and no later block has re-included it. It counts in no balance until it
              comes back."
            value={formatCount(balances.offChain)}
            testId="balance-offchain"
          />
          <Stat
            term="notes held"
            explains="Every note in this store, spent and unspent, on chain and off. The table
              below is the same set."
            value={formatCount(balances.noteCount)}
          />
        </dl>
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
          and tried against this wallet&apos;s viewing key, and the settled nullifier set is paged
          whole, so the node is never told which leaves or which nullifiers are this wallet&apos;s.
        </Notice>
      )}

      {balances.reachable < balances.unspent && (
        <Notice>
          One payment reaches {formatCount(balances.reachable)} of {formatCount(balances.unspent)}{' '}
          quanta. A leaf has two input slots, so a balance spread over more than two notes is not
          reachable in one spend: send yourself the largest notes to merge them.
        </Notice>
      )}

      {conflicted.length > 0 && (
        <Notice>
          {conflicted.length} of these notes share a nullifier with another note this wallet holds.
          A sender picks each note&apos;s randomness, so a repeated pair is two notes of which at
          most one can ever settle. Both are held; the larger is the one a spend uses, and the set
          is counted once.
        </Notice>
      )}

      {report !== null &&
        report.warnings.map((warning) => <Notice key={warning}>{warning}</Notice>)}

      <Panel title="Notes" flush>
        {notes.length === 0 ? (
          <Empty>
            No notes yet. A wallet receives value when somebody spends to its address, when a node
            configured with its miner key wins a block, or when a transparent account shields into
            it from the command-line wallet.
          </Empty>
        ) : (
          <TableScroll>
            <Table testId="notes-table">
              <thead>
                <tr>
                  <th>Leaf</th>
                  <th>Block</th>
                  <th className="text-right">Quanta</th>
                  <th>Origin</th>
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
                      <Num>{formatCount(BigInt(row.note.value))}</Num>
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
        <Panel title="Outputs this wallet could not keep" flush>
          <TableScroll>
            <Table>
              <thead>
                <tr>
                  <th>Leaf</th>
                  <th className="text-right">Quanta</th>
                  <th className="w-full">Reason</th>
                </tr>
              </thead>
              <tbody>
                {rejected.map((entry) => (
                  <tr key={entry.commitment}>
                    <Num>{entry.leafIndex}</Num>
                    <Num>{formatCount(BigInt(entry.value))}</Num>
                    <td>{entry.reason}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableScroll>
          <p className="px-3 pt-2 text-meta text-muted">
            Provisional. A reorg that orphans the settlement makes the same leaf acceptable, and the
            next sync drops the entry and holds the note.
          </p>
        </Panel>
      )}

      {report !== null && (
        <Panel title="Last sync" flush>
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
                  <td>notes received</td>
                  <Num>{formatCount(report.received)}</Num>
                  <td>settled nullifiers</td>
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
          {report.heldSpent > 0 && (
            <p className="px-3 pt-2 text-meta text-muted">
              {report.heldSpent} note{report.heldSpent === 1 ? '' : 's'} kept marked spent: their
              nullifiers are absent from this node&apos;s set, and this node has not yet reached the
              block that settled them. Clearing the flag on that reading would put a consumed note
              back into selection.
            </p>
          )}
          {report.forkedAt !== null && (
            <p className="px-3 pt-2 text-meta text-muted">
              This node is on a different branch above block {formatCount(report.forkedAt)}. The
              watermark was rewound to there and the leaves were walked again.
            </p>
          )}
        </Panel>
      )}
    </div>
  );
}
