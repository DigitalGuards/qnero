/**
 * Send Qnero.
 *
 * MyMonero's send screen is an address, an amount, a memo field and a fee on
 * its own line, with a named sending state under the button. The shape holds.
 * What is different is what the states are: a light wallet's "constructing
 * transaction" is milliseconds and this one's is tens of seconds of proving in
 * a worker, so the phases are listed rather than spun over, and the measured
 * expectation is printed beside the clock so a slow machine reads as slow
 * rather than as stuck.
 *
 * The fee is shown before anything is typed and it is not a slider. It is a
 * floor computed from the runtime's own constants and the size of the two
 * ciphertexts this submission will carry, and it is a public input fixed at
 * proving time: an underpaid one costs the whole proof and comes back refused.
 */

import { useEffect, useState, type ReactNode } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import { Button } from '../components/UI/Button';
import { Field, Input, Textarea } from '../components/UI/Field';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';
import { Num, Table, TableScroll } from '../components/UI/Table';
import { formatBytes, formatDuration, parseQuanta } from '../lib/format';
import { memoIsPlainAscii } from '../lib/memo';
import { formatCount } from '../lib/units';
import type { SpendProgress, SpendResult } from '../wallet/send';

const PHASES: { key: SpendProgress['stage']; label: string }[] = [
  { key: 'fee', label: 'fee floor' },
  { key: 'select', label: 'choosing notes' },
  { key: 'build', label: 'building the circuits' },
  { key: 'anchor', label: 'anchoring to the head' },
  { key: 'tree', label: 'rebuilding the tree' },
  { key: 'prove', label: 'proving the private batch' },
  { key: 'submit', label: 'submitting' },
  { key: 'confirm', label: 'waiting for inclusion' },
];

interface SendForm {
  to: string;
  amount: string;
  memo: string;
}

export function SendScreen({
  feeFloor,
  memoBytes,
  reachable,
  expectedSeconds,
  circuitsBuilt,
  proverThreads,
  onSend,
  progress,
  running,
  result,
  error,
  onDismiss,
}: {
  feeFloor: bigint;
  memoBytes: number;
  reachable: bigint;
  expectedSeconds: number;
  circuitsBuilt: boolean;
  proverThreads: number;
  onSend: (to: string, amount: bigint, memo: string) => void;
  progress: SpendProgress | null;
  running: boolean;
  result: SpendResult | null;
  error: string | null;
  onDismiss: () => void;
}): ReactNode {
  const form = useForm<SendForm>({ defaultValues: { to: '', amount: '', memo: '' } });
  // `useWatch` rather than `form.watch`: the subscription form is the one the
  // React compiler can reason about, and it re-renders this field alone.
  const memo = useWatch({ control: form.control, name: 'memo' });
  const [elapsed, setElapsed] = useState(0);

  // The elapsed clock is an external system this component subscribes to, so
  // the effect starts and stops the interval and nothing else.
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

  // Adjusting state during render rather than in an effect: the reading
  // belongs to the run that produced it, and a run that has ended has no
  // reading. React re-renders this component before anything is painted.
  if (!running && elapsed !== 0) {
    setElapsed(0);
  }

  if (result !== null) {
    return <SendResultView result={result} onDismiss={onDismiss} />;
  }

  if (running) {
    const current = PHASES.findIndex((phase) => phase.key === progress?.stage);
    return (
      <Panel title="Sending">
        <Prose>
          <p>
            The proof is being built in a background worker. This browser expects about{' '}
            {expectedSeconds} seconds for one payment
            {proverThreads > 1 ? ` on ${proverThreads} threads` : ' on one thread'}; a slower
            machine takes longer, and there is no way to know how much longer until it finishes.{' '}
            <strong className="text-ink">Leave this tab open.</strong>
          </p>
        </Prose>
        <div className="elev-inset mt-3 h-1 w-full overflow-hidden rounded-full bg-field">
          <div
            className="h-full bg-accent-fill transition-[width] duration-300"
            style={{ width: `${Math.min(100, ((current + 1) / PHASES.length) * 100)}%` }}
          />
        </div>
        <ul className="mt-3 list-none space-y-1 p-0 text-meta" data-testid="send-phases">
          {PHASES.map((phase, index) => (
            <li
              key={phase.key}
              className={
                index < current
                  ? 'flex justify-between text-muted'
                  : index === current
                    ? 'flex justify-between text-ink'
                    : 'flex justify-between text-dim'
              }
              data-state={index < current ? 'done' : index === current ? 'running' : 'waiting'}
            >
              <span>{phase.label}</span>
              <span>{index < current ? 'done' : index === current ? '…' : ''}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-meta text-muted" data-testid="send-elapsed">
          {formatDuration(elapsed)} elapsed
          {progress?.detail === undefined ? '' : `, ${progress.detail}`}
        </p>
      </Panel>
    );
  }

  const memoLength = new TextEncoder().encode(memo).length;

  return (
    <Panel title="Send Qnero">
      {!circuitsBuilt && (
        <Notice className="mb-3">
          The proving circuits are not resident yet. The first payment of this session builds them,
          which is seconds on top of the proof.
        </Notice>
      )}
      <form
        onSubmit={(event) => {
          void form.handleSubmit((values) => {
            onSend(values.to.trim(), parseQuanta(values.amount), values.memo);
          })(event);
        }}
      >
        <Field
          label="To"
          htmlFor="send-to"
          hint="a qn1 address"
          error={form.formState.errors.to?.message}
        >
          <Textarea
            id="send-to"
            data-testid="send-to"
            rows={3}
            autoComplete="off"
            spellCheck={false}
            {...form.register('to', {
              validate: (value) =>
                value.trim().length > 0 || 'enter the address this payment goes to',
            })}
          />
        </Field>
        <Field
          label="Amount"
          note="quanta"
          htmlFor="send-amount"
          hint={`${formatCount(reachable)} reachable in one payment`}
          error={form.formState.errors.amount?.message}
        >
          <Input
            id="send-amount"
            data-testid="send-amount"
            inputMode="numeric"
            autoComplete="off"
            {...form.register('amount', {
              validate: (value) => {
                let parsed: bigint;
                try {
                  parsed = parseQuanta(value);
                } catch (parseError) {
                  return (parseError as Error).message;
                }
                if (parsed + feeFloor > reachable) {
                  return (
                    `one payment reaches ${formatCount(reachable)} quanta and this one needs ` +
                    `${formatCount(parsed + feeFloor)} including the fee`
                  );
                }
                return true;
              },
            })}
          />
        </Field>
        <Field
          label="Memo"
          note="optional"
          htmlFor="send-memo"
          hint={
            memoIsPlainAscii(memo)
              ? `${memoLength} of ${memoBytes} bytes, padded to ${memoBytes}`
              : 'anything outside printable ASCII will be shown escaped at the other end'
          }
          error={
            memoLength > memoBytes ? `a memo is at most ${memoBytes} bytes` : undefined
          }
        >
          <Input
            id="send-memo"
            data-testid="send-memo"
            autoComplete="off"
            {...form.register('memo')}
          />
        </Field>

        <div className="mt-4 flex items-center justify-between gap-2 border-t border-edge pt-3">
          <span className="mm-label mb-0">Fee</span>
          <span className="font-mono text-body text-ink" data-testid="send-fee">
            {formatCount(feeFloor)} quanta
          </span>
        </div>
        <p className="mt-1 text-meta text-muted">
          The floor this runtime charges for one slot: a flat minimum plus one quantum per block of
          ciphertext bytes. Both memos are padded to {memoBytes} bytes so the two ciphertexts are
          the same length, which is what stops the memo&apos;s length being published in the clear.
        </p>

        {error !== null && (
          <Notice tone="error" className="mt-3" testId="send-error" sensitive>
            {error}
          </Notice>
        )}

        <Button type="submit" variant="action" size="block" className="mt-4" data-testid="do-send">
          Send
        </Button>
      </form>
    </Panel>
  );
}

function SendResultView({
  result,
  onDismiss,
}: {
  result: SpendResult;
  onDismiss: () => void;
}): ReactNode {
  const settled = result.inclusion?.settled === true;
  return (
    <Panel title={settled ? 'Sent' : 'Submitted'}>
      {result.warnings.map((warning) => (
        <Notice key={warning} className="mb-3">
          {warning}
        </Notice>
      ))}
      {result.inclusion === null ? (
        <Notice tone="error" className="mb-3" testId="send-timeout">
          This settlement did not land inside the wait. An unsigned settlement has a five-block
          longevity and constant priority, so resending these exact bytes will not displace the copy
          already in the pool: the answer is to prove again against a fresh anchor, which is another
          full proof.
        </Notice>
      ) : (
        !settled && (
          <Notice tone="error" className="mb-3">
            The extrinsic is in block {result.inclusion.blockNumber} and its nullifiers are not in
            the settled set at that block. A segment whose anchor went stale or whose nullifier was
            claimed elsewhere is skipped, and the block carries it anyway. Sync, then send again
            against a fresh anchor.
          </Notice>
        )
      )}
      <TableScroll>
        <Table testId="send-result">
          <tbody>
            <tr>
              <td>settled in block</td>
              <Num testId="send-block">{result.inclusion?.blockNumber ?? '-'}</Num>
            </tr>
            <tr>
              <td>fee</td>
              <Num>{formatCount(result.fee)} quanta</Num>
            </tr>
            <tr>
              <td>change</td>
              <Num testId="send-change">{formatCount(result.change)} quanta</Num>
            </tr>
            <tr>
              <td>inputs spent</td>
              <Num>{result.inputs.length}</Num>
            </tr>
            <tr>
              <td>proof</td>
              <Num>{formatBytes(result.proofBytes)}</Num>
            </tr>
            <tr>
              <td>proving time</td>
              <Num testId="prove-millis">{formatDuration(result.proveMillis)}</Num>
            </tr>
            <tr>
              <td>peak linear memory</td>
              <Num>{(result.peakLinearMemoryBytes / (1024 * 1024)).toFixed(1)} MiB</Num>
            </tr>
          </tbody>
        </Table>
      </TableScroll>
      <p className="mt-3 text-meta text-muted">
        The payment landed in output slot {result.paymentSlot}, drawn for this spend. The circuit
        derives each output&apos;s randomness from its slot, so either assignment settles the same
        way, and drawing it is what stops a chain reader telling the counterparty&apos;s output from
        the sender&apos;s change.
      </p>
      <Button variant="action" size="block" className="mt-4" data-testid="send-done" onClick={onDismiss}>
        Done
      </Button>
    </Panel>
  );
}
