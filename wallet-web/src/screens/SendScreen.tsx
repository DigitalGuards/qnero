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

import { Amount } from '../components/UI/Amount';
import { Button } from '../components/UI/Button';
import { CopyButton } from '../components/UI/CopyButton';
import { Field, Input, Textarea } from '../components/UI/Field';
import { Notice } from '../components/UI/Notice';
import { Hash } from '../components/UI/Address';
import { Panel, Prose } from '../components/UI/Panel';
import { PHASES, progressFraction } from './sendPhases';
import { Num, Table, TableScroll } from '../components/UI/Table';
import { formatBytes, formatDuration, parseQnrToSteps } from '../lib/format';
import { memoByteLength, memoIsPlainAscii, memoRefusal } from '../lib/memo';
import { formatStepsAsQnr } from '../lib/units';
import type { SpendProgress, SpendResult } from '../wallet/send';

interface SendForm {
  to: string;
  amount: string;
  memo: string;
}

export function SendScreen({
  feeFloor,
  memoBytes,
  reachable,
  measuredSeconds,
  provingSeconds,
  blockSeconds,
  circuitsBuilt,
  proverThreads,
  checkAddress,
  onSend,
  progress,
  running,
  syncing,
  result,
  error,
  onDismiss,
}: {
  feeFloor: bigint;
  memoBytes: number;
  reachable: bigint;
  /**
   * What the last payment on this machine cost end to end, in seconds, or
   * null. Measured from this button to a settled block, which is the interval
   * this screen's own clock reads.
   */
  measuredSeconds: number | null;
  /**
   * The published figure for the proof alone, in seconds, for the module this
   * browser is running. The browser's half of the wait.
   */
  provingSeconds: number;
  /**
   * One block interval, in seconds, read from the chain, or null while the
   * chain has not answered yet.
   *
   * The chain's half of the wait, and it is the chain's because the interval
   * is chain state: the same build faces a 120 s public chain and a 12 s dev
   * chain. A settled payment waits for the next block whatever the proof cost,
   * so a wait is quoted as the two halves and not as one number measured
   * somewhere else.
   *
   * Null is a real state and a short one. The connection is published the
   * moment the socket is up, one round trip before the target read returns, and
   * this screen is gated on the wallet being open, with the connection's own
   * state reaching no gate above it. While it is null the screen quotes the proving half alone,
   * which is the half it knows.
   */
  blockSeconds: number | null;
  circuitsBuilt: boolean;
  proverThreads: number;
  /** The module's bech32m check, asked as the address is typed. */
  checkAddress: (address: string) => Promise<boolean>;
  onSend: (to: string, amount: bigint, memo: string) => void;
  progress: SpendProgress | null;
  running: boolean;
  /**
   * Whether a scan is running, which is the one state this button is refused
   * in that has nothing to do with what is typed into the form.
   *
   * A scan reads every note before it starts and commits them at the end, and
   * a payment writes `spent` on those same rows the moment it settles, so the
   * two do not overlap. Said on the screen, before the press.
   */
  syncing: boolean;
  result: SpendResult | null;
  error: string | null;
  onDismiss: () => void;
}): ReactNode {
  const form = useForm<SendForm>({ defaultValues: { to: '', amount: '', memo: '' } });
  // `useWatch` rather than `form.watch`: the subscription form is the one the
  // React compiler can reason about, and it re-renders this field alone.
  const memo = useWatch({ control: form.control, name: 'memo' });
  const [elapsed, setElapsed] = useState(0);
  /**
   * Which phase is running, and what the clock read when it started.
   *
   * The bar needs the phase's own elapsed time rather than the run's: see
   * `progressFraction`. The worker reports a stage and no timestamp, so the
   * boundary is this component's first render after the stage changed.
   */
  const [phase, setPhase] = useState<{ index: number; startedAt: number }>({
    index: -1,
    startedAt: 0,
  });

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

  const current = running ? PHASES.findIndex((step) => step.key === progress?.stage) : -1;
  if (phase.index !== current) {
    setPhase({ index: current, startedAt: running ? elapsed : 0 });
  }

  if (result !== null) {
    return <SendResultView result={result} onDismiss={onDismiss} />;
  }

  if (running) {
    // Worst case, so the admission below fires late rather than early: the
    // block half is "up to" one interval and lands sooner on average.
    const expectedSeconds = measuredSeconds ?? provingSeconds + (blockSeconds ?? 0);
    const expectedMillis = expectedSeconds * 1000;
    // The estimate stops being quoted the moment it is wrong. Two numbers in
    // one panel that disagree are worse than one number and an admission.
    //
    // Both sides of this comparison are the same interval: the clock started
    // at the button press and the expectation is what a payment takes from the
    // button press to a settled block. They used to be the run's clock against
    // a proving-only figure, so the admission fired about halfway through every
    // correct payment and the number it withdrew was out by about a factor of
    // two.
    const overdue = elapsed > expectedMillis;
    return (
      <Panel title="Sending">
        <Prose>
          <p>
            The proof is being built in a background worker.{' '}
            {overdue ? (
              <>
                This is longer than this browser expected
                {proverThreads > 1 ? ` on ${proverThreads} threads` : ' on one thread'}; nothing has
                failed, and the list below says where it is.
              </>
            ) : (
              measuredSeconds === null ? (
                <>
                  The published figure is about {provingSeconds} seconds of proving
                  {proverThreads > 1 ? ` on ${proverThreads} threads` : ' on one thread'}
                  {blockSeconds === null ? (
                    ', then one block interval before it settles.'
                  ) : (
                    <>
                      , then up to one block interval of {blockSeconds} seconds before it settles.
                    </>
                  )}
                  {/* The first payment of a session pays for the circuit build
                      as well, which is the fact a notice over the empty form
                      used to carry. It belongs to the wait, so it is said
                      inside the wait. */}
                  {!circuitsBuilt && ' This first payment builds the circuits as well.'}
                </>
              ) : (
                <>
                  This browser&rsquo;s last payment took about {measuredSeconds} seconds
                  {proverThreads > 1 ? ` on ${proverThreads} threads` : ' on one thread'}, from this
                  button to a settled block.
                </>
              )
            )}{' '}
            <strong className="text-ink">Leave this tab open.</strong>
          </p>
        </Prose>
        <div className="elev-inset mt-3 h-1 w-full overflow-hidden rounded-full bg-field">
          <div
            className="h-full bg-accent-fill transition-[width] duration-300 motion-reduce:transition-none"
            style={{
              width: `${Math.min(
                100,
                progressFraction(current, elapsed - phase.startedAt, expectedMillis) * 100,
              )}%`,
            }}
          />
        </div>
        <ul className="mt-3 list-none space-y-1 p-0 text-meta" data-testid="send-phases">
          {PHASES.map((step, index) => (
            <li
              key={step.key}
              // No second dimming on a waiting row: the muted ink is 5.36:1
              // on this panel and 0.7 of it measured 3.31:1, which is under
              // what a line of text owes a reader in either theme.
              className={
                index === current
                  ? 'flex justify-between text-ink'
                  : 'flex justify-between text-muted'
              }
              data-state={index < current ? 'done' : index === current ? 'running' : 'waiting'}
            >
              <span>{step.label}</span>
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

  const memoLength = memoByteLength(memo);

  return (
    <Panel title="Send Qnero">
      {syncing && (
        <Notice className="mb-3" testId="send-blocked">
          A scan is running. It reads everything this wallet holds before it starts and commits at
          the end, so a payment settling underneath it would write the same rows from a later moment.
          This button comes back when the scan finishes.
        </Notice>
      )}
      <form
        onSubmit={(event) => {
          void form.handleSubmit((values) => {
            onSend(values.to.trim(), parseQnrToSteps(values.amount), values.memo);
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
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            {...form.register('to', {
              // The checksum as it is typed, from the module that will decode
              // it. Without this a truncated paste is refused inside wasm
              // after the circuit build, the anchor read and a rebuild of
              // every leaf on the chain, which is the failure shape the memo
              // check was moved up here to remove.
              validate: async (value) => {
                const address = value.trim();
                if (address.length === 0) {
                  return 'Enter the address this payment goes to.';
                }
                return (
                  (await checkAddress(address)) ||
                  'Not a valid Qnero address. Paste it again, whole.'
                );
              },
            })}
          />
        </Field>
        <Field
          label="Amount"
          note="QNR"
          htmlFor="send-amount"
          hint={`${formatStepsAsQnr(reachable)} reachable in one payment`}
          error={form.formState.errors.amount?.message}
        >
          <Input
            id="send-amount"
            data-testid="send-amount"
            inputMode="decimal"
            autoComplete="off"
            {...form.register('amount', {
              validate: (value) => {
                let parsed: bigint;
                try {
                  parsed = parseQnrToSteps(value);
                } catch (parseError) {
                  return (parseError as Error).message;
                }
                if (parsed + feeFloor > reachable) {
                  return (
                    `One payment reaches ${formatStepsAsQnr(reachable)} and this one needs ` +
                    `${formatStepsAsQnr(parsed + feeFloor)} including the fee.`
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
              ? `${memoLength} of ${memoBytes} characters`
              : `${memoLength} of ${memoBytes} bytes, shown escaped at the other end`
          }
          error={form.formState.errors.memo?.message}
        >
          <Input
            id="send-memo"
            data-testid="send-memo"
            autoComplete="off"
            {...form.register('memo', {
              // A rule rather than a decoration. Drawn under the field with
              // the button still live, this refusal arrived after the circuit
              // build and the tree rebuild, for something the form knew before
              // the click. `wallet/send.ts` refuses the same bound from the
              // same function.
              validate: (value) => memoRefusal(value, memoBytes) ?? true,
            })}
          />
        </Field>

        <div className="mt-4 flex items-center justify-between gap-2 border-t border-edge pt-3">
          {/* A label and the amount. What the floor is made of was a tooltip,
              which a touch screen cannot reach at all; the sentence is on the
              sent screen, under the fee it was charged. */}
          <span className="mm-label mb-0">Fee</span>
          <span className="font-mono text-body text-ink" data-testid="send-fee">
            {formatStepsAsQnr(feeFloor)}
          </span>
        </div>

        {error !== null && (
          <Notice tone="error" className="mt-3" testId="send-error" sensitive>
            {error}
          </Notice>
        )}

        <Button
          type="submit"
          variant="action"
          size="block"
          className="mt-4"
          data-testid="do-send"
          disabled={syncing}
        >
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
  const included = result.inclusion !== null;
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
            The settlement is in block {result.inclusion.blockNumber} and the chain did not settle
            it there. A payment whose anchor went stale, or whose transfer was spent elsewhere
            first, is skipped and the block carries it anyway. Read the chain, then send again.
          </Notice>
        )
      )}
      {/* What the payment was, at the size the balance is: it is the same
          question answered about a different moment. The result used to open
          with a five-row table of 11 px cells and put Done at y 678 of a
          667 px screen, under the whole recipient address. */}
      <Amount steps={result.amount} note="sent" testId="send-amount-paid" />
      <dl className="mt-3 space-y-1 border-t border-edge pt-3 text-meta" data-testid="send-result">
        <div className="flex justify-between gap-2">
          <dt className="text-muted">
            {settled ? 'settled in block' : included ? 'included in block' : 'not included'}
          </dt>
          <dd className="font-mono tabular-nums text-ink" data-testid="send-block">
            {result.inclusion?.blockNumber ?? '-'}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-muted">fee</dt>
          <dd className="font-mono tabular-nums text-ink">{formatStepsAsQnr(result.fee)}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-muted">change</dt>
          <dd className="font-mono tabular-nums text-ink" data-testid="send-change">
            {formatStepsAsQnr(result.change)}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-muted">to</dt>
          <dd className="min-w-0 text-ink" data-testid="send-recipient" title={result.to}>
            <Hash value={result.to} head={12} tail={8} />
          </dd>
        </div>
      </dl>
      {/* The sentence the fee field used to hide in a tooltip, said once,
          where a reader has just paid one. */}
      <p className="mm-note mt-2 text-muted">
        The fee is the floor this runtime charges for one slot, fixed at proving time.
      </p>
      <div className="mt-3 flex gap-2">
        <CopyButton value={result.to} label="Copy address" testId="copy-recipient" />
      </div>
      <Button variant="action" size="block" className="mt-4" data-testid="send-done" onClick={onDismiss}>
        Done
      </Button>
      <details className="mt-3">
        <summary className="cursor-pointer text-meta text-muted">What the proof cost</summary>
        <TableScroll>
          <Table testId="send-prover">
            <tbody>
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
              <tr>
                <td>transfers spent</td>
                <Num>{result.inputs.length}</Num>
              </tr>
            </tbody>
          </Table>
        </TableScroll>
        <p className="mm-note mt-2 text-muted">
          The payment landed in slot {result.paymentSlot}, drawn for this spend. Either slot
          settles the same way, and drawing it is what stops a chain reader telling the
          recipient&apos;s slot from the change.
        </p>
      </details>
    </Panel>
  );
}
