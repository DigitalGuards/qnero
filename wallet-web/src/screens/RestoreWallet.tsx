/**
 * Restoring from a seed.
 *
 * The 32 bytes, and one optional number: the chain height this wallet was
 * created at. A scan with no height reads the whole leaf range from block
 * zero, which is always correct and on a long chain is slow, and the screen
 * says how slow before anybody chooses it.
 *
 * A height is a claim about this wallet and it is recorded rounded **down** to
 * a multiple of `BIRTHDAY_EPOCH`, so what the store holds and what every node
 * this wallet ever syncs against is told is a coarse public epoch rather than
 * the moment the wallet was made. Down, so a height a little too high still
 * starts below the first note. A height above the block a note arrived in is a
 * note this wallet never reads, and the field says that in as many words.
 *
 * A date is taken as well as a number, because somebody restoring a wallet
 * remembers when they made it and not what block the chain was on. It is
 * converted by counting back from the node's head at the chain's own target
 * block time, and then a whole epoch is given away on top, because the
 * conversion is arithmetic over a block time that only holds on average. So a
 * date needs a node and a number does not, and this screen is reachable with
 * no node connected: that case says what is missing rather than calling the
 * date unreadable.
 */

import type { ReactNode } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import { Button } from '../components/UI/Button';
import { Field, Textarea, Input } from '../components/UI/Field';
import { Panel } from '../components/UI/Panel';
import { MIN_PASSPHRASE, seedHexIsWellFormed } from '../wallet/crypto';
import { BIRTHDAY_EPOCH, birthdayEpochOf } from '../wallet/model';
import { fullScanEstimate } from '../wallet/sync';

/**
 * What was typed in the restore-height field.
 *
 * Four answers rather than a height or `null`, because `null` meant two
 * different things to the caller and one of them was reported as the other. A
 * date is readable or not on its own; whether this wallet can turn it into a
 * height also depends on there being a node to count back from, and a screen
 * that answered "this wallet cannot read that" to a perfectly good date while
 * the socket was down was blaming the wrong side.
 */
export type RestoreField =
  | { kind: 'empty' }
  | { kind: 'height'; value: number }
  /** A date, with no head to count it back from. */
  | { kind: 'no-head' }
  | { kind: 'neither' };

/**
 * A block number or a date, as a height.
 *
 * A bare number is a height. Anything `Date.parse` reads is a date, turned
 * into a height by counting back from the head at the chain's own target block
 * time and then dropped a whole epoch, because that conversion is arithmetic
 * over a block time that holds on average and not block by block. Both are
 * then rounded down to the epoch where they are recorded.
 */
export function readRestoreField(
  typed: string,
  head: number | null,
  targetBlockTimeMs: number | null,
): RestoreField {
  const trimmed = typed.trim();
  if (trimmed === '') {
    return { kind: 'empty' };
  }
  if (/^[0-9]+$/.test(trimmed)) {
    return { kind: 'height', value: Number(trimmed) };
  }
  const when = Date.parse(trimmed);
  if (Number.isNaN(when)) {
    return { kind: 'neither' };
  }
  if (head === null || targetBlockTimeMs === null || targetBlockTimeMs <= 0) {
    return { kind: 'no-head' };
  }
  const back = Math.ceil((Date.now() - when) / targetBlockTimeMs);
  return { kind: 'height', value: Math.max(head - back - BIRTHDAY_EPOCH, 0) };
}

/** The height a restore starts at, or `null` for a scan of the whole chain. */
export function restoreHeightOf(field: RestoreField): number | null {
  return field.kind === 'height' ? field.value : null;
}

interface RestoreForm {
  seed: string;
  restoreHeight: string;
  passphrase: string;
  repeat: string;
}

export function RestoreWallet({
  onCancel,
  onRestore,
  busy,
  head,
  targetBlockTimeMs,
}: {
  onCancel: () => void;
  onRestore: (seedHex: string, passphrase: string, restoreHeight: number | null) => void;
  busy: boolean;
  /** The node's head, for the estimate and for reading a date as a height. */
  head: number | null;
  /** The chain's own target block time, for the same reason. */
  targetBlockTimeMs: number | null;
}): ReactNode {
  const form = useForm<RestoreForm>({
    defaultValues: { seed: '', restoreHeight: '', passphrase: '', repeat: '' },
  });
  // `useWatch` rather than `form.watch`: the subscription form is the one the
  // React compiler can reason about, and it re-renders this field alone.
  const typed = useWatch({ control: form.control, name: 'seed' }).replace(/\s+/g, '');
  const typedHeight = useWatch({ control: form.control, name: 'restoreHeight' });
  const field = readRestoreField(typedHeight, head, targetBlockTimeMs);
  // One line. What the field is for is the label, what an empty one does is
  // this, and the epoch and the estimate read on request under the form.
  const heightHint =
    field.kind === 'empty'
      ? 'Leave empty to read the whole chain'
      : field.kind === 'height'
        ? `Recorded as block ${birthdayEpochOf(field.value)}, the epoch below it`
        : field.kind === 'no-head'
          ? 'A date needs a node to count back from. Give a block number instead.'
          : 'Neither a block number nor a date this wallet can read';

  return (
    <Panel title="Use an existing wallet">
      <p className="text-body text-ink-2">
        Paste the 32-byte spend key, as 64 hex characters. Spaces and line breaks are ignored.
      </p>
      <form
        className="mt-3"
        onSubmit={(event) => {
          void form.handleSubmit((values) => {
            onRestore(
              values.seed.replace(/\s+/g, '').toLowerCase(),
              values.passphrase,
              restoreHeightOf(readRestoreField(values.restoreHeight, head, targetBlockTimeMs)),
            );
          })(event);
        }}
      >
        <Field
          label="Spend key"
          htmlFor="restore-seed"
          hint={`${typed.length} of 64 hex characters`}
          error={form.formState.errors.seed?.message}
        >
          <Textarea
            id="restore-seed"
            data-testid="restore-seed"
            autoComplete="off"
            spellCheck={false}
            rows={3}
            {...form.register('seed', {
              validate: (value) =>
                seedHexIsWellFormed(value.replace(/\s+/g, '')) ||
                'A spend key is 64 hex characters.',
            })}
          />
        </Field>
        <Field
          label="Start from (optional)"
          htmlFor="restore-height"
          hint={heightHint}
          error={form.formState.errors.restoreHeight?.message}
        >
          <Input
            id="restore-height"
            data-testid="restore-height"
            autoComplete="off"
            spellCheck={false}
            placeholder="block number or date"
            {...form.register('restoreHeight', {
              // Refused rather than taken as "scan everything". A typo in this
              // field used to submit as an empty one, and the difference
              // between the two is a wallet that reads the whole chain when
              // somebody meant to name a block.
              validate: (value) =>
                readRestoreField(value, head, targetBlockTimeMs).kind !== 'neither' ||
                'Give a block number, a date such as 2026-03-14, or nothing at all.',
            })}
          />
        </Field>
        <details className="mb-3">
          <summary className="cursor-pointer text-meta text-muted">
            What this number does
          </summary>
          <p className="mt-2 text-meta text-muted">
            It is recorded rounded down to the nearest {BIRTHDAY_EPOCH} blocks, so what the nodes
            this wallet syncs against are told is a coarse epoch rather than the day it was made.
            A height <strong className="text-ink">above</strong> the block a transfer arrived in is
            a transfer this wallet never reads and a balance quietly short, so if you are not sure,
            leave it empty or give a height you are sure is early.
            {head !== null && ` Empty reads the whole chain: ${fullScanEstimate(head)}.`}
          </p>
        </details>
        <Field
          label="Passphrase"
          htmlFor="passphrase"
          error={form.formState.errors.passphrase?.message}
        >
          <Input
            id="passphrase"
            type="password"
            data-testid="passphrase"
            autoComplete="new-password"
            {...form.register('passphrase', {
              // `validate` rather than `minLength`, which react-hook-form skips
              // on an empty field. See `CreateWallet` and `wallet/crypto.ts`.
              validate: (value) =>
                value.length >= MIN_PASSPHRASE ||
                `Use at least ${MIN_PASSPHRASE} characters for the passphrase.`,
            })}
          />
        </Field>
        <Field
          label="Passphrase again"
          htmlFor="passphrase-repeat"
          error={form.formState.errors.repeat?.message}
        >
          <Input
            id="passphrase-repeat"
            type="password"
            data-testid="passphrase-repeat"
            autoComplete="new-password"
            {...form.register('repeat', {
              validate: (value, values) =>
                value === values.passphrase || 'Those two passphrases do not match.',
            })}
          />
        </Field>
        <div className="mt-4 flex gap-2">
          <Button onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="action"
            className="flex-1"
            disabled={busy}
            data-testid="finish-restore"
          >
            {busy ? 'Opening…' : 'Restore wallet'}
          </Button>
        </div>
      </form>
    </Panel>
  );
}
