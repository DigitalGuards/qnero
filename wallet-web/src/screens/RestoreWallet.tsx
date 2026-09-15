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
 * conversion is arithmetic over a block time that only holds on average.
 */

import type { ReactNode } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import { Button } from '../components/UI/Button';
import { Field, Textarea, Input } from '../components/UI/Field';
import { Panel, Prose } from '../components/UI/Panel';
import { MIN_PASSPHRASE, seedHexIsWellFormed } from '../wallet/crypto';
import { BIRTHDAY_EPOCH, birthdayEpochOf } from '../wallet/model';
import { fullScanEstimate } from '../wallet/sync';

/**
 * A block number or a date, as a height, or `null` for neither.
 *
 * A bare number is a height. Anything `Date.parse` reads is a date, turned
 * into a height by counting back from the head at the chain's own target block
 * time and then dropped a whole epoch, because that conversion is arithmetic
 * over a block time that holds on average and not block by block. Both are
 * then rounded down to the epoch where they are recorded.
 */
export function heightFromRestoreField(
  typed: string,
  head: number | null,
  targetBlockTimeMs: number | null,
): number | null {
  const trimmed = typed.trim();
  if (trimmed === '') {
    return null;
  }
  if (/^[0-9]+$/.test(trimmed)) {
    return Number(trimmed);
  }
  const when = Date.parse(trimmed);
  if (Number.isNaN(when) || head === null || targetBlockTimeMs === null || targetBlockTimeMs <= 0) {
    return null;
  }
  const back = Math.ceil((Date.now() - when) / targetBlockTimeMs);
  return Math.max(head - back - BIRTHDAY_EPOCH, 0);
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
  const height = heightFromRestoreField(typedHeight, head, targetBlockTimeMs);
  const heightHint =
    typedHeight.trim() === ''
      ? head === null
        ? 'empty scans the whole chain from block zero'
        : `empty scans the whole chain: ${fullScanEstimate(head)}`
      : height === null
        ? 'that is neither a block number nor a date this wallet can read'
        : `recorded as block ${birthdayEpochOf(height)}, the epoch below it`;

  return (
    <Panel title="Use an existing wallet">
      <Prose>
        <p>
          Paste the 32-byte spend key, as 64 hex characters. Spaces and line breaks are ignored, so
          the grouped form this wallet shows can go straight back in.
        </p>
      </Prose>
      <form
        className="mt-3"
        onSubmit={(event) => {
          void form.handleSubmit((values) => {
            onRestore(
              values.seed.replace(/\s+/g, '').toLowerCase(),
              values.passphrase,
              heightFromRestoreField(values.restoreHeight, head, targetBlockTimeMs),
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
                seedHexIsWellFormed(value.replace(/\s+/g, '')) || 'a spend key is 64 hex characters',
            })}
          />
        </Field>
        <Field
          label="Restore height (optional)"
          htmlFor="restore-height"
          hint={heightHint}
        >
          <Input
            id="restore-height"
            data-testid="restore-height"
            autoComplete="off"
            spellCheck={false}
            placeholder="the chain height when this wallet was created, leave empty to scan everything"
            {...form.register('restoreHeight')}
          />
        </Field>
        <Prose>
          <p className="text-meta text-muted">
            A block number, or a date such as 2026-03-14. It is recorded rounded down to the
            nearest {BIRTHDAY_EPOCH} blocks, so what the nodes this wallet syncs against are told
            is a coarse epoch rather than the day it was made. A height{' '}
            <strong className="text-ink">above</strong> the block a transfer arrived in is a
            transfer this wallet never reads and a balance quietly short, so if you are not sure,
            leave it empty or give a height you are sure is early.
          </p>
        </Prose>
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
                `use at least ${MIN_PASSPHRASE} characters for the passphrase`,
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
                value === values.passphrase || 'those two passphrases do not match',
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
