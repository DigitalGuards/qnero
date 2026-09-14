/**
 * Restoring from a seed.
 *
 * The only input is the 32 bytes. There is no server-side account and no
 * "restore height": a scan reads the whole leaf range, and it reads it whole
 * on purpose, because a scan that started at a height the wallet named would
 * be a scan that told the node roughly when this wallet was created.
 */

import type { ReactNode } from 'react';
import { useForm, useWatch } from 'react-hook-form';

import { Button } from '../components/UI/Button';
import { Field, Textarea, Input } from '../components/UI/Field';
import { Panel, Prose } from '../components/UI/Panel';
import { seedHexIsWellFormed } from '../wallet/crypto';

const MIN_PASSPHRASE = 8;

interface RestoreForm {
  seed: string;
  passphrase: string;
  repeat: string;
}

export function RestoreWallet({
  onCancel,
  onRestore,
  busy,
}: {
  onCancel: () => void;
  onRestore: (seedHex: string, passphrase: string) => void;
  busy: boolean;
}): ReactNode {
  const form = useForm<RestoreForm>({
    defaultValues: { seed: '', passphrase: '', repeat: '' },
  });
  // `useWatch` rather than `form.watch`: the subscription form is the one the
  // React compiler can reason about, and it re-renders this field alone.
  const typed = useWatch({ control: form.control, name: 'seed' }).replace(/\s+/g, '');

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
            onRestore(values.seed.replace(/\s+/g, '').toLowerCase(), values.passphrase);
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
              minLength: {
                value: MIN_PASSPHRASE,
                message: `use at least ${MIN_PASSPHRASE} characters for the passphrase`,
              },
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
