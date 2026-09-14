/**
 * The lock screen.
 *
 * Deriving the key is about a second of PBKDF2 at 600,000 iterations, on the
 * main thread and on purpose: WebCrypto is async and runs off-thread anyway,
 * and the worker is reserved for proving, so a key derivation and a payment's
 * proof never contend.
 */

import { useState, type ReactNode } from 'react';

import { Address } from '../components/UI/Address';
import { Button } from '../components/UI/Button';
import { Dialog, DialogContent, DialogTrigger } from '../components/UI/Dialog';
import { Field, Input } from '../components/UI/Field';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';

export function Unlock({
  address,
  onUnlock,
  onForget,
  busy,
  error,
}: {
  address: string;
  onUnlock: (passphrase: string) => void;
  onForget: () => void;
  busy: boolean;
  error: string | null;
}): ReactNode {
  const [passphrase, setPassphrase] = useState('');

  return (
    <Panel title="Unlock">
      <Prose>
        <p>
          This browser holds a wallet. Its balance and its notes are readable without the
          passphrase; spending needs it, because the spend key and every note&apos;s randomness are
          encrypted with it.
        </p>
      </Prose>
      <Address value={address} testId="locked-address" />
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onUnlock(passphrase);
        }}
      >
        <Field label="Passphrase" htmlFor="unlock-passphrase">
          <Input
            id="unlock-passphrase"
            type="password"
            data-testid="unlock-passphrase"
            autoComplete="current-password"
            autoFocus
            value={passphrase}
            onChange={(event) => {
              setPassphrase(event.target.value);
            }}
          />
        </Field>
        {error !== null && <Notice tone="error">{error}</Notice>}
        <div className="mt-4 flex gap-2">
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="destructive" disabled={busy}>
                Remove
              </Button>
            </DialogTrigger>
            <DialogContent
              title="Remove this wallet?"
              description={
                <p>
                  This erases the encrypted seed and every note from this browser. Without the 32
                  bytes you wrote down there is no way back, and nothing anywhere else holds a
                  copy.
                </p>
              }
            >
              <Button
                variant="destructive"
                size="block"
                data-testid="confirm-forget"
                onClick={onForget}
              >
                Erase everything
              </Button>
            </DialogContent>
          </Dialog>
          <Button
            type="submit"
            variant="action"
            className="flex-1"
            disabled={busy}
            data-testid="do-unlock"
          >
            {busy ? 'Deriving the key…' : 'Unlock'}
          </Button>
        </div>
      </form>
    </Panel>
  );
}
