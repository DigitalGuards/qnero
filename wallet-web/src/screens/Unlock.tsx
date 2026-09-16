/**
 * The lock screen.
 *
 * Deriving the key is about a second of PBKDF2 at 600,000 iterations, on the
 * main thread and on purpose: WebCrypto is async and runs off-thread anyway,
 * and the worker is reserved for proving, so a key derivation and a payment's
 * proof never contend.
 */

import { useState, type ReactNode } from 'react';

import { Hash } from '../components/UI/Address';
import { Button } from '../components/UI/Button';
import { Dialog, DialogContent, DialogTrigger } from '../components/UI/Dialog';
import { Field, Input } from '../components/UI/Field';
import { Panel } from '../components/UI/Panel';

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
      {/* Shortened, where the address identifies which wallet this browser
          holds. `Address` shows one whole on the receive screen and the send
          result, where the value is being used rather than recognised; 176 px
          of 2,600 characters above the field this screen exists to collect is
          38% of the panel for something nobody reads.

          The fifty-one word paragraph that used to open this screen said a
          locked wallet still shows a balance, on a screen that shows none. */}
      <p className="mb-3 text-meta text-muted" data-testid="locked-address">
        <Hash value={address} head={12} tail={8} />
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onUnlock(passphrase);
        }}
      >
        {/* Under the field, like every other field failure in this wallet.
            The Notice box is for a refusal that is not about one field. */}
        <Field label="Passphrase" htmlFor="unlock-passphrase" error={error ?? undefined}>
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
        <div className="mt-4 flex gap-2">
          <Dialog>
            <DialogTrigger asChild>
              {/* Neutral, so the lock screen has one filled button and it is
                  Unlock. This one sits where a hand goes after a mistyped
                  passphrase, and what it opens erases the only copy of every
                  note's randomness. */}
              <Button disabled={busy}>Remove</Button>
            </DialogTrigger>
            <DialogContent
              title="Remove this wallet?"
              description={
                <p>
                  This clears every record and deletes the database. Without the 32 bytes you
                  wrote down there is no way back into this wallet. A browser may keep the freed
                  pages on disk until it compacts.
                </p>
              }
            >
              <Button
                variant="destructive"
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
        <p className="mt-3 text-meta text-muted">
          Spending needs the passphrase; viewing does not.
        </p>
      </form>
    </Panel>
  );
}
