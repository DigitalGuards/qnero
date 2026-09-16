/**
 * Creating a wallet: show the seed, optionally check the backup, then lock it.
 *
 * The confirmation is MyMonero's shape, adapted to what a Qnero seed is. That
 * wallet shows a mnemonic and asks for some of its words back. This one holds
 * 32 raw bytes, so it shows them as eight groups of eight hex characters and
 * asks for three of the groups back, chosen at random after the seed is
 * hidden. The user can skip that check and proceed to the same passphrase
 * setup. Both paths encrypt the original seed before creating the wallet.
 *
 * The two forms are `react-hook-form`'s, as they are in the sibling web
 * wallet: the validation rule sits beside the field it is about rather than in
 * a submit handler that has to remember the order to check things in.
 */

import { useMemo, useState, type ReactNode } from 'react';
import { useForm } from 'react-hook-form';

import { Button } from '../components/UI/Button';
import { Field, Input } from '../components/UI/Field';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';
import { MIN_PASSPHRASE } from '../wallet/crypto';
import { newSeed, bytesToHex } from '../wallet/crypto';

const GROUPS = 8;
const GROUP_LENGTH = 8;
/** How many groups are asked back. Three of eight is 24 of the 64 characters. */
const CHALLENGES = 3;
/** The floor on a passphrase this build will write a wallet under. */

function groupsOf(seedHex: string): string[] {
  const out: string[] = [];
  for (let index = 0; index < GROUPS; index += 1) {
    out.push(seedHex.slice(index * GROUP_LENGTH, (index + 1) * GROUP_LENGTH));
  }
  return out;
}

function drawChallenges(): number[] {
  const picked = new Set<number>();
  const draws = crypto.getRandomValues(new Uint8Array(32));
  let cursor = 0;
  while (picked.size < CHALLENGES && cursor < draws.length) {
    picked.add((draws[cursor] ?? 0) % GROUPS);
    cursor += 1;
  }
  return [...picked].sort((a, b) => a - b);
}

interface ConfirmForm {
  answers: Record<string, string>;
}

interface LockForm {
  passphrase: string;
  repeat: string;
}

export function CreateWallet({
  onCancel,
  onCreated,
  busy,
  storageWarning,
}: {
  onCancel: () => void;
  onCreated: (seedHex: string, passphrase: string) => void;
  busy: boolean;
  /**
   * What this browser said about keeping the wallet, when the answer was no.
   *
   * On this step and nowhere earlier: it is a sentence about the seed being
   * the only way back, and this is the one screen where the seed is on the
   * page and writing it down is the thing being asked for.
   */
  storageWarning: string | null;
}): ReactNode {
  const seedHex = useMemo(() => {
    const bytes = newSeed();
    const hex = bytesToHex(bytes);
    // The array this page allocated is erased. The string cannot be: see
    // `wallet/crypto.ts` and `README.md` on what zeroing does and does not buy
    // in a browser.
    bytes.fill(0);
    return hex;
  }, []);
  const groups = useMemo(() => groupsOf(seedHex), [seedHex]);
  const [step, setStep] = useState<'show' | 'confirm' | 'lock'>('show');
  const [challenges, setChallenges] = useState<number[]>([]);

  const confirmForm = useForm<ConfirmForm>({ defaultValues: { answers: {} } });
  const lockForm = useForm<LockForm>({ defaultValues: { passphrase: '', repeat: '' } });

  if (step === 'show') {
    return (
      <Panel title="Your new spend key">
        <Prose>
          <p>
            <strong className="text-ink">Write this down before you go on.</strong> It is the
            only thing that recovers this wallet, and nobody else has a copy: not a
            server, not this page after you leave it, not the node you connect to.
          </p>
          {storageWarning !== null && <p>{storageWarning}</p>}
          <p>
            Proving a payment happens in this browser too, in a background worker, and it takes
            tens of seconds. Nothing is contacted except the node you configure.
          </p>
        </Prose>
        {/* Hex, and no code beside it. A QR of the spend key is harvested by
            any camera, screen share or shoulder in the room in one frame,
            where reading the hex takes deliberate transcription, and nothing
            in this wallet scans one: the restore screen takes pasted hex. A
            scannable backup belongs with a camera import path, behind the
            same explicit reveal the miner key uses. */}
        {/* Numbered where they are shown, because the confirmation asks for
            them by ordinal. Unnumbered, the eight groups wrapped four and four
            at phone width and four in a row at desktop width, and somebody who
            wrote the key down as one 64-character string, or in a different
            number of columns than their window happened to use, had to count
            chunks in their own handwriting to answer "group 6 of 8" and could
            be off by one. The refusal then named groups they had copied
            correctly, and the way out redraws a fresh challenge set, so a
            miscount could loop without ever learning the transcription was
            fine. The grid is two columns at every width so the numbering a
            reader copies is the numbering they are asked for. */}
        <ol
          className="elev-inset my-3 grid list-none grid-cols-2 gap-x-4 gap-y-1 rounded-field
            border border-edge-strong bg-field p-3"
          data-testid="seed-hex"
        >
          {groups.map((group, index) => (
            <li key={group} className="flex items-baseline gap-2">
              <span className="w-4 shrink-0 text-right text-label text-muted" aria-hidden>
                {index + 1}
              </span>
              <span
                className="mm-secret text-body leading-6 tracking-wide text-ink"
                data-testid={`seed-group-${index}`}
              >
                {group}
              </span>
            </li>
          ))}
        </ol>
        <div className="mt-4 flex gap-2">
          <Button onClick={onCancel}>Cancel</Button>
          <Button
            variant="action"
            className="flex-1"
            data-testid="seed-written-down"
            onClick={() => {
              setChallenges(drawChallenges());
              setStep('confirm');
            }}
          >
            I have written it down
          </Button>
        </div>
      </Panel>
    );
  }

  if (step === 'confirm') {
    return (
      <Panel title="Confirm what you wrote">
        <Prose>
          <p>
            Type these groups back, by the numbers they were shown under, or skip this check to
            continue to passphrase setup.
          </p>
        </Prose>
        <form
          className="mt-3"
          onSubmit={(event) => {
            void confirmForm.handleSubmit((values) => {
              const wrong = challenges.filter(
                (index) => (values.answers[String(index)] ?? '').trim().toLowerCase() !== groups[index],
              );
              if (wrong.length > 0) {
                confirmForm.setError('root', {
                  message:
                    `That is not right for ${wrong.length === 1 ? 'group' : 'groups'} ` +
                    `${wrong.map((index) => index + 1).join(', ')}. You can look at the seed ` +
                    'again and start over.',
                });
                return;
              }
              confirmForm.clearErrors('root');
              setStep('lock');
            })(event);
          }}
        >
          {challenges.map((index) => (
            <Field
              key={index}
              label={`Group ${index + 1} of ${GROUPS}`}
              htmlFor={`confirm-group-${index}`}
            >
              <Input
                id={`confirm-group-${index}`}
                data-testid={`confirm-group-${index}`}
                autoComplete="off"
                spellCheck={false}
                {...confirmForm.register(`answers.${String(index)}` as const)}
              />
            </Field>
          ))}
          {confirmForm.formState.errors.root?.message !== undefined && (
            <Notice tone="error">{confirmForm.formState.errors.root.message}</Notice>
          )}
          <div className="mt-4 flex gap-2">
            <Button
              onClick={() => {
                confirmForm.reset({ answers: {} });
                setStep('show');
              }}
            >
              Show it again
            </Button>
            <Button type="submit" variant="action" className="flex-1" data-testid="confirm-seed">
              Confirm
            </Button>
          </div>
        </form>
        <Button
          type="button"
          variant="destructive"
          className="mt-3 w-full"
          data-testid="skip-seed-confirmation"
          disabled={busy}
          onClick={() => {
            setStep('lock');
          }}
        >
          Skip confirmation
        </Button>
      </Panel>
    );
  }

  return (
    <Panel title="Lock it with a passphrase">
      <Prose>
        <p>
          The seed and the secrets behind every transfer are encrypted with this passphrase before
          they are written to this browser&apos;s storage. It is not recoverable and it is not stored
          anywhere: forgetting it means restoring from your seed.
        </p>
      </Prose>
      <form
        className="mt-3"
        onSubmit={(event) => {
          void lockForm.handleSubmit((values) => {
            onCreated(seedHex, values.passphrase);
          })(event);
        }}
      >
        <Field
          label="Passphrase"
          htmlFor="passphrase"
          error={lockForm.formState.errors.passphrase?.message}
        >
          <Input
            id="passphrase"
            type="password"
            data-testid="passphrase"
            autoComplete="new-password"
            {...lockForm.register('passphrase', {
              // `validate` rather than `minLength`: react-hook-form skips
              // `minLength` when the field is empty, so a rule written that way
              // is dead for the one value that matters. `wallet/crypto.ts`
              // refuses the same floor at the boundary, where it is real.
              validate: (value) =>
                value.length >= MIN_PASSPHRASE || `use at least ${MIN_PASSPHRASE} characters`,
            })}
          />
        </Field>
        <Field
          label="Passphrase again"
          htmlFor="passphrase-repeat"
          error={lockForm.formState.errors.repeat?.message}
        >
          <Input
            id="passphrase-repeat"
            type="password"
            data-testid="passphrase-repeat"
            autoComplete="new-password"
            {...lockForm.register('repeat', {
              validate: (value, values) =>
                value === values.passphrase || 'those two do not match',
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
            data-testid="finish-create"
          >
            {busy ? 'Encrypting…' : 'Create wallet'}
          </Button>
        </div>
      </form>
    </Panel>
  );
}
