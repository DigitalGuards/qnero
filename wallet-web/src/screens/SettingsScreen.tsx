/**
 * Settings: the node, the lock, and what this wallet reveals.
 *
 * MyMonero's settings screen holds the server address and the lock, and so
 * does this one. The third panel is not in that wallet and is the point of
 * this one: a light wallet hands its server a viewing key and is told which
 * outputs are its own, and this wallet's whole design is the refusal to. So
 * what it does and does not tell the node is written on the screen, in the
 * words `docs/WALLET.md` uses, next to the field that decides which node that
 * is.
 */

import { Lock, RotateCcw } from 'lucide-react';
import { useState, type ReactNode } from 'react';

import { Button } from '../components/UI/Button';
import { Dialog, DialogContent, DialogTrigger } from '../components/UI/Dialog';
import { Field, Input } from '../components/UI/Field';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';
import { Switch } from '../components/UI/Switch';
import { endpointIsWebSocket } from '../chain/config';
import type { ConnectionState } from '../app/session';

export function SettingsScreen({
  connection,
  chainName,
  endpoint,
  onEndpoint,
  onLock,
  onRescan,
  onStopProver,
  onStartProver,
  onForget,
  proverThreads,
  proverRunning,
  persisted,
  busy,
}: {
  connection: ConnectionState;
  chainName: string;
  endpoint: string;
  onEndpoint: (endpoint: string) => void;
  onLock: () => void;
  onRescan: () => void;
  onStopProver: () => void;
  onStartProver: () => void;
  onForget: () => void;
  proverThreads: number;
  proverRunning: boolean;
  persisted: boolean;
  busy: boolean;
}): ReactNode {
  const [draft, setDraft] = useState(endpoint);

  return (
    <div className="space-y-3">
      <Panel title="Node">
        <Field
          label="RPC endpoint"
          htmlFor="endpoint"
          hint="WebSocket. This is the only address this wallet contacts."
          error={
            draft.length > 0 && !endpointIsWebSocket(draft)
              ? 'a node address starts with ws:// or wss://'
              : undefined
          }
        >
          <Input
            id="endpoint"
            data-testid="endpoint"
            autoComplete="off"
            spellCheck={false}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
            }}
          />
        </Field>
        <div className="flex items-center justify-between gap-2">
          <span className="text-meta text-muted">
            {connection.kind === 'live'
              ? `${chainName}: ${connection.specName ?? 'unknown'} ${connection.specVersion ?? ''}, head ${connection.head ?? '?'}`
              : connection.kind === 'failed'
                ? (connection.error ?? 'this node did not answer')
                : connection.kind}
          </span>
          <Button
            disabled={busy || !endpointIsWebSocket(draft)}
            data-testid="apply-endpoint"
            onClick={() => {
              onEndpoint(draft.trim());
            }}
          >
            Connect
          </Button>
        </div>
        {connection.drift !== undefined && connection.drift.length > 0 && (
          <Notice tone="error" className="mt-3">
            <p>This runtime declares storage differently from what this build assumes:</p>
            {connection.drift.map((entry) => (
              <p key={entry}>{entry}</p>
            ))}
            <p>
              An absent key and an empty map are indistinguishable, and an empty map here is a zero
              balance or a settled note reported unspent. Syncing against this node is refused.
            </p>
          </Notice>
        )}
      </Panel>

      <Panel title="What this wallet tells the node">
        <Prose>
          <p>
            A light wallet hands a server its viewing key and is told which outputs are its own.
            This wallet has no server and does not do that. What it asks the node for is public
            data, whole:
          </p>
          <p>
            <strong className="text-ink">Reading the chain.</strong> Every ciphertext, by leaf
            index, in batches, and every one of them is tried against this wallet&apos;s viewing key
            here. The node cannot tell which one decrypted.
          </p>
          <p>
            <strong className="text-ink">Spent status.</strong> The whole settled nullifier set is
            paged, and every decision is made against the local copy. The node is never asked about
            one nullifier, because that request would carry the raw value: a node that logged those
            would hold, per wallet, the set of values it will publish when it spends, before it has
            spent anything.
          </p>
          <p>
            <strong className="text-ink">Spending.</strong> Merkle paths are rebuilt here from the
            whole leaf range. The node is never asked for one leaf&apos;s proof, because that names
            the leaf being spent seconds before the settlement publishes the matching nullifiers.
          </p>
          <p>
            <strong className="text-ink">What it does learn.</strong> Your network address, that a
            wallet is syncing from it, roughly how often, and the exact bytes of every settlement
            you submit through it. A settlement&apos;s two nullifiers and two commitments are public
            the moment it is in a block, and the wallet asks this node to confirm those two
            nullifiers by name once, to tell a settled spend from one the chain skipped.
          </p>
          <p>
            <strong className="text-ink">What a chain reader sees.</strong> That a settlement
            happened, its fee, its anchor block, and two commitments and two ciphertexts of a fixed
            size. Not the amounts, not the sender, not the recipient, and not which of the two
            outputs is the change.
          </p>
        </Prose>
      </Panel>

      <Panel title="Prover">
        <Prose>
          <p>
            Proving runs in a background worker.{' '}
            {proverThreads > 1
              ? `This browser is cross-origin isolated, so the threaded module is in use with ${proverThreads} threads.`
              : 'This browser is running the single-threaded module: either it is not cross-origin isolated, or no threaded module is published beside this build.'}
          </p>
          <p>
            The circuits hold most of a gigabyte of linear memory once built, and wasm linear memory
            never shrinks. Stopping the worker is the only way to give it back. Nothing can sync or
            send while it is stopped, and starting it again loads the module afresh, so the next
            payment pays the circuit build too.
          </p>
        </Prose>
        <div className="mt-3 flex items-center justify-between gap-2">
          <label className="text-ui text-ink" htmlFor="prover-resident">
            Keep the prover resident
          </label>
          <Switch
            id="prover-resident"
            checked={proverRunning}
            disabled={busy}
            data-testid="prover-resident"
            onCheckedChange={(next) => {
              if (next) {
                onStartProver();
              } else {
                onStopProver();
              }
            }}
          />
        </div>
      </Panel>

      <Panel title="This wallet">
        <Prose>
          <p>
            Storage is {persisted ? 'marked persistent' : 'not marked persistent'} in this browser.
            {persisted
              ? ' The browser has been asked not to evict it under storage pressure.'
              : " A browser under storage pressure may drop it, and this store is the only copy of every note's randomness. Value settled on chain becomes unspendable if it goes."}
          </p>
        </Prose>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button data-testid="lock-wallet" onClick={onLock}>
            <Lock className="size-3.5" aria-hidden />
            Lock
          </Button>
          <Button disabled={busy} data-testid="rescan" onClick={onRescan}>
            <RotateCcw className="size-3.5" aria-hidden />
            Rescan from leaf zero
          </Button>
        </div>
        <p className="mt-2 text-meta text-muted">
          A rescan drops this wallet&apos;s watermark and its record of which blocks it has seen,
          then walks the node&apos;s whole tree again. It runs add only: spent flags and orphaned
          notes are not reconciled, because the evidence for reconciling them is the node gate the
          rescan bypassed. Run an ordinary sync against a current node afterwards.
        </p>
        <div className="mt-4 border-t border-edge pt-3">
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="destructive">Remove this wallet</Button>
            </DialogTrigger>
            <DialogContent
              title="Erase this wallet?"
              description={
                <p>
                  This erases the encrypted seed and every note from this browser. Without the 32
                  bytes you wrote down there is no way back, and nothing anywhere else holds a copy.
                </p>
              }
            >
              <Button
                variant="destructive"
                className="flex-1"
                data-testid="confirm-forget"
                onClick={onForget}
              >
                Erase everything
              </Button>
            </DialogContent>
          </Dialog>
        </div>
      </Panel>
    </div>
  );
}
