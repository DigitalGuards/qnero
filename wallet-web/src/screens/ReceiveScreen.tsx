/**
 * Receive Qnero: the address, its code, and the miner key behind a control.
 *
 * The address is long. It carries an ML-KEM-1024 encapsulation key, which is
 * 1568 bytes of the roughly 2600 characters, so it does not shorten and there
 * is no second short form: an integrated address or a subaddress would be
 * another thing to get wrong. It is shown whole, selectable in one gesture,
 * with the code beside it.
 *
 * The miner key is not the address and the screen says so before it shows one.
 * It carries the coinbase viewing key, so whoever holds it can pick this
 * wallet's coinbase notes out of the tree, and it is what a node an operator
 * runs is configured with. An address is meant to be handed out; this is not.
 */

import { Eye } from 'lucide-react';
import type { ReactNode } from 'react';

import { Address } from '../components/UI/Address';
import { Button } from '../components/UI/Button';
import { CopyButton } from '../components/UI/CopyButton';
import { Dialog, DialogContent, DialogTrigger } from '../components/UI/Dialog';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';
import { Qr } from '../components/UI/Qr';

export function ReceiveScreen({
  address,
  minerKey,
  onRevealMinerKey,
  locked,
}: {
  address: string;
  minerKey: string | null;
  onRevealMinerKey: () => void;
  locked: boolean;
}): ReactNode {
  return (
    <div className="space-y-3">
      <Panel title="Receive Qnero">
        <Prose>
          <p>
            Anything sent to this address arrives as a note only this wallet can open. The chain
            publishes the commitment and the ciphertext and nothing else: not the amount, not the
            sender, not which of a settlement&apos;s two outputs is this one.
          </p>
        </Prose>
        <Address value={address} testId="receive-address" />
        <div className="mb-3 flex gap-2">
          <CopyButton value={address} label="Copy address" testId="copy-address" />
        </div>
        <Qr value={address} uppercase caption="the same address, uppercase inside the code" />
        <Notice className="mt-3">
          Moving transparent value into the pool is a command-line step. A shield is signed with
          ML-DSA-87 and this browser&apos;s prover exports no signing at all, so this wallet is
          funded by a payment from another wallet, by `qnero-wallet shield` followed by a send, or
          by a node configured with the miner key below.
        </Notice>
      </Panel>

      <Panel title="Miner key">
        <Prose>
          <p>
            <strong className="text-ink">This is not the address, and it is secret bearing.</strong>{' '}
            It is what a node you run is configured with so that the blocks it wins mint their
            reward to this wallet. It carries the coinbase viewing key, so whoever holds it can pick
            this wallet&apos;s coinbase notes out of the tree. It cannot spend them, and it says
            nothing about any other note this wallet holds.
          </p>
        </Prose>
        {locked ? (
          <Notice className="mt-3">Unlock this wallet to derive its miner key.</Notice>
        ) : minerKey === null ? (
          <Dialog>
            <DialogTrigger asChild>
              <Button className="mt-3" data-testid="reveal-miner-key">
                <Eye className="size-3.5" aria-hidden />
                Show the miner key
              </Button>
            </DialogTrigger>
            <DialogContent
              title="Show the miner key?"
              description={
                <p>
                  Whoever holds it can pick this wallet&apos;s coinbase notes out of the tree and
                  read what a miner earned block by block. Do not hand it out the way an address is
                  handed out.
                </p>
              }
            >
              <Button variant="action" size="block" data-testid="confirm-miner-key" onClick={onRevealMinerKey}>
                Show it
              </Button>
            </DialogContent>
          </Dialog>
        ) : (
          <>
            <Address value={minerKey} tone="secret" testId="miner-key" />
            <div className="flex gap-2">
              <CopyButton value={minerKey} label="Copy miner key" />
            </div>
            <p className="mt-2 text-meta text-muted">
              Prefer the node&apos;s environment variable to its command line: every process listing
              on a machine can read a command line.
            </p>
          </>
        )}
      </Panel>
    </div>
  );
}
