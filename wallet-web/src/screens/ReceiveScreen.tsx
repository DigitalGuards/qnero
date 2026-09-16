/**
 * Receive Qnero: the address, its code, and the miner key behind a control.
 *
 * The address is long. It carries an ML-KEM-1024 encapsulation key, which is
 * 1568 bytes of the roughly 2600 characters, so it does not shorten and there
 * is no second short form: an integrated address or a subaddress would be
 * another thing to get wrong. The code is what a payment is made from, so the
 * code is first and the address is collapsed to three lines under it, whole on
 * request and selectable in one gesture either way.
 *
 * How transparent value gets into the pool is a command-line step and it lives
 * in `docs/WALLET.md`. What a reader of this screen needs on the public
 * testnet is the faucet, which is a link beside the copy control.
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
import { Panel } from '../components/UI/Panel';
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
        {/* The code first. A receive screen owes a phone the thing a payment
            is made from, and this one opened with a forty-four word paragraph
            and ten lines of an address, which put the code at y 517 of a
            667 px screen. */}
        <Qr value={address} uppercase caption="the same address, uppercase inside the code" />
        <div className="mt-3 flex flex-wrap gap-2">
          <CopyButton value={address} label="Copy address" testId="copy-address" />
          <Button asChild data-testid="receive-faucet">
            <a href="https://faucet.qnero.io" target="_blank" rel="noreferrer">
              Get test QNR from the faucet
            </a>
          </Button>
        </div>
        <Address value={address} testId="receive-address" expandable />
        <p className="mm-note text-muted">
          Payments to this address are private; the chain shows nothing about them.
        </p>
      </Panel>

      <Panel title="Miner key">
        <p className="text-body text-ink-2">
          What a node you run is configured with, so the blocks it wins pay this wallet.
        </p>
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
                <>
                  {/* The whole warning, in the one place a reader is deciding.
                      It was a four-sentence paragraph on the screen, above a
                      button, where it was read before there was anything to
                      decide. */}
                  <p>
                    This is not the address and it is secret bearing. It carries the coinbase
                    viewing key, so whoever holds it can pick this wallet&apos;s mining rewards
                    out of the tree and read what a miner earned block by block.
                  </p>
                  <p>
                    It cannot spend them, and it says nothing about anything else this wallet
                    holds. Do not hand it out the way an address is handed out.
                  </p>
                </>
              }
            >
              <Button
                variant="action"
                data-testid="confirm-miner-key"
                onClick={onRevealMinerKey}
              >
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
            <p className="mm-note mt-2 text-muted">
              Prefer the node&apos;s environment variable to its command line: every process listing
              on a machine can read a command line.
            </p>
          </>
        )}
      </Panel>
    </div>
  );
}
