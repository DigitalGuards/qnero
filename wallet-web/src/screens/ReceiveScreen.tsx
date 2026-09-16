/**
 * Receive Qnero: the address, then its code behind a control, then the miner
 * key behind another.
 *
 * The address is long. It carries an ML-KEM-1024 encapsulation key, which is
 * 1568 bytes of its 2571 characters, so it does not shorten and there is no
 * second short form: an integrated address or a subaddress would be another
 * thing to get wrong. That length is also what the code is made of. 1568
 * uniformly random bytes do not compress, so the symbol is version 35 whatever
 * encoding or correction level is chosen, and on a laptop it is a wall of
 * modules too fine for a phone held at arm's length. Nothing in this wallet
 * scans one either.
 *
 * So the screen leads with the text and the ways of handing it over: copy, and
 * the system share sheet where the device has one. The code is behind a
 * disclosure, remembered for as long as this tab is open, for the reader who
 * wants to try it anyway. The shorter address that would make the code small
 * is a key registry on chain and a protocol change, and it is planned
 * separately.
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

import { Eye, QrCode, Share2 } from 'lucide-react';
import { useState, type ReactNode } from 'react';

import { Address } from '../components/UI/Address';
import { Button } from '../components/UI/Button';
import { CopyButton } from '../components/UI/CopyButton';
import { Dialog, DialogContent, DialogTrigger } from '../components/UI/Dialog';
import { Notice } from '../components/UI/Notice';
import { Panel } from '../components/UI/Panel';
import { Qr } from '../components/UI/Qr';

/**
 * Whether the code was open, for this tab and no longer.
 *
 * `sessionStorage` rather than `localStorage`: a reader who opened the code
 * once to try a scanner should not meet it on every visit from now on, and a
 * reader who is mid-task should not lose it by switching tabs and back. Both
 * accessors throw in a private window with site data blocked, which is not a
 * failure: the code is then closed on each open, which is the default anyway.
 */
const QR_KEY = 'qnero-wallet-receive-qr';

function readQrOpen(): boolean {
  try {
    return sessionStorage.getItem(QR_KEY) === 'open';
  } catch {
    return false;
  }
}

function writeQrOpen(open: boolean): void {
  try {
    sessionStorage.setItem(QR_KEY, open ? 'open' : 'closed');
  } catch {
    // A private window, or site data blocked.
  }
}

/** Whether this device has a share sheet to hand the address to. */
function hasShareSheet(): boolean {
  return typeof navigator.share === 'function';
}

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
  const [qrOpen, setQrOpen] = useState(readQrOpen);
  // Read once per mount. A share sheet does not appear part way through a
  // visit, and a control that comes and goes between renders is worse than one
  // that is decided when the screen opens.
  const [canShare] = useState(hasShareSheet);

  return (
    <div className="space-y-3">
      <Panel title="Receive Qnero">
        {/* The text first, whole and selectable in one gesture. It is what a
            payment is actually made from here: the code is 2571 characters of
            incompressible key and nothing in this wallet reads one. */}
        <Address value={address} testId="receive-address" />
        <div className="mt-3 flex flex-wrap gap-2">
          <CopyButton value={address} label="Copy address" testId="copy-address" />
          {canShare && (
            <Button
              data-testid="share-address"
              onClick={() => {
                // The sheet rejects when it is dismissed, which is a reader
                // changing their mind rather than an error to report.
                navigator.share({ text: address }).then(
                  () => undefined,
                  () => undefined,
                );
              }}
            >
              <Share2 className="size-3.5" aria-hidden />
              Share address
            </Button>
          )}
          <Button asChild data-testid="receive-faucet">
            <a href="https://faucet.qnero.io" target="_blank" rel="noreferrer">
              Get test QNR from the faucet
            </a>
          </Button>
        </div>
        <p className="mm-note text-muted">
          Payments to this address are private; the chain shows nothing about them.
        </p>

        <div className="mt-3">
          <Button
            data-testid="toggle-qr"
            aria-expanded={qrOpen}
            aria-controls="receive-qr"
            onClick={() => {
              const next = !qrOpen;
              setQrOpen(next);
              writeQrOpen(next);
            }}
          >
            <QrCode className="size-3.5" aria-hidden />
            {qrOpen ? 'Hide QR code' : 'Show QR code'}
          </Button>
          {qrOpen && (
            <div id="receive-qr" className="mt-3">
              <Qr
                value={address}
                uppercase
                alt="this wallet's address as a QR code, uppercase inside the code"
                caption="A Qnero address is 2571 characters, so its code is large; copying the text is the reliable way to hand it over."
              />
            </div>
          )}
        </div>
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
