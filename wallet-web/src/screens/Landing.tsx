/**
 * The first screen: create, or restore.
 *
 * MyMonero's landing asks "How would you like to add a wallet?" over two
 * stacked buttons with the primary one last, and that is the shape here. What
 * changes is the sentence under it, because this wallet's answer to "where do
 * my keys live" is different from a light wallet's, and that is the thing to
 * say before somebody creates one.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router';

import { Button } from '../components/UI/Button';
import { Notice } from '../components/UI/Notice';
import { Panel, Prose } from '../components/UI/Panel';

export function Landing({ storageWarning }: { storageWarning: string | null }): ReactNode {
  return (
    <Panel>
      {/* MyMonero sets this same sentence at 13 px in a light weight, and
          `text-display` is 32 px, which in this design is the balance. The
          first screen a reader sees should not invert the type hierarchy the
          rest of the app is built on. */}
      <h1 className="mb-3 text-body font-normal text-ink">
        How would you like to
        <br />
        add a wallet?
      </h1>
      <Prose>
        <p>
          Everything this wallet holds lives in this browser. The spend key is generated here,
          encrypted here with a passphrase you choose, and used here: no server sees it and no
          server holds a copy. Losing this browser without the seed written down loses the wallet.
        </p>
        <p>
          Proving a payment happens here too, in a background worker, and it takes tens of seconds.
          Nothing is contacted except the node you configure.
        </p>
      </Prose>
      {storageWarning !== null && <Notice className="mt-3">{storageWarning}</Notice>}
      <div className="mt-4 space-y-2">
        <Button asChild size="block" data-testid="use-existing">
          <Link to="/restore">Use existing wallet</Link>
        </Button>
        <Button asChild variant="action" size="block" data-testid="create-wallet">
          <Link to="/create">Create new wallet</Link>
        </Button>
      </div>
    </Panel>
  );
}
