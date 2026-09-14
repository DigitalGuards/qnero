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
      {/* MyMonero sets this sentence at 13 px, weight 300, in the secondary
          ink, centred, in an otherwise empty panel: a quiet prompt over two
          answers. Setting it semibold in the primary ink made the question
          the brightest, heaviest thing on the screen and turned a choice into
          a document. The second paragraph moved to the create path, where the
          reader has decided to generate a key and the warning is actionable. */}
      <h1 className="mb-3 text-center text-body font-light text-ink-2">
        How would you like to
        <br />
        add a wallet?
      </h1>
      <Prose>
        <p>
          Everything this wallet holds lives in this browser: the spend key is generated here,
          encrypted here with a passphrase you choose, and used here.
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
