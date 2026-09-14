import { useState, type ReactNode, type SyntheticEvent } from 'react';

import { useChain } from '../app/chainContext';
import { href, navigate } from '../app/router';
import { useAsync } from '../app/useAsync';
import { fetchLeaves, findCommitment } from '../chain/leaves';
import { blockForHash, classifyQuery, findExtrinsic, findNullifierBlock } from '../chain/search';
import { fetchSnapshot, nullifierSeen } from '../chain/state';
import { formatCount } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Loading, Notice, Panel } from '../components/ui';

export function Search({ query }: { query: string }): ReactNode {
  const kind = classifyQuery(query);

  return (
    <>
      <header className="page__head">
        <h1>Search</h1>
        <p className="page__lede">
          A height, a block hash, an extrinsic hash, a nullifier or a commitment. The last two
          answer where they were seen, or that they were not.
        </p>
      </header>

      {/* Keyed by the route's query, so the box follows the route. A box that
          kept the previous value across a back button would leave the consent
          notice below naming 32 bytes that are not the ones the lookup sends. */}
      <SearchBox key={query} initial={query} />

      {query === '' ? null : kind === 'unknown' ? (
        <Empty>
          <span className="mono">{query}</span> is neither a height nor a 32-byte hash.
        </Empty>
      ) : kind === 'height' ? (
        <HeightResult height={Number(query)} />
      ) : (
        // Keyed by the query, so asking about a second value starts from the
        // warning again. Consent to name one nullifier to the node is not
        // consent to name the next one.
        <HashResult key={query.toLowerCase()} hash={query.toLowerCase()} />
      )}
    </>
  );
}

function SearchBox({ initial }: { initial: string }): ReactNode {
  const [text, setText] = useState(initial);
  const onSubmit = (event: SyntheticEvent): void => {
    event.preventDefault();
    navigate({ name: 'search', query: text.trim() });
  };
  return (
    <Panel>
      <form className="row row--search" onSubmit={onSubmit} role="search">
        <label className="field__label" htmlFor="search-input">
          Query
        </label>
        <input
          id="search-input"
          className="input"
          value={text}
          onChange={(event) => {
            setText(event.target.value);
          }}
          placeholder="height, or 0x followed by 64 hex characters"
          spellCheck={false}
          autoComplete="off"
        />
        <button className="button button--action" type="submit">
          Look up
        </button>
      </form>
    </Panel>
  );
}

function HeightResult({ height }: { height: number }): ReactNode {
  return (
    <Panel title="Height">
      <p>
        <a href={href({ name: 'block', id: String(height) })}>Block {formatCount(height)}</a>
      </p>
    </Panel>
  );
}

/**
 * What a 32-byte value can be, one question at a time.
 *
 * Only the block check runs on its own. It reads a header, which names nothing
 * the chain does not already publish, and a block hash is public by
 * construction. Everything below it is asked for, because a nullifier lookup
 * names the value to whoever runs the node and the two scans walk the chain.
 * The warning is on the page before any of them can run, which is the point of
 * running none of them automatically.
 *
 * The whole subtree is keyed by the query, so every button is back to unasked
 * when the query changes. Without that, one click would carry its permission
 * to every value typed after it.
 */
function HashResult({ hash }: { hash: string }): ReactNode {
  const { bundle } = useChain();
  const asBlock = useAsync(
    bundle === null ? null : `block-for:${hash}`,
    bundle === null ? null : () => blockForHash(bundle.context, hash),
  );

  if (bundle === null) {
    return <Loading what="the chain" />;
  }

  return (
    <>
      <Notice>
        <p>
          This page is answering for <span className="mono">{hash}</span>.
        </p>
        <p>
          A nullifier lookup builds a map key out of those 32 bytes and asks the node for it, so
          whoever runs the node learns that someone asked about that value. It runs only when you
          ask for it below, and so do the two scans, which read leaves and events in ranges and
          name no single one of them.
        </p>
      </Notice>

      <Panel title="Direct answers">
        <Fields>
          <Field
            label="A block on this chain"
            value={
              asBlock.status === 'loading' ? (
                'reading'
              ) : asBlock.status === 'error' ? (
                'not answered'
              ) : asBlock.value === null ? (
                'not seen'
              ) : (
                <a href={href({ name: 'block', id: hash })}>block {formatCount(asBlock.value)}</a>
              )
            }
            note="one header read, which names nothing the chain does not already publish"
          />
        </Fields>
      </Panel>

      <NullifierLookup hash={hash} />
      <CommitmentScan hash={hash} />
      <ExtrinsicScan hash={hash} />
    </>
  );
}

/**
 * The point lookup, behind the disclosure.
 *
 * A failure is never rendered as "not seen". The negative is the answer a
 * reader acts on, and a refused read, a dropped socket or a renamed storage
 * item establishes nothing. Storage drift blocks the question outright,
 * because a key built with the wrong hasher is simply absent and an absent key
 * reads exactly like an empty set.
 */
function NullifierLookup({ hash }: { hash: string }): ReactNode {
  const { bundle, head } = useChain();
  // The block the question was asked at, captured on the click. Keying this on
  // the live head instead would re-send the lookup on every imported block, so
  // one consent would keep naming the value to the node for as long as the tab
  // stayed open, and every re-run would drop the answer back to loading and
  // throw away the walk below it.
  const [askedAt, setAskedAt] = useState<{ hash: string; number: number } | null>(null);
  const result = useAsync(
    bundle === null || askedAt === null ? null : `nullifier:${hash}`,
    bundle === null || askedAt === null
      ? null
      : () => nullifierSeen(bundle.context, hash, askedAt.hash),
  );
  // The key holds no head, so a ready answer stays ready and the walk mounted
  // under it is never unmounted halfway through by a newly imported block.
  const answered = result.status === 'ready' ? result.value : null;
  if (bundle === null) {
    return null;
  }
  const drift = bundle.context.storageDrift;

  return (
    <>
      <Panel title="The settled nullifier set">
        {drift.length > 0 ? (
          <ErrorBox>
            The runtime declares its storage differently from what this build assumes, so a lookup
            here would answer &ldquo;not seen&rdquo; for every value with no error anywhere:{' '}
            {drift.join('; ')}.
          </ErrorBox>
        ) : askedAt === null ? (
          <>
            <p>
              This asks the node for one key built from these 32 bytes, which names the value to
              whoever runs it. It runs once, against the block the chain is at when you ask.
              Membership proves some note was spent and says nothing about which note it was.
            </p>
            <button
              className="button"
              type="button"
              disabled={head === null}
              onClick={() => {
                if (head !== null) {
                  setAskedAt({ hash: head.hash, number: head.header.number });
                }
              }}
            >
              Check the settled nullifier set
            </button>
          </>
        ) : result.status === 'loading' ? (
          <Loading what="the settled set" />
        ) : (
          <>
            <Fields>
              <Field
                label="In the settled nullifier set"
                value={
                  result.status === 'error' ? 'not answered' : answered === true ? 'seen' : 'not seen'
                }
                note={
                  result.status === 'error'
                    ? 'the node did not answer, so this is not an absence'
                    : `as of block ${formatCount(askedAt.number)}: presence proves some note was spent and says nothing about which`
                }
              />
            </Fields>
            {result.status === 'error' ? <ErrorBox>{result.error}</ErrorBox> : null}
          </>
        )}
      </Panel>
      {answered === true ? <NullifierBlock hash={hash} /> : null}
    </>
  );
}

function NullifierBlock({ hash }: { hash: string }): ReactNode {
  const { bundle, head } = useChain();
  const [run, setRun] = useState(false);
  const [scanned, setScanned] = useState(0);
  const result = useAsync(
    !run || bundle === null || head === null ? null : `nullifier-block:${hash}`,
    !run || bundle === null || head === null
      ? null
      : () =>
          findNullifierBlock(
            bundle.context,
            hash,
            head.header.number,
            bundle.config.searchWindowBlocks,
            setScanned,
          ),
  );
  if (bundle === null) {
    return null;
  }
  return (
    <Panel title="Which settlement published it">
      {!run ? (
        <>
          <p>
            The settled set holds presence only. Finding the block means reading the settlement
            events of the last {formatCount(bundle.config.searchWindowBlocks)} blocks.
          </p>
          <button
            className="button"
            type="button"
            onClick={() => {
              setRun(true);
            }}
          >
            Read the last {formatCount(bundle.config.searchWindowBlocks)} blocks
          </button>
        </>
      ) : result.status === 'loading' ? (
        <Loading what={`blocks, ${formatCount(scanned)} read`} />
      ) : result.status === 'error' ? (
        <ErrorBox>{result.error}</ErrorBox>
      ) : result.value.found === null ? (
        <Empty>
          Not published in the last {formatCount(result.value.scanned)} blocks
          {result.value.stopped === null ? '' : `, and ${result.value.stopped}`}. It is in the
          settled set, so it was published earlier than this walk reached.
        </Empty>
      ) : (
        <p>
          Settled at{' '}
          <a href={href({ name: 'block', id: result.value.found.blockHash })}>
            block {formatCount(result.value.found.height)}
          </a>
          , extrinsic {result.value.found.extrinsicIndex ?? '-'}.
        </p>
      )}
    </Panel>
  );
}

function CommitmentScan({ hash }: { hash: string }): ReactNode {
  const { bundle, head } = useChain();
  const [run, setRun] = useState(false);
  const [scanned, setScanned] = useState(0);
  const result = useAsync(
    !run || bundle === null || head === null ? null : `commitment:${hash}`,
    !run || bundle === null || head === null
      ? null
      : async () => {
          const snapshot = await fetchSnapshot(bundle.context);
          const found = await findCommitment(
            bundle.context,
            hash,
            Number(snapshot.tree.leafCount),
            head.hash,
            bundle.config.searchWindowBlocks * 4,
            setScanned,
          );
          if (found.index === null || found.window === null) {
            return { index: null, scanned: found.scanned, exhausted: found.exhausted, block: null };
          }
          // The window the match came out of, read back whole, and the row
          // picked here. Asking for the one leaf would name it to whoever runs
          // the node, which is the correlation this site exists not to hand
          // over, and it would do it on the page that says it does not.
          const window = await fetchLeaves(
            bundle.context,
            found.window.start,
            found.window.end,
            head.hash,
          );
          const leaf = window.find((row) => row.index === found.index);
          return {
            index: found.index,
            scanned: found.scanned,
            exhausted: found.exhausted,
            block: leaf?.blockNumber ?? null,
          };
        },
  );
  if (bundle === null) {
    return null;
  }
  return (
    <Panel title="As a commitment in the tree">
      {!run ? (
        <>
          <p>
            The tree is keyed by leaf index, so finding a commitment means reading leaves newest
            first. Every request here asks for a range of leaves, so none of them names the one
            that matters.
          </p>
          <button
            className="button"
            type="button"
            onClick={() => {
              setRun(true);
            }}
          >
            Scan the tree
          </button>
        </>
      ) : result.status === 'loading' ? (
        <Loading what={`leaves, ${formatCount(scanned)} read`} />
      ) : result.status === 'error' ? (
        <ErrorBox>{result.error}</ErrorBox>
      ) : result.value.index === null ? (
        <Empty>
          Not among the {formatCount(result.value.scanned)} newest leaves
          {result.value.exhausted ? ', which is the whole tree' : ''}.
        </Empty>
      ) : (
        <p>
          Leaf {formatCount(result.value.index)}
          {result.value.block === null ? (
            ''
          ) : (
            <>
              , appended at{' '}
              <a href={href({ name: 'block', id: String(result.value.block) })}>
                block {formatCount(result.value.block)}
              </a>
            </>
          )}
          .
        </p>
      )}
    </Panel>
  );
}

function ExtrinsicScan({ hash }: { hash: string }): ReactNode {
  const { bundle, head } = useChain();
  const [run, setRun] = useState(false);
  const [scanned, setScanned] = useState(0);
  const result = useAsync(
    !run || bundle === null || head === null ? null : `extrinsic:${hash}`,
    !run || bundle === null || head === null
      ? null
      : () =>
          findExtrinsic(
            bundle.context,
            hash,
            head.header.number,
            bundle.config.searchWindowBlocks,
            setScanned,
          ),
  );
  if (bundle === null) {
    return null;
  }
  return (
    <Panel title="As an extrinsic hash">
      {!run ? (
        <>
          <p>
            Bodies are not indexed here, so this reads the last{' '}
            {formatCount(bundle.config.searchWindowBlocks)} blocks and hashes what it finds.
          </p>
          <button
            className="button"
            type="button"
            onClick={() => {
              setRun(true);
            }}
          >
            Scan recent blocks
          </button>
        </>
      ) : result.status === 'loading' ? (
        <Loading what={`blocks, ${formatCount(scanned)} read`} />
      ) : result.status === 'error' ? (
        <ErrorBox>{result.error}</ErrorBox>
      ) : result.value.found === null ? (
        <Empty>
          Not in the last {formatCount(result.value.scanned)} blocks
          {result.value.stopped === null ? '' : `, and ${result.value.stopped}`}.
        </Empty>
      ) : (
        <p>
          Extrinsic {formatCount(result.value.found.index)} of{' '}
          <a href={href({ name: 'block', id: result.value.found.blockHash })}>
            block {formatCount(result.value.found.height)}
          </a>
          . <a href={href({ name: 'settlement', hash, at: result.value.found.blockHash })}>Open it</a>
          .
        </p>
      )}
    </Panel>
  );
}

export function NotFound({ path }: { path: string }): ReactNode {
  return (
    <>
      <header className="page__head">
        <h1>Not a page</h1>
      </header>
      <Empty>
        <span className="mono">{path}</span> is not a route on this site.{' '}
        <a href={href({ name: 'home' })}>Back to the chain</a>.
      </Empty>
    </>
  );
}
