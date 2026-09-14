import { useState, type ReactNode, type SyntheticEvent } from 'react';

import { useChain } from '../app/chainContext';
import { href, navigate } from '../app/router';
import { useAsync } from '../app/useAsync';
import { fetchLeaf, findCommitment } from '../chain/leaves';
import { blockForHash, classifyQuery, findExtrinsic, findNullifierBlock } from '../chain/search';
import { fetchSnapshot } from '../chain/state';
import { nullifierSeen } from '../chain/state';
import { formatCount } from '../lib/units';
import { Empty, ErrorBox, Field, Fields, Loading, Notice, Panel } from '../components/ui';

export function Search({ query }: { query: string }): ReactNode {
  const [text, setText] = useState(query);
  const kind = classifyQuery(query);

  const onSubmit = (event: SyntheticEvent): void => {
    event.preventDefault();
    navigate({ name: 'search', query: text.trim() });
  };

  return (
    <>
      <header className="page__head">
        <h1>Search</h1>
        <p className="page__lede">
          A height, a block hash, an extrinsic hash, a nullifier or a commitment. The last two
          answer where they were seen, or that they were not.
        </p>
      </header>

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

      {query === '' ? null : kind === 'unknown' ? (
        <Empty>
          <span className="mono">{query}</span> is neither a height nor a 32-byte hash.
        </Empty>
      ) : kind === 'height' ? (
        <HeightResult height={Number(query)} />
      ) : (
        <HashResult hash={query.toLowerCase()} />
      )}
    </>
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

function HashResult({ hash }: { hash: string }): ReactNode {
  const { bundle, head } = useChain();
  const cheap = useAsync(
    bundle === null || head === null ? null : `direct:${hash}`,
    bundle === null || head === null
      ? null
      : async () => {
          const [height, seen] = await Promise.all([
            blockForHash(bundle.context, hash),
            nullifierSeen(bundle.context, hash, head.hash).catch(() => false),
          ]);
          return { height, seen };
        },
  );

  if (bundle === null || head === null || cheap.status === 'loading') {
    return <Loading what="the chain" />;
  }
  if (cheap.status === 'error') {
    return <ErrorBox>{cheap.error}</ErrorBox>;
  }

  return (
    <>
      <Panel title="Direct answers">
        <Fields>
          <Field
            label="A block on this chain"
            value={
              cheap.value.height === null ? (
                'not seen'
              ) : (
                <a href={href({ name: 'block', id: hash })}>
                  block {formatCount(cheap.value.height)}
                </a>
              )
            }
          />
          <Field
            label="In the settled nullifier set"
            value={cheap.value.seen ? 'seen' : 'not seen'}
            note="presence proves some note was spent and says nothing about which"
          />
        </Fields>
      </Panel>

      <Notice>
        <p>
          A 32-byte query is sent to the node as a nullifier-set lookup, which names that value to
          whoever runs it. The two searches below read public ranges and name nothing, and
          they run only when asked because each walks the chain.
        </p>
      </Notice>

      {cheap.value.seen ? <NullifierBlock hash={hash} /> : null}
      <CommitmentScan hash={hash} />
      <ExtrinsicScan hash={hash} />
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
          <button className="button" type="button" onClick={() => {
              setRun(true);
            }}>
            Read the last {formatCount(bundle.config.searchWindowBlocks)} blocks
          </button>
        </>
      ) : result.status === 'loading' ? (
        <Loading what={`blocks, ${formatCount(scanned)} read`} />
      ) : result.status === 'error' ? (
        <ErrorBox>{result.error}</ErrorBox>
      ) : result.value.found === null ? (
        <Empty>
          Not published in the last {formatCount(result.value.scanned)} blocks. It is in the settled
          set, so it was published earlier than this window reaches.
        </Empty>
      ) : (
        <p>
          Settled at{' '}
          <a href={href({ name: 'block', id: String(result.value.found.height) })}>
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
          if (found.index === null) {
            return { index: null, scanned: found.scanned, exhausted: found.exhausted, block: null };
          }
          const leaf = await fetchLeaf(bundle.context, found.index, head.hash);
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
            first. This reads commitments only and says nothing about which one matters.
          </p>
          <button className="button" type="button" onClick={() => {
              setRun(true);
            }}>
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
          <button className="button" type="button" onClick={() => {
              setRun(true);
            }}>
            Scan recent blocks
          </button>
        </>
      ) : result.status === 'loading' ? (
        <Loading what={`blocks, ${formatCount(scanned)} read`} />
      ) : result.status === 'error' ? (
        <ErrorBox>{result.error}</ErrorBox>
      ) : result.value.found === null ? (
        <Empty>
          Not in the last {formatCount(result.value.scanned)} blocks.
        </Empty>
      ) : (
        <p>
          Extrinsic {formatCount(result.value.found.index)} of{' '}
          <a href={href({ name: 'block', id: String(result.value.found.height) })}>
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
