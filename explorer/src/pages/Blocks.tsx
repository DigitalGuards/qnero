import type { ReactNode } from 'react';

import { useChain } from '../app/chainContext';
import { href } from '../app/router';
import { useAsync } from '../app/useAsync';
import { fetchRecent } from '../chain/blocks';
import { formatCount } from '../lib/units';
import { Empty, ErrorBox, Loading, Panel } from '../components/ui';
import { RecentBlocks } from './parts/RecentBlocks';

const PAGE_SIZE = 20;

export function Blocks({ before }: { before: number | null }): ReactNode {
  const { bundle, head } = useChain();
  const top = before ?? head?.header.number ?? null;
  const blocks = useAsync(
    bundle === null || top === null ? null : `blocks:${top}`,
    bundle === null || top === null
      ? null
      : () => fetchRecent(bundle.context, bundle.cache, top, PAGE_SIZE),
  );

  if (bundle === null || top === null) {
    return <Loading what="the chain head" />;
  }

  const older = top - PAGE_SIZE;
  const newer = before === null ? null : before + PAGE_SIZE;

  return (
    <>
      <header className="page__head">
        <h1>Blocks</h1>
        <p className="page__lede">
          Newest first, from height {formatCount(top)}. A height names different blocks on different
          branches, so every link here carries the block it meant.
        </p>
      </header>
      <Panel>
        {blocks.status === 'loading' ? <Loading what="blocks" /> : null}
        {blocks.status === 'error' ? <ErrorBox>{blocks.error}</ErrorBox> : null}
        {blocks.status === 'ready' ? (
          blocks.value.length === 0 ? (
            <Empty>No blocks in this range.</Empty>
          ) : (
            <RecentBlocks blocks={blocks.value} />
          )
        ) : null}
        <div className="pager">
          <a
            className="button"
            style={{ lineHeight: '30px' }}
            href={href({ name: 'blocks', before: null })}
          >
            Newest
          </a>
          {newer === null ? null : (
            <a
              className="button"
              style={{ lineHeight: '30px' }}
              href={href({
                name: 'blocks',
                before: head === null ? newer : Math.min(newer, head.header.number),
              })}
            >
              Newer
            </a>
          )}
          {older < 0 ? null : (
            <a className="button" style={{ lineHeight: '30px' }} href={href({ name: 'blocks', before: older })}>
              Older
            </a>
          )}
        </div>
      </Panel>
    </>
  );
}
