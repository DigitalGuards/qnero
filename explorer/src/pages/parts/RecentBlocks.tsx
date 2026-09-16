import { useEffect, useState, type ReactNode } from 'react';

import { href } from '../../app/router';
import type { BlockSummary } from '../../chain/blocks';
import { formatAgo, formatCount, formatQnr } from '../../lib/units';
import { Hash, TableWrap } from '../../components/ui';

/**
 * The clock the ages are read against.
 *
 * The ages used to be computed at render and re-rendered only when the head
 * changed, so on the blocks page for an older range, which never re-renders,
 * "6 s ago" stayed "6 s ago" for as long as the tab was open. At a 12 s target
 * block time a list of ages that does not move reads as a stalled chain.
 *
 * One interval for the whole list, and none at all for a reader who asked for
 * less movement: for them the ages are the times they were when the page was
 * read, which is a static state and still true of the blocks.
 */
function useSecond(): number {
  const [reduced] = useState(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (reduced) {
      return;
    }
    const id = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(id);
    };
  }, [reduced]);
  return now;
}

/**
 * The two empty cases are different and the word for each is different.
 *
 * `null` is state the node no longer keeps, which is what `unread` means
 * everywhere on this site. A timestamp of 0 is genesis, which the node did
 * read and which simply carries no time: the block page says `none` for it,
 * and a row that said `unread` for the block whose coinbase it prints as
 * `none` contradicted the page it links to.
 */
function age(timestampMs: number | null, now: number): ReactNode {
  if (timestampMs === null) {
    return <span className="dim">unread</span>;
  }
  if (timestampMs === 0) {
    return <span className="dim">none</span>;
  }
  return formatAgo(timestampMs, now);
}

/**
 * The block list.
 *
 * Every row links by hash and shows the height. A height names different
 * blocks on different branches and this chain reorgs up to its reorg depth, so
 * a link by height would quietly open a different block than the row the
 * reader clicked.
 *
 * A row whose state the node no longer keeps shows dashes rather than zeros:
 * an unread block and an empty block are not the same block. It fills the same
 * cells as every other row, because a spanning cell leaves the table two
 * columns short of its header once the narrow layout drops the wide ones.
 *
 * The row is the tap target: the height's link is stretched over it, so a tap
 * anywhere on the row opens the block it names and the keyboard order is one
 * stop per row.
 *
 * At phone width the columns that carry the block's answer stay and the author
 * label goes. It is the widest cell in the row and, by its own note, groups
 * nothing across blocks, so clipping the coinbase amount to keep it would be
 * trading a number for a label.
 */
export function RecentBlocks({
  blocks,
  label = 'Blocks, newest first',
}: {
  blocks: readonly BlockSummary[];
  label?: string;
}): ReactNode {
  const now = useSecond();
  return (
    <TableWrap label={label}>
      <table>
        <thead>
          <tr>
            <th scope="col">Height</th>
            <th scope="col">Age</th>
            {/* What the label is worth, under the column it is about. It was
                a yellow box of its own between two panels, and at 375 px it
                explained a column the phone does not show. */}
            <th className="col--wide" scope="col">
              Author label
              <span className="th__note">
                H(cvk, parent_hash), which changes every block, so no table here groups a
                miner&rsquo;s income
              </span>
            </th>
            <th className="col--wide" scope="col">
              Leaves
            </th>
            <th scope="col">Settlements</th>
            <th className="col--wide" scope="col">
              Entries
            </th>
            <th scope="col">Coinbase</th>
          </tr>
        </thead>
        <tbody>
          {blocks.map((block) => (
            <tr key={block.hash}>
              <td className="num row-link">
                <a href={href({ name: 'block', id: block.hash })}>
                  {formatCount(block.header.number)}
                </a>
              </td>
              <td className="num">{age(block.timestampMs, now)}</td>
              <td className="col--wide">
                {block.header.authorLabel === null ? (
                  <span className="dim">none</span>
                ) : (
                  <Hash value={block.header.authorLabel} />
                )}
              </td>
              {block.stateError === null ? (
                <>
                  <td className="num col--wide">{formatCount(block.leavesAdded.length)}</td>
                  <td className="num">{formatCount(block.settlements.length)}</td>
                  <td className="num col--wide">{formatCount(block.entries.length)}</td>
                  <td className="num">
                    {block.coinbase === null ? (
                      <span className="dim">none</span>
                    ) : (
                      formatQnr(block.coinbase.valuePlanck)
                    )}
                  </td>
                </>
              ) : (
                <>
                  <td className="num col--wide dim">-</td>
                  <td className="dim" title={block.stateError}>
                    state not kept
                  </td>
                  <td className="num col--wide dim">-</td>
                  <td className="num dim">-</td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
