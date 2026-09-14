import type { ReactNode } from 'react';

import { href } from '../../app/router';
import type { BlockSummary } from '../../chain/blocks';
import { formatCount, formatQnr } from '../../lib/units';
import { Hash } from '../../components/ui';

function age(timestampMs: number | null): ReactNode {
  if (timestampMs === null || timestampMs === 0) {
    return <span className="dim">unread</span>;
  }
  const seconds = Math.max(0, Math.round((Date.now() - timestampMs) / 1000));
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)}m ago`;
  }
  return `${Math.round(seconds / 3600)}h ago`;
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
 * an unread block and an empty block are not the same block.
 */
export function RecentBlocks({ blocks }: { blocks: readonly BlockSummary[] }): ReactNode {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Height</th>
            <th scope="col">Age</th>
            <th scope="col">Author label</th>
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
              <td className="num">
                <a href={href({ name: 'block', id: block.hash })}>
                  {formatCount(block.header.number)}
                </a>
              </td>
              <td className="num">{age(block.timestampMs)}</td>
              <td>
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
                <td className="dim" colSpan={4} title={block.stateError}>
                  state not kept at this block
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
