import type { ReactNode } from 'react';

import { href } from '../../app/router';
import type { BlockSummary } from '../../chain/blocks';
import { formatCount, formatQnr } from '../../lib/units';
import { Hash } from '../../components/ui';

function age(timestampMs: number): string {
  const seconds = Math.max(0, Math.round((Date.now() - timestampMs) / 1000));
  if (seconds < 60) {
    return `${seconds}s ago`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)}m ago`;
  }
  return `${Math.round(seconds / 3600)}h ago`;
}

export function RecentBlocks({ blocks }: { blocks: readonly BlockSummary[] }): ReactNode {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Height</th>
            <th scope="col">Age</th>
            <th scope="col">Author label</th>
            <th scope="col">Leaves</th>
            <th scope="col">Settlements</th>
            <th scope="col">Entries</th>
            <th scope="col">Coinbase</th>
          </tr>
        </thead>
        <tbody>
          {blocks.map((block) => (
            <tr key={block.hash}>
              <td className="num">
                <a href={href({ name: 'block', id: String(block.header.number) })}>
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
              <td className="num">{formatCount(block.leavesAdded.length)}</td>
              <td className="num">{formatCount(block.settlements.length)}</td>
              <td className="num">{formatCount(block.entries.length)}</td>
              <td className="num">
                {block.coinbase === null ? (
                  <span className="dim">none</span>
                ) : (
                  formatQnr(block.coinbase.valuePlanck)
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
