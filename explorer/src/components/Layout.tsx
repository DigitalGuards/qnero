import type { ReactNode } from 'react';

import { href, type Route } from '../app/router';
import { useChain } from '../app/chainContext';
import { formatCount } from '../lib/units';
import { ThemeToggle } from './ThemeToggle';

const NAV: { label: string; route: Route; match: Route['name'][] }[] = [
  { label: 'Chain', route: { name: 'home' }, match: ['home'] },
  { label: 'Blocks', route: { name: 'blocks', before: null }, match: ['blocks', 'block'] },
  { label: 'Search', route: { name: 'search', query: '' }, match: ['search'] },
  { label: 'Reveals', route: { name: 'reveals' }, match: ['reveals'] },
];

function StatusStrip(): ReactNode {
  const { status, bundle, head, error } = useChain();
  const warn = status === 'offline' || status === 'failed';
  const dot =
    status === 'live' ? 'strip__dot strip__dot--live' : warn ? 'strip__dot strip__dot--down' : 'strip__dot';
  return (
    <div className={warn ? 'strip strip--warn' : 'strip'} role="status">
      <span className={dot} aria-hidden="true" />
      <span>
        {status === 'live'
          ? 'connected'
          : status === 'connecting'
            ? 'connecting'
            : status === 'offline'
              ? 'node unreachable, retrying'
              : 'connection failed'}
      </span>
      {bundle === null ? null : <span className="mono">{bundle.config.rpcEndpoint}</span>}
      {head === null ? null : <span>block {formatCount(head.header.number)}</span>}
      {error === null ? null : <span>{error}</span>}
      <span className="strip__spacer" />
      <ThemeToggle />
    </div>
  );
}

export function Layout({ current, children }: { current: Route['name']; children: ReactNode }): ReactNode {
  const { bundle } = useChain();
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <StatusStrip />
      <div className="frame">
        <nav className="rail" aria-label="Sections">
          <a className="rail__brand" href={href({ name: 'home' })}>
            Qnero
            <span className="rail__chain">{bundle?.config.chainName ?? 'explorer'}</span>
          </a>
          <div className="rail__nav">
            {NAV.map((item) => (
              <a
                key={item.label}
                className="rail__link"
                href={href(item.route)}
                aria-current={item.match.includes(current) ? 'page' : undefined}
              >
                {item.label}
              </a>
            ))}
          </div>
        </nav>
        <main className="main" id="main">
          <div className="main__inner">{children}</div>
        </main>
      </div>
    </>
  );
}
