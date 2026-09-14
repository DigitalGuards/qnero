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
  const { status, endpoint, head, error } = useChain();
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
      {/* The endpoint is held from the moment config.json is read, so the
          address that is failing to answer is on screen while it fails. */}
      {endpoint === null ? null : <span className="mono">{endpoint}</span>}
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
      {/* The fragment belongs to the router, so following this as a link would
          navigate to "main" and render the not-a-page view. It moves focus
          itself, and main takes focus because an anchor target does not. */}
      <a
        className="skip-link"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main')?.focus();
        }}
      >
        Skip to content
      </a>
      <StatusStrip />
      <div className="frame">
        <nav className="rail" aria-label="Sections">
          {/* The wordmark, in the rail's own type: the name at the UI size
              in the mono face, the chain it is pointed at under it at label
              size. "silQ Road, the Qnero explorer" is the full form and it is
              set where a subtitle has room: the tab title, the readme and the
              docs. Under the name here is the chain, which is the thing a
              reader of a page needs to know first. */}
          <a className="rail__brand" href={href({ name: 'home' })}>
            silQ Road
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
        <main className="main" id="main" tabIndex={-1}>
          <div className="main__inner">{children}</div>
        </main>
      </div>
    </>
  );
}
