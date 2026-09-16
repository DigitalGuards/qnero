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

/**
 * The masthead: the wordmark, and the one live fact this surface has.
 *
 * It replaces a 155 px stack of a wrapping status strip over a three-line
 * wordmark. The strip carried five things at once, among them a raw WebSocket
 * URL as the second most prominent string on every page, and it printed the
 * chain's name 75 px above the heading that printed it again.
 *
 * So the name is printed once per screen. The chain page's `h1` is the chain,
 * and on every other page the chain is here beside the height. The endpoint
 * left the header for the No connection page and the foot of the chain page,
 * which are the two places it answers a question.
 */
function Masthead({ current }: { current: Route['name'] }): ReactNode {
  const { status, chainName, head } = useChain();
  const live = status === 'live' || status === 'offline';
  const modifier =
    status === 'failed'
      ? ' masthead__status--down'
      : status === 'offline'
        ? ' masthead__status--warn'
        : '';
  const dot =
    status === 'live'
      ? 'dot dot--live'
      : status === 'connecting'
        ? 'dot'
        : status === 'offline'
          ? 'dot dot--warn'
          : 'dot dot--down';
  // The chain page's heading is the chain's name, so the slot beside it holds
  // the height alone.
  const named = current !== 'home' && chainName !== null;
  return (
    <header className="masthead">
      <a className="masthead__brand" href={href({ name: 'home' })}>
        silQ Road
      </a>
      <span className={`masthead__status${modifier}`} role="status">
        <span className={dot} aria-hidden="true" />
        {status === 'connecting' ? <span>Reading the chain head</span> : null}
        {status === 'failed' ? <span>connection failed</span> : null}
        {live && status === 'offline' ? <span>no node</span> : null}
        {live && named ? <span className="masthead__chain">{chainName}</span> : null}
        {live && named && head !== null ? (
          <span className="masthead__sep" aria-hidden="true">
            &middot;
          </span>
        ) : null}
        {live && head !== null ? (
          <span className="num">block {formatCount(head.header.number)}</span>
        ) : null}
      </span>
    </header>
  );
}

export function Layout({ current, children }: { current: Route['name']; children: ReactNode }): ReactNode {
  const { status } = useChain();
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
      <Masthead current={current} />
      <nav className="nav" aria-label="Sections">
        {NAV.map((item) => (
          <a
            key={item.label}
            className="nav__link"
            href={href(item.route)}
            aria-current={item.match.includes(current) ? 'page' : undefined}
          >
            {item.label}
          </a>
        ))}
        <ThemeToggle />
      </nav>
      {/* Two pixels of movement while the socket is opening, and nothing once
          it has. It is the one thing on a screen with no figures on it yet that
          says the page is working; under reduced motion it is a static rule. */}
      {status === 'connecting' ? <div className="indeterminate" aria-hidden="true" /> : null}
      <main className="main" id="main" tabIndex={-1}>
        <div className="main__inner">{children}</div>
      </main>
    </>
  );
}
