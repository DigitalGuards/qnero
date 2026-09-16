import type { ReactNode } from 'react';

import { useChain } from './app/chainContext';
import { href, useRoute } from './app/router';
import { Why } from './components/ui';
import { Layout } from './components/Layout';
import { Block } from './pages/Block';
import { Blocks } from './pages/Blocks';
import { Home } from './pages/Home';
import { Reveals } from './pages/Reveals';
import { NotFound, Search } from './pages/Search';
import { Settlement } from './pages/Settlement';

function view(route: ReturnType<typeof useRoute>): ReactNode {
  switch (route.name) {
    case 'home':
      return <Home />;
    case 'blocks':
      return <Blocks before={route.before} />;
    case 'block':
      return <Block id={route.id} />;
    case 'settlement':
      return <Settlement hash={route.hash} at={route.at} />;
    case 'search':
      return <Search query={route.query} />;
    case 'reveals':
      return <Reveals />;
    case 'notFound':
      return <NotFound path={route.path} />;
  }
}

/**
 * What a page that cannot reach its node says.
 *
 * Every figure on this site is read live, so a route that needs the chain has
 * nothing to show. What it had instead was a dead end: the same sentence in the
 * status strip and again in a red box below it, the endpoint three times on one
 * screen, a deployment instruction shown to every visitor, and no button. A
 * phone that lost signal for fifteen seconds stayed here until its reader
 * worked out that a reload was the way back.
 *
 * One sentence, which names the endpoint once and is the node's own message.
 * One primary button. The retry runs on its own at 5, 15 and 60 seconds, and
 * the header counts it down.
 */
function NoConnection({ error, retry }: { error: string | null; retry: () => void }): ReactNode {
  return (
    <>
      <header className="page__head">
        <h1>No connection</h1>
      </header>
      <p>{error === null ? 'The node did not answer.' : capitalise(error)}</p>
      <p>
        <button className="button button--action" type="button" onClick={retry}>
          Try again
        </button>
      </p>
      <Why summary="Where the endpoint is set">
        <p>
          In <span className="mono">config.json</span> beside these assets, read at startup, so one
          build serves any chain. The README says what goes in it.
        </p>
      </Why>
      <p>
        <a href={href({ name: 'reveals' })}>What this chain reveals</a> needs no connection.
      </p>
    </>
  );
}

/**
 * A message the node wrote, rendered as a sentence.
 *
 * A message opening on an endpoint, a storage item or a runtime call is left
 * exactly as it was written: capitalising `ws://…` or `qPoW::CurrentDifficulty`
 * changes a value into something that is not the value.
 */
function capitalise(text: string): string {
  const [first = ''] = text.split(/\s/);
  if (!/^[a-z]/.test(text) || /[:/]/.test(first)) {
    return text;
  }
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function App(): ReactNode {
  const route = useRoute();
  const { status, error, retry } = useChain();
  // The reveals page is prose and reads nothing, so a dead node does not take
  // it down with the rest.
  const needsChain = route.name !== 'reveals' && route.name !== 'notFound';
  return (
    <Layout current={route.name}>
      {status === 'failed' && needsChain ? (
        <NoConnection error={error} retry={retry} />
      ) : (
        view(route)
      )}
    </Layout>
  );
}
