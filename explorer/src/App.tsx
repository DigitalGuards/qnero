import type { ReactNode } from 'react';

import { useChain } from './app/chainContext';
import { href, useRoute } from './app/router';
import { ErrorBox } from './components/ui';
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
 * nothing to show. It says which endpoint did not answer and where that
 * endpoint is set, which is the answer in almost every case.
 */
function NoConnection({ endpoint, error }: { endpoint: string | null; error: string | null }): ReactNode {
  return (
    <>
      <header className="page__head">
        <h1>No connection</h1>
        <p className="page__lede">
          This site reads one node live and keeps no index of its own, so it has nothing to show
          until that node answers.
        </p>
      </header>
      <ErrorBox>{error ?? 'the connection failed'}</ErrorBox>
      {endpoint === null ? null : (
        <p>
          The endpoint is <span className="mono">{endpoint}</span>, set in{' '}
          <span className="mono">config.json</span> beside these assets and read at startup.
        </p>
      )}
      <p>
        <a href={href({ name: 'reveals' })}>What this chain reveals</a> needs no connection.
      </p>
    </>
  );
}

export function App(): ReactNode {
  const route = useRoute();
  const { status, endpoint, error } = useChain();
  // The reveals page is prose and reads nothing, so a dead node does not take
  // it down with the rest.
  const needsChain = route.name !== 'reveals' && route.name !== 'notFound';
  return (
    <Layout current={route.name}>
      {status === 'failed' && needsChain ? (
        <NoConnection endpoint={endpoint} error={error} />
      ) : (
        view(route)
      )}
    </Layout>
  );
}
