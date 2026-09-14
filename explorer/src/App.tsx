import type { ReactNode } from 'react';

import { useRoute } from './app/router';
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

export function App(): ReactNode {
  const route = useRoute();
  return <Layout current={route.name}>{view(route)}</Layout>;
}
