import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router';

import './styles/app.css';
import { TooltipProvider } from './components/UI/Tooltip';
import { App } from './App';

/**
 * `HashRouter`, so a built directory works dropped on any static host at any
 * path under it. A path router needs the host to rewrite every unknown path to
 * `index.html`, and a host that does not is a wallet that works until somebody
 * reloads the send screen.
 */
const root = document.getElementById('root');
if (root === null) {
  throw new Error('the page carries no #root to mount into');
}

createRoot(root).render(
  <StrictMode>
    <HashRouter>
      <TooltipProvider delayDuration={200}>
        <App />
      </TooltipProvider>
    </HashRouter>
  </StrictMode>,
);
