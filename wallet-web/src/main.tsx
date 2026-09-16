import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router';

import './styles/app.css';
import { applyTheme, readTheme } from './app/theme';
import { TooltipProvider } from './components/UI/Tooltip';
import { App } from './App';

/*
 * The stored theme, before the first paint.
 *
 * `script-src 'self'` forbids the inline tag the site uses for this, and it is
 * not needed: `#root` is empty until this bundle runs, so the attribute is on
 * the root element before React renders anything and no flash results. Without
 * it only the settings screen applied the choice, so a reader who chose light
 * on a dark-system phone got the dark wallet on every open.
 */
applyTheme(readTheme());

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
