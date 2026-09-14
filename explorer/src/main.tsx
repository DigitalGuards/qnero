import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import { ChainProvider } from './app/chainContext';
import './styles/app.css';

const root = document.getElementById('root');
if (root === null) {
  throw new Error('the page has no #root element');
}

createRoot(root).render(
  <StrictMode>
    <ChainProvider>
      <App />
    </ChainProvider>
  </StrictMode>,
);
