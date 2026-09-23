import type { ReactNode } from 'react';

import { APPS, appUrl } from '../lib/appLinks';

/** The footer row linking every Qnero app, with this one marked current. */
export function AppLinks(): ReactNode {
  const hostname = typeof location === 'undefined' ? '' : location.hostname;
  return (
    <nav aria-label="Qnero apps" className="flex flex-wrap gap-x-5 gap-y-2">
      {APPS.map((app) =>
        app.host === 'wallet' ? (
          <span key={app.label} aria-current="page" className="text-ink-2">
            {app.label}
          </span>
        ) : (
          <a
            key={app.label}
            href={appUrl(app.host, hostname)}
            className="text-muted no-underline hover:text-accent-hover hover:underline"
          >
            {app.label}
          </a>
        ),
      )}
    </nav>
  );
}
