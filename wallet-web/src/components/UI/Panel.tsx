import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A panel: one thing, with its name over it.
 *
 * MyMonero's screens are stacks of these, and one screen is one job. The
 * measure is on the panel rather than on the paragraph, because a `ch` cap on
 * a paragraph tracks that paragraph's own font size and an 11 px note would
 * then stop at half the width of the 13 px text above it.
 */
export function Panel({
  title,
  children,
  className,
  flush = false,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}): ReactNode {
  return (
    <section
      className={cn(
        'elev-raised rounded-panel border border-edge bg-panel',
        flush ? 'py-4' : 'p-4',
        className,
      )}
    >
      {title !== undefined && (
        <h2
          className={cn(
            'mb-3 text-label uppercase tracking-label text-muted',
            flush && 'px-4',
          )}
        >
          {title}
        </h2>
      )}
      {children}
    </section>
  );
}

/** Prose inside a panel, capped at the reading measure. */
export function Prose({ children }: { children: ReactNode }): ReactNode {
  return (
    <div className="prose max-w-[var(--measure)] space-y-2 text-body text-ink-2">{children}</div>
  );
}
