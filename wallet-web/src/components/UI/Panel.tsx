import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A panel: one thing, with its name over it.
 *
 * Panels share a reading measure and comfortable gutters across screen sizes.
 * Flush content keeps its own horizontal gutters for tables and lists.
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
        flush ? 'py-5 sm:py-6' : 'p-5 sm:p-6',
        className,
      )}
    >
      {title !== undefined && (
        <h2
          className={cn(
            'mb-4 text-label uppercase tracking-label text-muted',
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
