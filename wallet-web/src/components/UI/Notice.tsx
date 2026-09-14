import { AlertTriangle, Info } from 'lucide-react';
import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A claim the wallet is making, set apart from the reading it is about.
 *
 * The yellow box is MyMonero's (see `NOTICE`), and it is used for the same
 * thing: something true about this wallet that is not an error and does not
 * stop anything. `tone="error"` is a refusal, and it is the only one that
 * carries `role="alert"`.
 */
export function Notice({
  children,
  tone = 'notice',
  className,
  testId,
}: {
  children: ReactNode;
  tone?: 'notice' | 'error';
  className?: string;
  testId?: string;
}): ReactNode {
  const Icon = tone === 'error' ? AlertTriangle : Info;
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      data-testid={testId}
      className={cn(
        'flex gap-2 rounded-panel border p-2 text-meta',
        tone === 'error'
          ? 'border-destructive/45 bg-destructive/8 text-destructive'
          : 'border-notice-edge bg-notice-bg text-notice',
        className,
      )}
    >
      <Icon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
      <div className="min-w-0 space-y-1">{children}</div>
    </div>
  );
}

/** An empty list, said as an empty list rather than drawn as a blank box. */
export function Empty({ children }: { children: ReactNode }): ReactNode {
  return <p className="px-4 text-meta text-muted">{children}</p>;
}

/**
 * A read that did not happen, said as a read that did not happen.
 *
 * An absence sentence is a claim about what the chain published, and over a
 * read that failed it is a false one, read by exactly the person checking
 * whether something happened.
 */
export function NotRead({ what }: { what: string }): ReactNode {
  return <span className="text-meta text-muted">{what} could not be read</span>;
}
