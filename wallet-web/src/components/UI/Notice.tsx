import { AlertTriangle, Info } from 'lucide-react';
import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A claim the wallet is making, set apart from the reading it is about.
 *
 * The box is MyMonero's (see `NOTICE`) and it is used for the same thing:
 * something true about this wallet that is not an error and does not stop
 * anything. `tone="error"` is a refusal, and it is the only one that carries
 * `role="alert"`.
 *
 * What is not carried is that wallet's yellow. Its action is cyan, so a yellow
 * notice sits 141 degrees away from it; Qnero's accent is amber, and a yellow
 * notice beside an amber button is one warm block. So the notice is a strong
 * border, the secondary ink and the icon, and the saturated warm thing on any
 * screen is the one action that screen is for. See `styles/tokens.css`.
 *
 * `sensitive` marks a notice whose text came from the prover module rather
 * than from this wallet. The module's own errors are forwarded as they are,
 * and a plonky2 witness failure can name a note's amount or its position in
 * the tree, so the mark is there for a screenshot pass and a bug-report
 * template to key on: what is inside is for the wallet's owner.
 */
export function Notice({
  children,
  tone = 'notice',
  className,
  testId,
  sensitive = false,
}: {
  children: ReactNode;
  tone?: 'notice' | 'error';
  className?: string;
  testId?: string;
  sensitive?: boolean;
}): ReactNode {
  const Icon = tone === 'error' ? AlertTriangle : Info;
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      data-testid={testId}
      data-sensitive={sensitive ? 'may name an amount' : undefined}
      className={cn(
        'flex gap-2 rounded-panel border p-2 text-meta',
        // `bg-notice-bg` is `transparent` in both themes. The token is kept so
        // the role still has one place to change; the fill is what was dropped.
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
