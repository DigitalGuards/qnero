import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A table that scrolls sideways inside its panel rather than widening the
 * page.
 *
 * The hover rule is the one from the explorer's stylesheet: a hovered row
 * lifts its muted cells to the primary ink rather than inverting the ramp,
 * which keeps every cell above 4.5:1 in both themes instead of trading one
 * contrast problem for another.
 */
export function TableScroll({ children }: { children: ReactNode }): ReactNode {
  return <div className="w-full overflow-x-auto">{children}</div>;
}

export function Table({
  children,
  testId,
}: {
  children: ReactNode;
  testId?: string;
}): ReactNode {
  return (
    <table
      data-testid={testId}
      className="w-full border-collapse text-meta [&_td]:px-3 [&_td]:py-1.5 [&_th]:px-3 [&_th]:py-1.5
        [&_tbody_tr:hover_td]:text-ink [&_tbody_tr:hover]:bg-hover
        [&_th]:text-left [&_th]:text-label [&_th]:uppercase [&_th]:tracking-label [&_th]:text-muted
        [&_tbody_tr]:border-t [&_tbody_tr]:border-edge"
    >
      {children}
    </table>
  );
}

/** A right-aligned numeric cell, tabular so columns of digits line up. */
export function Num({
  children,
  className,
  testId,
}: {
  children: ReactNode;
  className?: string;
  testId?: string;
}): ReactNode {
  return (
    <td data-testid={testId} className={cn('text-right font-mono tabular-nums', className)}>
      {children}
    </td>
  );
}
