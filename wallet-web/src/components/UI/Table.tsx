import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A table that scrolls sideways inside its panel rather than widening the
 * page, with an edge shadow while a column is off screen.
 *
 * The shadow is not decoration. At 400 px the notes table ends at STATE and
 * the memo column is off screen with nothing to say so, and an overlay
 * scrollbar stays invisible until it is dragged, so a phone reader has no way
 * to know the column is there. `.mm-scroll-x` in `styles/app.css` is the
 * explorer's recipe for exactly this, and it spends the `--shadow-edge` pair
 * the token file already defines.
 *
 * The hover rule is the one from the explorer's stylesheet: a hovered row
 * lifts its muted cells to the primary ink rather than inverting the ramp,
 * which keeps every cell above 4.5:1 in both themes instead of trading one
 * contrast problem for another.
 *
 * The cell inset is 16 px, which is `Panel`'s own and the empty state's.
 * Inside a flush panel the three have to agree, or the left edge of a list
 * moves by four pixels the moment the list stops being empty.
 */
export function TableScroll({ children }: { children: ReactNode }): ReactNode {
  return <div className="mm-scroll-x w-full">{children}</div>;
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
      className="w-full border-collapse text-meta [&_td]:px-4 [&_td]:py-1.5 [&_th]:px-4 [&_th]:py-1.5
        [&_tbody_tr:hover_td]:text-ink [&_tbody_tr:hover]:bg-hover
        [&_th]:text-left [&_th]:text-label [&_th]:uppercase [&_th]:tracking-label [&_th]:text-muted
        [&_tbody_tr]:border-t [&_tbody_tr]:border-edge"
    >
      {children}
    </table>
  );
}

/**
 * A right-aligned numeric cell, tabular so columns of digits line up.
 *
 * It never wraps. The memo column takes every pixel of slack (`w-full`), so
 * each amount cell collapses to the width of its own header, and an amount is
 * "10.00 QNR" now rather than a bare count: without the rule the cell breaks
 * at the space and renders the symbol on a second line under the digits,
 * which is the opposite of what a column of decimal points is for. `.num` in
 * the explorer's stylesheet carries the same rule for the same reason.
 */
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
    <td
      data-testid={testId}
      className={cn('text-right font-mono tabular-nums whitespace-nowrap', className)}
    >
      {children}
    </td>
  );
}
