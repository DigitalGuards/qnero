import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import type { ReactNode } from 'react';

/**
 * A tooltip, for a word this wallet uses in a particular sense.
 *
 * It is never the only place something is said. A tooltip is unreachable on a
 * touch screen and easy to miss on any screen, so what is in one here is an
 * expansion of a term the surrounding sentence already carries.
 */
export const TooltipProvider = TooltipPrimitive.Provider;

export function Tooltip({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}): ReactNode {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          sideOffset={6}
          className="z-50 max-w-[280px] rounded-panel border border-edge bg-raised px-2 py-1
            text-meta text-ink shadow-[var(--shadow-float)]"
        >
          {label}
          <TooltipPrimitive.Arrow className="fill-[var(--bg-raised)]" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}
