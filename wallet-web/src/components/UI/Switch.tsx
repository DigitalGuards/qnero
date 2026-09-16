import * as SwitchPrimitive from '@radix-ui/react-switch';
import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A switch, for a setting that takes effect the moment it is flipped.
 *
 * Radix's primitive carries the role and the keyboard behaviour; what is here
 * is MyMonero's geometry and the accent.
 *
 * `testId` is a named prop rather than a spread `data-testid`, because JSX
 * skips type checking for hyphenated attribute names: a caller writing
 * `data-testid` on a component that destructures a fixed prop list compiles,
 * renders nothing, and the hook it advertised is missing with no error
 * anywhere. This is the same shape `Notice` and `Table` use.
 */
export function Switch({
  checked,
  onCheckedChange,
  id,
  disabled = false,
  className,
  testId,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  id?: string;
  disabled?: boolean;
  className?: string;
  testId?: string;
}): ReactNode {
  return (
    <SwitchPrimitive.Root
      id={id}
      data-testid={testId}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      className={cn(
        // The switch is 16 x 28 and the target around it is 44 px tall in a
        // hand: `before` is the hit area, the track is what is drawn.
        // The track does not animate its colour: see `UI/Button.tsx`. The
        // thumb's travel is one of the three motions this surface keeps, and
        // it is the one that says the switch was thrown.
        'elev-inset relative h-4 w-7 shrink-0 rounded-full border border-edge',
        'before:absolute before:-inset-y-3.5 before:-inset-x-2 before:content-[""]',
        'sm:before:hidden',
        checked ? 'bg-accent-fill' : 'bg-field',
        disabled && 'opacity-50',
        className,
      )}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          'block size-3 rounded-full bg-panel motion-safe:transition-transform',
          checked ? 'translate-x-3.5' : 'translate-x-0.5',
        )}
      />
    </SwitchPrimitive.Root>
  );
}
