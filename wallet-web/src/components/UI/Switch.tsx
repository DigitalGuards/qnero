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
        'elev-inset relative h-4 w-7 shrink-0 rounded-full border border-edge transition-colors',
        checked ? 'bg-accent-fill' : 'bg-field',
        disabled && 'opacity-50',
        className,
      )}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          'block size-3 rounded-full bg-panel transition-transform',
          checked ? 'translate-x-3.5' : 'translate-x-0.5',
        )}
      />
    </SwitchPrimitive.Root>
  );
}
