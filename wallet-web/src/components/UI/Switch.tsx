import * as SwitchPrimitive from '@radix-ui/react-switch';
import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * A switch, for a setting that takes effect the moment it is flipped.
 *
 * Radix's primitive carries the role and the keyboard behaviour; what is here
 * is MyMonero's geometry and the accent.
 */
export function Switch({
  checked,
  onCheckedChange,
  id,
  disabled = false,
  className,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  id?: string;
  disabled?: boolean;
  className?: string;
}): ReactNode {
  return (
    <SwitchPrimitive.Root
      id={id}
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
