import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import type { ButtonHTMLAttributes, ReactNode } from 'react';

import { cn } from '../../utils/cn';

/**
 * The action button, in MyMonero's three colours. See `NOTICE`.
 *
 * Three variants and they are not decoration. `action` is the one thing a
 * screen is for and there is at most one per screen; `utility` is everything
 * else; `destructive` is a button that destroys something this browser holds
 * the only copy of. The geometry is that wallet's: 3 px radius, 13 px semibold
 * for the action and 12 px with half a pixel of tracking for the utility, with
 * the two-part elevation on the raised ones. The height comes from the tokens,
 * which is 32 px where a pointer is and 40 px in a hand, 44 for the action.
 *
 * A disabled button keeps its opacity. Fading one to half takes its label to
 * about 2:1 and says "this is broken" where the true answer is "not yet": what
 * a disabled control owes a reader is the raised ground, the muted label, and
 * a line nearby that says why.
 *
 * Built the way the sibling web wallet builds its buttons: `cva` for the
 * variants and `@radix-ui/react-slot` so `asChild` can hand the styling to a
 * router link without nesting an anchor inside a button.
 */
const buttonVariants = cva(
  'inline-flex min-h-[var(--control-h)] select-none items-center justify-center gap-2 ' +
    'rounded-control transition-colors disabled:pointer-events-none',
  {
    variants: {
      variant: {
        utility:
          'elev-raised bg-raised text-ink text-ui tracking-label hover:bg-hover ' +
          'disabled:bg-raised disabled:text-muted',
        action:
          'min-h-[var(--primary-h)] bg-accent-fill text-on-accent text-body font-semibold ' +
          'hover:bg-accent-hover shadow-[inset_0_0.5px_0_0_rgba(255,255,255,0.2)] ' +
          'disabled:bg-raised disabled:text-muted disabled:shadow-none',
        destructive:
          'min-h-[var(--primary-h)] bg-destructive-fill text-on-destructive text-body ' +
          'font-semibold shadow-[inset_0_0.5px_0_0_rgba(255,255,255,0.2)] hover:opacity-90 ' +
          'disabled:bg-raised disabled:text-muted disabled:shadow-none',
        quiet: 'min-h-0 text-muted text-meta hover:text-ink underline underline-offset-2',
      },
      size: {
        default: 'px-4',
        small: 'min-h-0 h-6 px-2 text-meta',
        block: 'w-full px-4',
      },
    },
    defaultVariants: { variant: 'utility', size: 'default' },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
  children: ReactNode;
}

export function Button({
  className,
  variant,
  size,
  asChild = false,
  type = 'button',
  ...props
}: ButtonProps): ReactNode {
  const Component = asChild ? Slot : 'button';
  return (
    <Component
      // `asChild` hands the type to whatever it renders, and an anchor has no
      // `type`, so it is only set on a real button.
      {...(asChild ? {} : { type })}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}

export { buttonVariants };
