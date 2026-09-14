import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Class names, merged the way the sibling web wallet merges them
 * (`myqrlwallet-frontend/src/utils/cn.ts`).
 *
 * `twMerge` is what makes a `className` prop on a component able to override
 * the component's own utilities rather than sit beside them and lose to
 * whichever rule the stylesheet happens to order last.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
