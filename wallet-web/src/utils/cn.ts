import { clsx, type ClassValue } from 'clsx';
import { extendTailwindMerge } from 'tailwind-merge';

/**
 * The merger, taught this project's type scale.
 *
 * `tailwind-merge` ships Tailwind's own class groups, and this app's type
 * scale is not Tailwind's: `text-display`, `text-body`, `text-ui`, `text-meta`
 * and `text-label` are the 32/13/12/11/10 px steps carried over from
 * MyMonero's web wallet (`styles/tokens.css`). The stock merger has no name
 * for them, so it filed every one of them under text colour and deleted it
 * whenever a colour class appeared later in the same call: `cn('text-meta',
 * 'text-ink')` returned `text-ink` alone, and six components rendered at the
 * inherited size while their sibling elements rendered at the declared one.
 * Two things in the same declared label style then sat three pixels apart.
 *
 * Teaching the merger the scale is what makes the two namespaces stop
 * colliding. The other half of that fix is in `styles/app.css`: a colour token
 * and a size token may not share a name, because `text-<name>` is one class
 * and Tailwind resolves it to whichever namespace claims the name.
 */
const merge = extendTailwindMerge({
  extend: {
    classGroups: {
      'font-size': [{ text: ['display', 'body', 'ui', 'meta', 'label'] }],
    },
  },
});

/**
 * Class names, merged the way the sibling web wallet merges them
 * (`myqrlwallet-frontend/src/utils/cn.ts`).
 *
 * The merge is what makes a `className` prop on a component able to override
 * the component's own utilities rather than sit beside them and lose to
 * whichever rule the stylesheet happens to order last.
 */
export function cn(...inputs: ClassValue[]): string {
  return merge(clsx(inputs));
}
