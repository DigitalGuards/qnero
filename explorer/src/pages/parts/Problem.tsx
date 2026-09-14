import type { ReactNode } from 'react';

import { href } from '../../app/router';
import { ErrorBox, Hash } from '../../components/ui';

function isHash(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

/**
 * A page opened by a value that the node could not answer for.
 *
 * A bare error box leaves a page with no heading, no statement of what was
 * asked and no way out, which is what a pasted hash, a genesis parent link and
 * a settlement whose block read failed all used to land on. The block page and
 * the settlement page are both opened by a value a reader typed or followed, so
 * they fail in one shape: the heading that says which kind of page this is, the
 * value it was opened by, the node's own message, and a link back.
 */
export function Problem({
  heading,
  value,
  children,
}: {
  heading: string;
  value: string;
  children: ReactNode;
}): ReactNode {
  return (
    <>
      <header className="page__head">
        <h1>{heading}</h1>
        <p className="page__lede">
          {isHash(value) ? <Hash value={value} full /> : <span className="mono">{value}</span>}
        </p>
      </header>
      <ErrorBox>{children}</ErrorBox>
      <p>
        <a href={href({ name: 'home' })}>Back to the chain</a>.
      </p>
    </>
  );
}
