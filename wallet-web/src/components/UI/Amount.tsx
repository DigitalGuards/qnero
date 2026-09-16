import type { ReactNode } from 'react';

import { formatStepsAsQnr, splitAmountForDisplay } from '../../lib/units';

/**
 * An amount at the display size, split so the padding can be dimmed.
 *
 * MyMonero's balance treatment (see `NOTICE`): 32 px at weight 100, with the
 * trailing pad zeros of a long amount receding so the significant digits read
 * at a glance. Amounts move in steps of 0.01 QNR, so a Qnero amount carries
 * exactly two significant decimals and in practice this renders at one weight,
 * which is what that wallet does for an amount with nothing to pad.
 *
 * Shared, because the balance and the sent screen are the same figure at the
 * same size: what a wallet holds, and what it just paid.
 */
export function Amount({
  steps,
  note,
  testId,
}: {
  steps: bigint;
  /** A word after the symbol, such as `sent`. */
  note?: string;
  testId?: string;
}): ReactNode {
  const { significant, pad } = splitAmountForDisplay(formatStepsAsQnr(steps).replace(' QNR', ''));
  return (
    <div className="mm-balance text-ink" data-testid={testId}>
      {significant}
      {pad !== '' && <span className="mm-balance-fraction">{pad}</span>}
      {/* A real space, because the margin is only an optical gap. Without it
          the element's text is "10.00QNR" to anything that reads it rather
          than looks at it: a screen reader, a copy-paste, the `balance-held`
          probe in the end-to-end suite. */}{' '}
      <span className="text-ui font-normal text-muted">
        QNR{note === undefined ? '' : ` ${note}`}
      </span>
    </div>
  );
}
