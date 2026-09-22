import type { ReactNode } from 'react';

import { href } from '../../app/router';
import type { Settlement } from '../../lib/events';
import { formatBytes, formatCount, formatQnr, REFERENCE_CIPHERTEXT_BYTES } from '../../lib/units';
import { Field, Fields, Hash } from '../../components/ui';

/**
 * A settlement output's ciphertext size.
 *
 * The chain requires exactly `REFERENCE_CIPHERTEXT_BYTES` of every suite-1
 * ciphertext a settlement carries, so on a settlement leaf any other size is
 * unreachable rather than merely unusual. Saying so loudly is the point: a row
 * that reads this way means a settlement got past a consensus rule, which is a
 * node to report and not a wallet to identify.
 */
function ciphertextNote(bytes: number): ReactNode {
  if (bytes === REFERENCE_CIPHERTEXT_BYTES) {
    return `${formatBytes(bytes)} of ciphertext`;
  }
  return (
    `${formatBytes(bytes)} of ciphertext, which the chain does not settle: a settlement carries ` +
    `exactly ${formatCount(REFERENCE_CIPHERTEXT_BYTES)} bytes per output, so this is an ` +
    'invariant violation'
  );
}

/**
 * One settlement, in full.
 *
 * A slot's two outputs are rendered as an unordered pair. Which one is the
 * sender's change is hidden only because the wallet draws the payment's output
 * slot per spend, so labelling one "to" and one "change" here would reintroduce
 * by presentation exactly what the protocol pays to hide.
 *
 * The two nullifiers and the two commitments of one slot are published
 * together and the page says so, once, under the list of slots. A nullifier
 * marks one of the slot's two input positions consumed, and a position holding
 * a dummy input publishes a nullifier over no note, so the note claims a bound
 * on what a slot spent and nothing about which note each value stands for.
 */
export function SettlementView({
  settlement,
  blockHeight,
}: {
  settlement: Settlement;
  blockHeight: number;
}): ReactNode {
  return (
    <>
      <Fields>
        <Field label="Slots settled" value={<span className="num">{formatCount(settlement.slots.length)}</span>} />
        <Field
          label="Circuit segments"
          value={<span className="num">{formatCount(settlement.segments)}</span>}
          note="segments that settled; one the chain skipped is not counted, so this is not the submission's shape"
        />
        <Field label="Fee" value={<span className="num">{formatQnr(settlement.feePlanck)}</span>} />
        <Field
          label="To the block author"
          value={<span className="num">{formatQnr(settlement.authorFeePlanck)}</span>}
          note="carried in this block's coinbase note"
        />
      </Fields>
      {settlement.slots.map((slot, index) => (
        <div className="slot" key={slot.nullifiers[0]}>
          <div className="slot__title">Slot {index + 1}</div>
          <div className="pair">
            <div>
              <span className="field__label">Nullifiers settled</span>
              {/* Numbered rather than stacked: each of these wraps, so flush
                  against each other the two of them read as four lines of hex
                  and a reader cannot tell where the first one ends. */}
              <ol className="hashlist">
                {slot.nullifiers.map((nullifier) => (
                  <li className="field__value hashlist__item" key={nullifier}>
                    <Hash value={nullifier} full />
                  </li>
                ))}
              </ol>
            </div>
            <div>
              <span className="field__label">Commitments appended, unordered</span>
              {slot.outputs.map((output) => (
                <div key={output.leafIndex}>
                  <div className="field__value">
                    <Hash value={output.commitment} full />
                  </div>
                  <span className="field__note">
                    leaf {formatCount(output.leafIndex)} at block {formatCount(blockHeight)},{' '}
                    {ciphertextNote(output.ciphertextBytes)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}
      {/* Once, under the list, and one sentence long. It was rendered inside
          every slot first: a settlement with eight slots printed the same
          345-character paragraph eight times, 2,760 characters of it. Then it
          was that paragraph once, eight lines of it at 375 px on a page whose
          job is the data above it. The reasoning lives in Reveals, under
          "What a settled nullifier stands for", which the settlement page
          links under this panel and the masthead links from every page. */}
      <p className="field__note">
        A nullifier marks one input position consumed and names no note.
      </p>
    </>
  );
}

export function SettlementLink({
  txHash,
  blockHash,
  children,
}: {
  txHash: string;
  blockHash: string;
  children: ReactNode;
}): ReactNode {
  return <a href={href({ name: 'settlement', hash: txHash, at: blockHash })}>{children}</a>;
}
