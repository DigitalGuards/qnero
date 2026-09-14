import type { ReactNode } from 'react';

import { href } from '../../app/router';
import type { Settlement } from '../../lib/events';
import { formatBytes, formatCount, formatQnr, REFERENCE_CIPHERTEXT_BYTES } from '../../lib/units';
import { Field, Fields, Hash } from '../../components/ui';

function ciphertextNote(bytes: number): ReactNode {
  if (bytes === REFERENCE_CIPHERTEXT_BYTES) {
    return `${formatBytes(bytes)} of ciphertext`;
  }
  return `${formatBytes(bytes)} of ciphertext, which is not the ${formatCount(
    REFERENCE_CIPHERTEXT_BYTES,
  )} the reference wallet writes`;
}

/**
 * One settlement, in full.
 *
 * A slot's two outputs are rendered as an unordered pair. Which one is the
 * sender's change is hidden only because the wallet draws the payment's output
 * slot per spend, so labelling one "to" and one "change" here would reintroduce
 * by presentation exactly what the protocol pays to hide.
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
              <span className="field__label">Nullifiers spent</span>
              <div className="field__value">
                <Hash value={slot.nullifiers[0]} full />
              </div>
              <div className="field__value">
                <Hash value={slot.nullifiers[1]} full />
              </div>
              <span className="field__note">
                Membership proves some note was spent. Nothing on chain joins a nullifier to a leaf.
              </span>
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
