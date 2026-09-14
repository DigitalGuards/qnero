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
 *
 * The two nullifiers and the two commitments of one slot are published
 * together and the page says so. What the chain hides is which note each
 * nullifier spent, and that is the only thing the note under them claims.
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
              <span className="field__label">Nullifiers spent</span>
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
              <span className="field__note">
                Membership proves some note was spent and says nothing about which note it was:
                nothing on chain joins a nullifier to the leaf it spent. The two leaves beside it
                are the outputs this spend created, and the chain publishes that link.
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
