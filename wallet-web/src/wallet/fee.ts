/**
 * The fee floor, computed before the witness is built.
 *
 * The fee is a public input of the leaf proof, fixed at proving time and not
 * raisable afterwards. Both terms of the floor are known before proving,
 * because the ciphertext sizes are: a note ciphertext is a fixed
 * `CIPHERTEXT_FIXED_BYTES` plus a memo padded to `MEMO_BYTES`. So a wallet
 * owes the arithmetic first and proves second, or it pays for a 33-second
 * proof and reads `PayloadUnderpaid` off the pool.
 *
 * Every constant comes from the runtime's own metadata. None is compiled in:
 * the runtime moved `CiphertextBytesPerFeeQuantum` inside one `spec_version`
 * during M4, and a wallet holding a copy would have been wrong with nothing on
 * chain to catch it.
 *
 * This mirrors `crates/qnero-wallet/src/fee.rs` rule for rule.
 */

import type { ShieldedConstants } from '../chain/api';

/** The divisor, clamped the way the pallet clamps it. A zero would divide by zero. */
function bytesPerQuantum(constants: ShieldedConstants): bigint {
  return BigInt(Math.max(1, constants.ciphertextBytesPerFeeQuantum));
}

function divCeil(value: bigint, divisor: bigint): bigint {
  return (value + divisor - 1n) / divisor;
}

/** `MinLeafFee + ceil((len(ct_1) + len(ct_2)) / CiphertextBytesPerFeeQuantum)`. */
export function slotFeeFloor(
  constants: ShieldedConstants,
  ct1Length: number,
  ct2Length: number,
): bigint {
  const bytes = BigInt(ct1Length) + BigInt(ct2Length);
  return constants.minLeafFee + divCeil(bytes, bytesPerQuantum(constants));
}

/**
 * The whole-submission floor, over every real slot a submission carries.
 *
 * A wallet's own submission is one private batch with one real slot and no
 * skipped segment, so this equals the per-slot floor. It is written out
 * because it is the bound the pallet actually applies, and the two stop
 * agreeing the moment a submission carries more than one transfer.
 */
export function submissionFeeFloor(
  constants: ShieldedConstants,
  realSlots: bigint,
  carriedBytes: bigint,
): bigint {
  return constants.minLeafFee * realSlots + divCeil(carriedBytes, bytesPerQuantum(constants));
}

/**
 * A ciphertext over `MaxCiphertextBytes` fails the extrinsic's SCALE decode,
 * after the proof committing to those exact bytes exists. So the check happens
 * before proving.
 *
 * The message names the pad rather than the memo. Every memo is padded to one
 * size, so a ciphertext is a fixed length whatever the memo says and
 * shortening one moves nothing.
 */
export function ensureCiphertextFits(
  constants: ShieldedConstants,
  length: number,
  memoBytes: number,
  what: string,
): void {
  if (length > constants.maxCiphertextBytes) {
    throw new Error(
      `the ${what} ciphertext is ${length} bytes and this runtime caps one at ` +
        `${constants.maxCiphertextBytes}. Every memo is padded to ${memoBytes} bytes, so a ` +
        'ciphertext is a fixed size and shortening the memo will not move it: the pad is what ' +
        'has to come down, and every wallet on the chain has to move it together.',
    );
  }
}

/**
 * The memo pad against the runtime's cap: a refusal.
 *
 * The only bound on the pad that stops a spend, and now the only bound left. A
 * runtime that lowered `MaxCiphertextBytes` below a padded ciphertext would
 * fail every send, memoless ones included, and the only message an operator
 * saw would be about a size no memo of theirs controls.
 *
 * The pad used to be decided by a second, tighter bound as well: it had to
 * keep an honest pair a fee bucket below a pair padded to the cap, because the
 * chain did not parse these bytes and nothing held a submission to a real
 * ciphertext shape. Settlement now requires the exact length the declared
 * crypto suite fixes, so the padded pair is refused outright and the
 * separation priced a state nobody can reach. What holds the pad instead is
 * the protocol profile: it carries the length, and the wallet refuses a chain
 * whose profile is not the one it was built for.
 */
export function ensureMemoPadFits(
  constants: ShieldedConstants,
  paddedCiphertextBytes: number,
  memoBytes: number,
  fixedBytes: number,
): void {
  if (paddedCiphertextBytes > constants.maxCiphertextBytes) {
    throw new Error(
      `this wallet pads every memo to ${memoBytes} bytes, so each output ciphertext is ` +
        `${paddedCiphertextBytes} bytes, and this runtime caps one at ` +
        `${constants.maxCiphertextBytes}. The pad is what has to shrink, to at most ` +
        `${Math.max(0, constants.maxCiphertextBytes - fixedBytes)}, and every wallet on the ` +
        'chain has to agree on the size or the padding buys nothing.',
    );
  }
}

