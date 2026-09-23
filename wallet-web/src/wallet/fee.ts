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
 * Every constant comes from the runtime's own metadata, and each one is held
 * inside a compiled-in bound before it prices anything. The value is the
 * runtime's because the runtime moved `CiphertextBytesPerFeeQuantum` inside
 * one `spec_version` during M4, and a wallet holding a copy would have been
 * wrong with nothing on chain to catch it. The bound is compiled in because
 * metadata carries no proof: see `ensureFeeConstantsAreSane`.
 *
 * This mirrors `crates/qnero-wallet/src/fee.rs` rule for rule.
 */

import { formatStepsAsQnr } from '../lib/units';
import type { ShieldedConstants } from '../chain/api';

/**
 * The widest `MinLeafFee` this wallet will price a spend against, in pool
 * steps.
 *
 * The chain declares 1 (`chain/runtime/src/configs/mod.rs`), so this leaves a
 * runtime upgrade sixty-four times the room it uses today.
 */
export const MAX_TRUSTED_MIN_LEAF_FEE = 64n;

/**
 * The narrowest `CiphertextBytesPerFeeQuantum` this wallet will price a spend
 * against, in bytes.
 *
 * The chain declares 512, so this leaves an upgrade room to make a byte of
 * payload eight times dearer.
 */
export const MIN_TRUSTED_BYTES_PER_FEE_QUANTUM = 64;

/** The widest fee this wallet pays for one slot, in pool steps. */
export const MAX_TRUSTED_SLOT_FEE = 256n;

/**
 * A fee at or under this is paid whatever the amount is, in pool steps.
 *
 * An honest slot costs 8, and a payment may legitimately be smaller than a few
 * times that. Below the allowance there is nothing worth stopping a spend
 * over.
 */
export const HIGH_FEE_ALLOWANCE = 16n;

/** Above the allowance, a fee may take at most this share of the amount. */
export const HIGH_FEE_AMOUNT_SHARE = 2n;

/**
 * The bounds this wallet holds a runtime's fee constants inside.
 *
 * `MinLeafFee` and `CiphertextBytesPerFeeQuantum` arrive in runtime metadata,
 * which is the node's own word: no state root covers it, so a node answers
 * what it likes. Those two decide the floor, this wallet sends no `fee` field,
 * and the chain credits an overpayment to the block author. A node that
 * multiplied either constant by a thousand would be paid a thousandfold with
 * nothing on screen to compare the figure against.
 *
 * The chain's real values price an honest settlement slot at 8 steps, and the
 * bounds above are wide multiples of each term, so a fee change the chain
 * makes on purpose is still taken and a fee change a node invents is refused
 * by name. A runtime that wanted more than these would ship with a wallet that
 * carries the new bound.
 *
 * `crates/qnero-wallet/src/fee.rs` holds the same three numbers.
 */
export function ensureFeeConstantsAreSane(constants: ShieldedConstants): void {
  if (constants.minLeafFee > MAX_TRUSTED_MIN_LEAF_FEE) {
    throw new Error(
      `this node declares MinLeafFee as ${constants.minLeafFee.toString()} pool steps and this ` +
        `wallet pays at most ${MAX_TRUSTED_MIN_LEAF_FEE.toString()}. Runtime metadata is the ` +
        "node's own word, no state root covers it, and the chain pays an overpaid fee to " +
        'the block author. Nothing has been built and nothing has been submitted.',
    );
  }
  if (constants.ciphertextBytesPerFeeQuantum < MIN_TRUSTED_BYTES_PER_FEE_QUANTUM) {
    throw new Error(
      `this node declares CiphertextBytesPerFeeQuantum as ` +
        `${String(constants.ciphertextBytesPerFeeQuantum)} bytes and this wallet prices a spend ` +
        `against at least ${String(MIN_TRUSTED_BYTES_PER_FEE_QUANTUM)}. The divisor is what a ` +
        'step of fee buys, so a small one is a large fee, and runtime metadata is the ' +
        "node's own word. Nothing has been built and nothing has been submitted.",
    );
  }
}

/** The fee this spend would pay, against the absolute per-slot ceiling. */
export function ensureFeeWithinCeiling(fee: bigint): void {
  if (fee > MAX_TRUSTED_SLOT_FEE) {
    throw new Error(
      `this spend would pay ${formatStepsAsQnr(fee)} for one slot and this wallet pays at most ` +
        `${formatStepsAsQnr(MAX_TRUSTED_SLOT_FEE)}. The fee comes from constants the node ` +
        'declares and the chain credits an overpayment to the block author. Nothing has been ' +
        'built and nothing has been submitted.',
    );
  }
}

/**
 * The fee against the amount it is charged on.
 *
 * The ceiling above bounds what a hostile node can take per spend; this bounds
 * what it can take out of a small payment. The allowance is what keeps an
 * honest floor from stopping a genuinely small one.
 */
export function feeOutrunsAmount(fee: bigint, amount: bigint): boolean {
  return fee > HIGH_FEE_ALLOWANCE && fee * HIGH_FEE_AMOUNT_SHARE > amount;
}

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

