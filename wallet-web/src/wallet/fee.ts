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
 * This mirrors `crates/qnero-wallet/src/fee.rs` rule for rule, including which
 * of the two bounds on the memo pad is a refusal and which is a warning.
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
 * The looser of the two bounds on the pad, and the only one that stops a
 * spend. A runtime that lowered `MaxCiphertextBytes` below a padded ciphertext
 * would fail every send, memoless ones included, and the only message an
 * operator saw would be about a size no memo of theirs controls.
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

/**
 * The memo pad against the runtime's divisor: a warning, printed once.
 *
 * The tighter of the two bounds. `CiphertextBytesPerFeeQuantum` is sized so an
 * honest pair and a pair padded to the cap land in different fee buckets; the
 * chain never parses these bytes and `Shielded::Ciphertexts` is never pruned,
 * so once the buckets merge a settler pads both outputs to the cap, writes the
 * extra permanent state and pays what an honest spend pays.
 *
 * It is not a refusal, and that is the whole point of this function. The
 * property is chain wide: a settler pads to the cap whatever this wallet does,
 * so refusing would stop every send this wallet makes and fix nothing. The
 * operator cannot change the divisor, and a wallet shrinking its own pad below
 * everyone else's would publish its own ciphertext length, which is the leak
 * the pad exists to close.
 */
export function memoPadSeparationWarning(
  constants: ShieldedConstants,
  paddedCiphertextBytes: number,
  memoBytes: number,
  fixedBytes: number,
): string | null {
  const cap = constants.maxCiphertextBytes;
  const sent = slotFeeFloor(constants, paddedCiphertextBytes, paddedCiphertextBytes);
  const capped = slotFeeFloor(constants, cap, cap);
  if (sent < capped) {
    return null;
  }
  const pad = largestSeparatingPad(constants, fixedBytes);
  const advice =
    pad === null
      ? `no pad restores it under this runtime: even an unpadded pair of ${fixedBytes} bytes ` +
        'each pays what a pair padded to the cap pays, so the divisor is what has to come down'
      : `a coordinated move of the memo pad down to ${pad} bytes would restore it, and every ` +
        'wallet on the chain has to make it together';
  return (
    "this runtime's payload fee prices nothing. This wallet pads every memo to " +
    `${memoBytes} bytes, so the pair of ciphertexts a spend publishes is ` +
    `${2 * paddedCiphertextBytes} bytes and pays ${sent} quanta of payload fee, and a pair ` +
    `padded to this runtime's cap of ${cap} bytes each pays ${capped}. A settler can pad both ` +
    `outputs to the cap and write ${2 * Math.max(0, cap - paddedCiphertextBytes)} bytes of ` +
    'permanent state per slot for what an honest spend pays. It is a property of the chain and ' +
    `not of this spend, so the spend goes ahead. This runtime charges one quantum per ` +
    `${constants.ciphertextBytesPerFeeQuantum} ciphertext bytes; ${advice}.`
  );
}

/**
 * The largest memo pad that keeps this wallet's pair a fee bucket below a pair
 * padded to the cap, or null when no pad does.
 *
 * A pair of `total` bytes pays `ceil(total / q)`. The cap's pair pays
 * `ceil(2 * cap / q)`, so the largest total strictly below that bucket is
 * `(ceil(2 * cap / q) - 1) * q`, and half of it less the fixed part of a
 * ciphertext is the pad. At 512 and 2048 that is 61, which is where the pad
 * comes from.
 */
export function largestSeparatingPad(
  constants: ShieldedConstants,
  fixedBytes: number,
): number | null {
  const quantum = bytesPerQuantum(constants);
  const cap = BigInt(constants.maxCiphertextBytes);
  const capBucket = divCeil(cap * 2n, quantum);
  if (capBucket === 0n) {
    return null;
  }
  const largestTotal = (capBucket - 1n) * quantum;
  const each = Number(largestTotal / 2n);
  const pad = each - fixedBytes;
  return pad < 0 ? null : pad;
}
