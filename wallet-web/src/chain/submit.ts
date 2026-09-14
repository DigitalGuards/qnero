/**
 * Submitting a settlement, and watching for it to land.
 *
 * `submit_private_batch(proof, outputs)` is an unsigned extrinsic: no
 * signature, no nonce, no tip, admitted by `ValidateUnsigned` and free.
 *
 * It is hand-encoded here, as the CLI hand-encodes it
 * (`crates/qnero-wallet/src/extrinsic.rs`), and the reason is not that the
 * browser lacks a codec. `api.tx.shielded.submitPrivateBatch(...)` builds a
 * `SubmittableExtrinsic`, and constructing one instantiates `ExtrinsicV4`,
 * which resolves this runtime's signature type: `DilithiumSignatureScheme`,
 * carrying a fixed `[u8; 7219]`. polkadot-js refuses any fixed array above
 * 2048 bytes, so the typed constructor throws before the call is encoded at
 * all, on an extrinsic that will never carry a signature. The explorer hits
 * the same wall reading block bodies and walks the envelope by hand for the
 * same reason.
 *
 * What still comes from metadata is everything that identifies the call: the
 * pallet index and the call index, read off `.callIndex`, which is a property
 * of the submittable function rather than of an instance, so reading it builds
 * nothing. Nothing about the layout is compiled in.
 *
 * The guards the CLI carries stay, because none of them is what a codec
 * checks: the pallet and call have to exist, the runtime's declared extrinsic
 * format version has to be one a bare preamble decodes at, and the storage
 * layout has to match. A wallet that skipped them would build a proof and then
 * learn the node cannot read the envelope around it.
 */

import { bytesToHex } from '../lib/hex';
import { concatBytes, encodeCompact } from '../lib/scale';
import { blockExtrinsics, confirmNullifiersSettled, fetchHead } from './reads';
import { ensureBarePreambleDecodes, type ChainContext } from './api';

/**
 * `sp_runtime`'s bare preamble: format version 4, unsigned. Versions 4 and 5
 * both decode a bare extrinsic and 4 is the one every runtime in this lineage
 * accepts. `ensureBarePreambleDecodes` checks the runtime agrees before any of
 * this is built.
 */
const BARE_PREAMBLE = 0x04;

/** A SCALE `Vec<u8>`: a compact length, then the bytes. */
function encodeBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes([encodeCompact(bytes.length), bytes]);
}

/**
 * The wire bytes of one settlement.
 *
 * Returned rather than sent, so the caller holds the exact bytes it has to
 * find in a block: an extrinsic that is *in* a block is not a settled one, and
 * the only way to tell which one landed is to match it byte for byte.
 */
export function encodeSettlement(
  context: ChainContext,
  proof: Uint8Array,
  outputs: readonly { ct1: Uint8Array; ct2: Uint8Array }[],
): string {
  ensureBarePreambleDecodes(context);
  const shielded = context.api.tx['shielded'];
  if (shielded === undefined) {
    throw new Error('this runtime has no Shielded pallet, so it cannot settle a private batch');
  }
  const call = shielded['submitPrivateBatch'];
  if (call === undefined) {
    throw new Error('the Shielded pallet declares no submit_private_batch call');
  }
  const callIndex = call.callIndex;
  if (callIndex.length !== 2) {
    throw new Error('this runtime indexes calls with something other than two bytes');
  }

  const body = concatBytes([
    // The bare preamble: format version 4, unsigned.
    new Uint8Array([BARE_PREAMBLE]),
    callIndex,
    encodeBytes(proof),
    encodeCompact(outputs.length),
    // `BoundedVec<u8, MaxCiphertextBytes>` encodes exactly as a `Vec<u8>`, and
    // a struct of two of them encodes as the two in order. Overrunning the
    // bound fails the node's decode, which is why the size check happens
    // before proving rather than here.
    ...outputs.flatMap((output) => [encodeBytes(output.ct1), encodeBytes(output.ct2)]),
  ]);
  // `bytesToHex` carries the `0x` an RPC parameter needs.
  return bytesToHex(concatBytes([encodeCompact(body.length), body]));
}

/** Hand the bytes to the pool. The answer is the extrinsic hash. */
export async function submitSettlement(context: ChainContext, encoded: string): Promise<string> {
  return context.send<string>('author_submitExtrinsic', [encoded]);
}

export interface Inclusion {
  blockNumber: number;
  blockHash: string;
  /** Whether both nullifiers are in `UsedNullifiers` at the inclusion block. */
  settled: boolean;
}

/**
 * Wait for the exact submitted bytes to appear in a block, then check that the
 * settlement actually settled.
 *
 * Two separate questions. An extrinsic in a block is not a settled one: a
 * segment whose anchor went stale or whose nullifier was claimed elsewhere is
 * **skipped** and the block carries it anyway. So inclusion is matched on the
 * bytes, and settlement is checked by asking whether both nullifiers are in
 * the set at that block. Those two nullifiers are public the moment the proof
 * is in a block, which is what makes the point lookup acceptable here and
 * nowhere else.
 *
 * An unsigned settlement has `longevity(5)` and constant priority, so a
 * byte-identical rebroadcast will not displace the copy already in the pool.
 * On a timeout the answer is to prove again against a fresh anchor, and the
 * caller says so rather than offering a retry that resends these bytes.
 */
export async function waitForInclusion(
  context: ChainContext,
  encoded: string,
  nullifiers: readonly string[],
  options: { timeoutMs: number; pollMs?: number; onBlock?: (height: number) => void },
): Promise<Inclusion | null> {
  const deadline = Date.now() + options.timeoutMs;
  const pollMs = options.pollMs ?? 2000;
  let checked = -1;
  while (Date.now() < deadline) {
    const head = await fetchHead(context);
    for (let height = checked < 0 ? head.number : checked + 1; height <= head.number; height += 1) {
      const hash = await context.send<string | null>('chain_getBlockHash', [height]);
      if (hash === null) {
        continue;
      }
      options.onBlock?.(height);
      const extrinsics = await blockExtrinsics(context, hash);
      if (!extrinsics.includes(encoded)) {
        continue;
      }
      const settled = await confirmNullifiersSettled(context, nullifiers, hash);
      return { blockNumber: height, blockHash: hash, settled: settled.every(Boolean) };
    }
    checked = head.number;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return null;
}
