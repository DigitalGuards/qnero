/**
 * One payment, end to end.
 *
 * The order here is a set of rules rather than a convenience, and each step
 * names the failure it exists to prevent. `docs/WALLET.md` section G is the
 * authority and `crates/qnero-wallet/src/wallet.rs` is the implementation this
 * mirrors.
 *
 * 1. **The fee floor first**, measured from the ciphertexts the submission
 *    will actually carry. The fee is a public input fixed at proving time, so
 *    a low one costs a whole 33-second proof and comes back as
 *    `PayloadUnderpaid`.
 * 2. **The memo pad**, checked against both of the runtime's bounds. Over the
 *    cap is a refusal; a runtime whose divisor merged the two fee buckets is a
 *    warning and the spend goes ahead, because the operator cannot change the
 *    divisor and a wallet shrinking its own pad below everyone else's would
 *    publish its own ciphertext length.
 * 3. **Selection**, largest first, at most two, ties on the lowest leaf index
 *    so a retry proves the same leaf.
 * 4. **Build the circuits**, then take the anchor. Not the other way round:
 *    the anchor block is a public input, so anchoring before a twelve-second
 *    build would publish this machine's build time in the anchor-to-inclusion
 *    gap.
 * 5. **The anchor is the current head**, taken fresh per submission. An anchor
 *    at head minus k, or one cached across two spends, is a distinguisher
 *    inside the 256-block window marking both spends as one wallet's.
 * 6. **Check the rebuild before proving**: the rebuilt root against the
 *    header's `zkTreeRoot` first, because that is what makes a leaf index mean
 *    anything, then each leaf against its own commitment, then each path's
 *    recomputed root against the header.
 * 7. **Draw the payment's output slot.** The circuit derives each output's
 *    `rho` from its slot index, so either assignment proves and settles
 *    unchanged, and a fixed assignment would tell every chain reader which of
 *    a settlement's two leaves is the sender's change.
 * 8. **Prove, verify locally, write the change note, then submit.** The store
 *    is the only copy of the change note's `r`, and a tab reclaimed between
 *    the submit and the write has published a note nobody can open.
 */

import type { ChainContext } from '../chain/api';
import { anchorFromHeader, parseRawHeader, type Anchor } from '../chain/anchor';
import { fetchHead, fetchLeafHashes, fetchTreeShape, headerAt } from '../chain/reads';
import { encodeSettlement, submitSettlement, waitForInclusion } from '../chain/submit';
import type { ProverClient } from '../worker/client';
import type { ProverLimits } from '../worker/protocol';
import {
  ensureCiphertextFits,
  ensureMemoPadFits,
  memoPadSeparationWarning,
  slotFeeFloor,
} from './fee';
import type { NoteSecret, PendingNote, StoredNote } from './model';
import { selectNotes } from './select';
import type { WalletStore } from './store';

export interface SpendRequest {
  to: string;
  /** Pool quanta. */
  amount: bigint;
  memo: string;
  /** The wallet's own address, which the change note is written to. */
  changeAddress: string;
  /** Notes this spend may choose from: on chain, unspent, one per nullifier. */
  candidates: readonly { note: StoredNote; secret: NoteSecret }[];
  /** Override of the computed floor. Never below it. */
  fee?: bigint;
}

export interface SpendProgress {
  stage:
    | 'fee'
    | 'select'
    | 'build'
    | 'anchor'
    | 'tree'
    | 'prove'
    | 'submit'
    | 'confirm'
    | 'done';
  detail?: string;
}

export interface SpendResult {
  fee: bigint;
  change: bigint;
  inputs: { commitment: string; value: bigint }[];
  /** The two commitments the settlement publishes, in slot order. */
  commitments: [string, string];
  nullifiers: [string, string];
  /** Which slot the payment landed in. Drawn, so it is reported rather than assumed. */
  paymentSlot: 1 | 2;
  extrinsicHash: string;
  proofBytes: number;
  proveMillis: number;
  phases: { phase: string; millis: number }[];
  peakLinearMemoryBytes: number;
  inclusion: { blockNumber: number; blockHash: string; settled: boolean } | null;
  warnings: string[];
}

/** The floor this spend owes, from the runtime's constants and the pad. */
export function feeFloorFor(context: ChainContext, limits: ProverLimits): bigint {
  return slotFeeFloor(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.padded_ciphertext_bytes,
  );
}

export async function spend(
  context: ChainContext,
  prover: ProverClient,
  store: WalletStore,
  request: SpendRequest,
  limits: ProverLimits,
  report: (progress: SpendProgress) => void,
): Promise<SpendResult> {
  const warnings: string[] = [];

  report({ stage: 'fee' });
  // The pad against both of the runtime's bounds. The cap is a refusal, the
  // divisor is a warning: see `fee.ts`.
  ensureMemoPadFits(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    limits.ciphertext_fixed_bytes,
  );
  const separation = memoPadSeparationWarning(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    limits.ciphertext_fixed_bytes,
  );
  if (separation !== null) {
    warnings.push(separation);
  }
  ensureCiphertextFits(
    context.constants,
    limits.padded_ciphertext_bytes,
    limits.memo_bytes,
    'payment',
  );

  const floor = feeFloorFor(context, limits);
  const fee = request.fee ?? floor;
  if (fee < floor) {
    throw new Error(
      `this runtime's floor for one slot is ${floor} quanta and this spend offers ${fee}. The ` +
        'fee is a public input fixed at proving time, so an underpaid one costs the whole proof ' +
        'and comes back as PayloadUnderpaid.',
    );
  }

  report({ stage: 'select' });
  const target = request.amount + fee;
  const selection = selectNotes(
    request.candidates.map((candidate) => candidate.note),
    target,
  );
  const chosen = selection.notes.map((note) => {
    const held = request.candidates.find(
      (candidate) => candidate.note.commitment === note.commitment,
    );
    if (held === undefined) {
      throw new Error('a selected note lost its secrets between selection and proving');
    }
    return held;
  });
  const change = selection.total - target;

  // The circuits first, then the anchor. Reversing these two publishes this
  // machine's build time in the anchor-to-inclusion gap.
  report({ stage: 'build' });
  await prover.buildProver();

  report({ stage: 'anchor' });
  const head = await fetchHead(context);
  const raw = await headerAt(context, head.hash);
  const anchor: Anchor = anchorFromHeader(parseRawHeader(raw));
  // The rebuild the wallet did of the header preimage, hashed by the circuit's
  // own function and compared against what the chain says. The digest
  // re-encoding is the part that goes wrong, and the alternative to checking
  // is paying for the proof and reading `BlockHashMismatch`.
  const recomputed = await prover.headerBlockHash(anchor);
  if (recomputed.toLowerCase() !== head.hash.toLowerCase().replace(/^0x/, '')) {
    throw new Error(
      `the header this wallet rebuilt for block ${anchor.block_number} hashes to ${recomputed} ` +
        `where the chain says ${head.hash}. Proving against it would be refused with ` +
        'BlockHashMismatch.',
    );
  }

  report({ stage: 'tree', detail: 'rebuilding the commitment tree at the anchor' });
  const shape = await fetchTreeShape(context, head.hash);
  const leafHashes = await fetchLeafHashes(context, 0, shape.leafCount, head.hash, (done) => {
    report({ stage: 'tree', detail: `${done} of ${shape.leafCount} leaves` });
  });

  // The root gate first. Without it a leaf index means nothing at all, and
  // every check after it would be comparing against a tree the anchor does not
  // commit to.
  const rebuiltRoot = await prover.treeRoot(copyOf(leafHashes), shape.depth);
  if (rebuiltRoot.toLowerCase() !== anchor.zk_tree_root.toLowerCase()) {
    throw new Error(
      `the tree this wallet rebuilt over ${shape.leafCount} leaves at depth ${shape.depth} roots ` +
        `to ${rebuiltRoot} and the anchor header says ${anchor.zk_tree_root}. Nothing has been ` +
        'proved. Sync again: the node may have appended a leaf between the two reads.',
    );
  }

  const inputs = [];
  for (const held of chosen) {
    if (held.note.leafIndex >= shape.leafCount) {
      // Past the end of a tree that roots correctly. Either the leaf is not
      // folded yet, which is "wait one block", or the store recorded its block
      // strictly below the anchor, which makes it a note this chain does not
      // carry. Reporting the second as a race leaves somebody retrying
      // forever, because selection picks the same phantom every time.
      const recordedBelow =
        held.note.blockNumber !== null && held.note.blockNumber < anchor.block_number;
      if (recordedBelow) {
        // Written off here rather than left for a sync to notice. The sync's
        // orphan marking runs only when a checkpoint walk rewound, and a
        // rescan never runs it at all, so "sync so it is marked off chain"
        // would be advice that does not always hold and selection would pick
        // the same phantom on every retry.
        await store.markOffChain(held.note.commitment);
        throw new Error(
          `note ${held.note.commitment} is recorded at leaf ${held.note.leafIndex}, which is ` +
            `past the end of a ${shape.leafCount}-leaf tree the anchor confirms, and it was ` +
            `recorded at block ${held.note.blockNumber}, below the anchor. This chain does not ` +
            'carry it, so it is marked off chain. Send again: the next selection will not offer it.',
        );
      }
      throw new Error(
        `note ${held.note.commitment} sits at leaf ${held.note.leafIndex} and the tree at the ` +
          `anchor holds ${shape.leafCount}. A note cannot be minted and spent in the same ` +
          'block: wait one block and send again.',
      );
    }
    const path = await prover.treePath(copyOf(leafHashes), shape.depth, held.note.leafIndex);
    if (path.leaf.toLowerCase() !== held.note.commitment.toLowerCase()) {
      throw new Error(
        `leaf ${held.note.leafIndex} carries ${path.leaf} on this chain and this wallet holds a ` +
          `note committing to ${held.note.commitment}. Sync before sending.`,
      );
    }
    if (path.root.toLowerCase() !== anchor.zk_tree_root.toLowerCase()) {
      throw new Error(
        `the path for leaf ${held.note.leafIndex} reaches ${path.root} and the anchor header ` +
          `says ${anchor.zk_tree_root}.`,
      );
    }
    inputs.push({
      value: held.note.value,
      rho: held.secret.rho,
      r: held.secret.r,
      path: { siblings: path.siblings, positions: path.positions },
    });
  }

  // The payment's slot is drawn. Both outputs are the same size and the
  // circuit derives each `rho` from its slot index, so either assignment
  // proves and settles unchanged; a fixed one would split every settlement's
  // outputs publicly into "counterparty" and "sender's change".
  const draw = crypto.getRandomValues(new Uint8Array(1))[0] ?? 0;
  const paymentSlot: 1 | 2 = draw % 2 === 0 ? 1 : 2;
  const payment = { address: request.to, value: request.amount.toString(), memo: request.memo };
  const changeOutput = {
    address: request.changeAddress,
    value: change.toString(),
    // A change memo is always empty, which is why both are padded to one size.
    memo: '',
  };
  const outputs = paymentSlot === 1 ? [payment, changeOutput] : [changeOutput, payment];

  report({ stage: 'prove', detail: 'the circuits are built; proving one private batch' });
  const proveStarted = performance.now();
  const submission = await prover.proveTransfer({
    anchor,
    tree_depth: shape.depth,
    fee: fee.toString(),
    inputs,
    outputs,
  });
  const proveMillis = performance.now() - proveStarted;

  // The two ciphertexts the fee was computed from have to be the two the
  // submission carries. Equal to each other, because a difference is the leak
  // the padding closes, and equal to the pad, because the fee is already
  // fixed inside the proof.
  const [size1, size2] = submission.report.ciphertext_bytes;
  if (size1 !== size2) {
    throw new Error(
      `this submission's ciphertexts are ${size1} and ${size2} bytes. A difference is the memo ` +
        'length in the clear, which is the leak the pad closes. Nothing has been submitted.',
    );
  }
  if (size1 !== limits.padded_ciphertext_bytes) {
    throw new Error(
      `the fee was computed from ${limits.padded_ciphertext_bytes}-byte ciphertexts and this ` +
        `submission carries ${size1}. Nothing has been submitted.`,
    );
  }

  report({ stage: 'submit' });
  const encoded = encodeSettlement(context, submission.proof, [
    { ct1: submission.ct1, ct2: submission.ct2 },
  ]);

  // Before the submission, in one committed transaction. The store is the only
  // copy of this note's `r` anywhere in the world.
  const changeCommitment = submission.report.public_inputs.commitments[paymentSlot === 1 ? 1 : 0];
  const pending: PendingNote = {
    commitment: changeCommitment,
    kind: 'change',
    value: change.toString(),
    submittedAtBlock: anchor.block_number,
    extrinsic: encoded,
    secret: await store.sealPendingSecret(changeCommitment, {
      // The change note's `(rho, r)` are derived inside the circuit from the
      // spend's own nullifiers, and the wallet recovers them by decrypting its
      // own ciphertext on the next sync. What is recorded here is the claim
      // that the note exists, so a sync that has not reached it still shows it.
      rho: '',
      r: '',
      nullifier: '',
      memo: '',
    }),
  };
  await store.commitPending(pending);

  const extrinsicHash = await submitSettlement(context, encoded);

  report({ stage: 'confirm', detail: 'waiting for the settlement to land' });
  const inclusion = await waitForInclusion(
    context,
    encoded,
    submission.report.public_inputs.nullifiers,
    {
      // The anchor window is the real bound, and it is comfortable: 256 blocks
      // at a 12-second target is about 51 minutes. Two minutes is what a dev
      // chain needs and what a person will wait before being told the answer
      // is to prove again.
      timeoutMs: 120_000,
      // These bytes did not exist before the anchor, so no block at or below
      // it can carry them and none after it is skipped.
      fromBlock: anchor.block_number,
      onBlock: (height) => {
        report({ stage: 'confirm', detail: `block ${height}` });
      },
    },
  );

  if (inclusion !== null && inclusion.settled) {
    // Latch the flag now, on the nullifiers rather than on the commitments. A
    // send that happens before the next sync would otherwise select the other
    // member of a conflict set, which carries the nullifier the chain has just
    // settled. See `WalletStore.markSpentByNullifier`.
    await store.markSpentByNullifier(
      chosen.map((held) => held.secret.nullifier),
      inclusion.blockNumber,
    );
  }

  report({ stage: 'done' });
  return {
    fee,
    change,
    inputs: chosen.map((held) => ({
      commitment: held.note.commitment,
      value: BigInt(held.note.value),
    })),
    commitments: submission.report.public_inputs.commitments,
    nullifiers: submission.report.public_inputs.nullifiers,
    paymentSlot,
    extrinsicHash,
    proofBytes: submission.report.proof_bytes,
    proveMillis,
    phases: submission.report.phases,
    peakLinearMemoryBytes: submission.report.peak_linear_memory_bytes_since_init,
    inclusion,
    warnings,
  };
}

/**
 * A copy of the leaf range, because the worker takes ownership of what it is
 * transferred and a spend with two inputs asks for two paths out of the same
 * bytes.
 */
function copyOf(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  return out;
}
